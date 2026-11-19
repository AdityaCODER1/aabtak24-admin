/**
 * Main Admin Only: Sub-Editor Account Management & Audit Log routes (Cloudflare D1):
 *  - GET    /api/editors
 *  - POST   /api/editors
 *  - PATCH  /api/editors/:id
 *  - DELETE /api/editors/:id
 *  - GET    /api/audit-logs
 */

import {
    MIN_PASSWORD_LENGTH,
    PBKDF2_ITERATIONS,
    authenticateRequest,
    getClientIp,
    hashPassword,
    randomHex,
    revokeUserSessions,
    verifyOriginAndCsrf
} from "../auth.js";
import { writeAuditLog } from "../db.js";
import { errorResponse, jsonResponse, readJsonBody } from "../http.js";
import { normalizeUsername } from "../sanitize.js";

function mapEditorRow(row) {
    return {
        id: row.id,
        username: row.username,
        display_name: row.display_name || "",
        permission: row.permission === "all_articles" ? "all_articles" : "own_only",
        active: Number(row.active) === 1,
        created_at: row.created_at || "",
        updated_at: row.updated_at || ""
    };
}

export async function handleEditorsRoutes(request, env, pathname) {
    const method = request.method.toUpperCase();
    const session = await authenticateRequest(request, env);
    if (!session) {
        return errorResponse("सत्र समाप्त हो गया है। कृपया पुनः लॉगिन करें।", 401);
    }
    if (session.role !== "admin") {
        return errorResponse("⛔ संपादक प्रबंधन केवल मुख्य एडमिन के लिए उपलब्ध है।", 403);
    }

    const ip = getClientIp(request);

    // 1. GET /api/audit-logs
    if (pathname === "/api/audit-logs" && method === "GET") {
        const res = await env.CMS_DB.prepare(
            `SELECT id, actor_role, actor_username, action, target, details, ip, created_at
             FROM audit_logs ORDER BY id DESC LIMIT 50`
        ).all();
        return jsonResponse({ logs: res.results || [] });
    }

    // 2. GET /api/editors
    if (pathname === "/api/editors" && method === "GET") {
        const res = await env.CMS_DB.prepare(
            `SELECT id, username, display_name, permission, active, created_at, updated_at
             FROM editors ORDER BY created_at DESC`
        ).all();
        return jsonResponse({ editors: (res.results || []).map(mapEditorRow) });
    }

    // Mutations require Origin + CSRF verification
    const csrfCheck = await verifyOriginAndCsrf(request, env, session);
    if (!csrfCheck.ok) {
        return errorResponse(csrfCheck.error, 403);
    }

    // 3. POST /api/editors (Create Sub-Editor)
    if (pathname === "/api/editors" && method === "POST") {
        const body = await readJsonBody(request, 16 * 1024);
        const username = normalizeUsername(body.username);
        const displayName = String(body.display_name || "").trim().slice(0, 100);
        const password = String(body.password || "");
        const permission = body.permission === "all_articles" ? "all_articles" : "own_only";

        if (!username || username.length < 3 || username.length > 120 || /\s/.test(username)) {
            return errorResponse("⚠️ कृपया एक मान्य ईमेल या यूज़रनेम (बिना स्पेस, कम से कम 3 अक्षर) दर्ज करें।", 400);
        }
        if (username === "admin") {
            return errorResponse("⚠️ 'admin' यूज़रनेम मुख्य एडमिन के लिए आरक्षित है।", 400);
        }
        if (password.length < MIN_PASSWORD_LENGTH) {
            return errorResponse(`⚠️ संपादक के लिए कम से कम ${MIN_PASSWORD_LENGTH} अक्षरों का मजबूत पासवर्ड दर्ज करें।`, 400);
        }

        const existing = await env.CMS_DB.prepare(`SELECT id FROM editors WHERE username = ?`).bind(username).first();
        if (existing) {
            return errorResponse("⚠️ इस ईमेल/यूज़रनेम से पहले से एक संपादक खाता मौजूद है।", 409);
        }

        const hashed = await hashPassword(password, env.PASSWORD_PEPPER, PBKDF2_ITERATIONS);
        const id = `ed-${Date.now()}-${randomHex(4)}`;
        const nowIso = new Date().toISOString();

        await env.CMS_DB.prepare(
            `INSERT INTO editors (id, username, display_name, password_hash, salt, iterations, permission, active, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
        ).bind(id, username, displayName, hashed.hash, hashed.salt, hashed.iterations, permission, nowIso, nowIso).run();

        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: session.username,
            action: "editor_created",
            target: username,
            details: `permission=${permission}`,
            ip
        });

        const res = await env.CMS_DB.prepare(
            `SELECT id, username, display_name, permission, active, created_at, updated_at
             FROM editors ORDER BY created_at DESC`
        ).all();
        return jsonResponse({ ok: true, id, editors: (res.results || []).map(mapEditorRow) }, 201);
    }

    // 4. PATCH / DELETE /api/editors/:id
    const idMatch = pathname.match(/^\/api\/editors\/([^/]+)$/);
    if (!idMatch) {
        return errorResponse("Not Found", 404);
    }
    const editorId = decodeURIComponent(idMatch[1]).trim();

    const existing = await env.CMS_DB.prepare(
        `SELECT id, username, display_name, permission, active, created_at, updated_at FROM editors WHERE id = ?`
    ).bind(editorId).first();
    if (!existing) {
        return errorResponse("संपादक खाता नहीं मिला।", 404);
    }

    if (method === "PATCH") {
        const body = await readJsonBody(request, 16 * 1024);
        const nextUsername = body.username !== undefined ? normalizeUsername(body.username) : existing.username;
        const nextDisplayName = body.display_name !== undefined
            ? String(body.display_name || "").trim().slice(0, 100)
            : existing.display_name;
        const nextPermission = body.permission !== undefined
            ? (body.permission === "all_articles" ? "all_articles" : "own_only")
            : existing.permission;
        const nextActive = body.active !== undefined ? (body.active ? 1 : 0) : Number(existing.active);
        const newPassword = body.password !== undefined ? String(body.password || "") : "";

        if (!nextUsername || nextUsername.length < 3 || nextUsername.length > 120 || /\s/.test(nextUsername)) {
            return errorResponse("⚠️ कृपया एक मान्य ईमेल या यूज़रनेम दर्ज करें।", 400);
        }
        if (nextUsername === "admin") {
            return errorResponse("⚠️ 'admin' यूज़रनेम मुख्य एडमिन के लिए आरक्षित है।", 400);
        }
        if (nextUsername !== existing.username) {
            const dup = await env.CMS_DB.prepare(`SELECT id FROM editors WHERE username = ? AND id != ?`)
                .bind(nextUsername, editorId)
                .first();
            if (dup) {
                return errorResponse("⚠️ इस ईमेल/यूज़रनेम से पहले से एक संपादक मौजूद है।", 409);
            }
        }
        if (newPassword && newPassword.length < MIN_PASSWORD_LENGTH) {
            return errorResponse(`⚠️ नया पासवर्ड कम से कम ${MIN_PASSWORD_LENGTH} अक्षरों का होना चाहिए।`, 400);
        }

        const nowIso = new Date().toISOString();
        const changes = [];

        if (newPassword) {
            const hashed = await hashPassword(newPassword, env.PASSWORD_PEPPER, PBKDF2_ITERATIONS);
            await env.CMS_DB.prepare(
                `UPDATE editors
                 SET username = ?, display_name = ?, password_hash = ?, salt = ?, iterations = ?, permission = ?, active = ?, updated_at = ?
                 WHERE id = ?`
            ).bind(
                nextUsername,
                nextDisplayName,
                hashed.hash,
                hashed.salt,
                hashed.iterations,
                nextPermission,
                nextActive,
                nowIso,
                editorId
            ).run();
            changes.push("password_reset");
            // Force re-login on password reset
            await revokeUserSessions(env.CMS_DB, editorId);
        } else {
            await env.CMS_DB.prepare(
                `UPDATE editors
                 SET username = ?, display_name = ?, permission = ?, active = ?, updated_at = ?
                 WHERE id = ?`
            ).bind(nextUsername, nextDisplayName, nextPermission, nextActive, nowIso, editorId).run();
        }

        if (nextActive === 0) {
            await revokeUserSessions(env.CMS_DB, editorId);
            changes.push("suspended");
        } else if (Number(existing.active) === 0 && nextActive === 1) {
            changes.push("reactivated");
        }
        if (nextPermission !== existing.permission) {
            changes.push(`permission=${nextPermission}`);
        }

        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: session.username,
            action: "editor_updated",
            target: nextUsername,
            details: changes.join(", ") || "profile_updated",
            ip
        });

        const res = await env.CMS_DB.prepare(
            `SELECT id, username, display_name, permission, active, created_at, updated_at
             FROM editors ORDER BY created_at DESC`
        ).all();
        return jsonResponse({ ok: true, editors: (res.results || []).map(mapEditorRow) });
    }

    if (method === "DELETE") {
        await revokeUserSessions(env.CMS_DB, editorId);
        await env.CMS_DB.prepare(`DELETE FROM editors WHERE id = ?`).bind(editorId).run();
        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: session.username,
            action: "editor_deleted",
            target: existing.username,
            ip
        });

        const res = await env.CMS_DB.prepare(
            `SELECT id, username, display_name, permission, active, created_at, updated_at
             FROM editors ORDER BY created_at DESC`
        ).all();
        return jsonResponse({ ok: true, editors: (res.results || []).map(mapEditorRow) });
    }

    return errorResponse("Method Not Allowed", 405);
}
