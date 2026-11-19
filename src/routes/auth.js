/**
 * Authentication routes:
 *  - GET  /api/auth/me
 *  - POST /api/auth/login           (blank username = Main Admin; email/username = Sub-Editor)
 *  - POST /api/auth/logout
 *  - POST /api/auth/change-password (Main Admin only)
 *  - POST /api/auth/recover-admin   (Forgot Main Admin Password via server-side ADMIN_RECOVERY_KEY)
 */

import {
    MIN_PASSWORD_LENGTH,
    PBKDF2_ITERATIONS,
    authenticateRequest,
    buildClearSessionCookieHeader,
    checkRateLimit,
    clearRateLimit,
    createSession,
    getClientIp,
    hashPassword,
    recordRateLimitFailure,
    revokeUserSessions,
    timingSafeEqualStr,
    verifyOrigin,
    verifyOriginAndCsrf,
    verifyPassword
} from "../auth.js";
import { writeAuditLog } from "../db.js";
import { errorResponse, jsonResponse, readJsonBody } from "../http.js";
import { normalizeUsername } from "../sanitize.js";

export async function handleAuthRoutes(request, env, pathname) {
    const method = request.method.toUpperCase();
    const ip = getClientIp(request);

    // 1. GET /api/auth/me
    if (pathname === "/api/auth/me" && method === "GET") {
        const session = await authenticateRequest(request, env);
        if (!session) {
            return jsonResponse({ authenticated: false, user: null });
        }

        let securityInfo = null;
        if (session.role === "admin") {
            const adminRow = await env.CMS_DB.prepare(
                `SELECT iterations, updated_at FROM admin_config WHERE id = 1`
            ).first();
            const counts = await env.CMS_DB.prepare(
                `SELECT COUNT(*) AS total, SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active_count FROM editors`
            ).first();
            securityInfo = {
                backend: "Cloudflare Workers + Private D1",
                password_updated_at: adminRow?.updated_at || "",
                pbkdf2_iterations: adminRow?.iterations || PBKDF2_ITERATIONS,
                peppered: true,
                recovery_configured: Boolean(env.ADMIN_RECOVERY_KEY && String(env.ADMIN_RECOVERY_KEY).length >= 12),
                total_editors: Number(counts?.total || 0),
                active_editors: Number(counts?.active_count || 0)
            };
        }

        return jsonResponse({
            authenticated: true,
            csrfToken: session.csrfToken,
            user: {
                role: session.role,
                id: session.userId,
                username: session.username,
                display_name: session.displayName,
                permission: session.permission
            },
            securityInfo
        });
    }

    // 2. POST /api/auth/login
    if (pathname === "/api/auth/login" && method === "POST") {
        if (!verifyOrigin(request, env)) {
            return errorResponse("Invalid request origin.", 403);
        }

        const body = await readJsonBody(request, 16 * 1024);
        const normalizedUser = normalizeUsername(body.username);
        const password = String(body.password || "");

        if (!password) {
            return errorResponse("कृपया अपना पासवर्ड दर्ज करें।", 400);
        }

        const buckets = [`ip:${ip}`, `acct:${normalizedUser || "admin"}`];
        const rate = await checkRateLimit(env.CMS_DB, buckets);
        if (!rate.allowed) {
            return errorResponse(
                `⏳ बहुत अधिक गलत प्रयास! सुरक्षा के लिए कृपया ${rate.retryAfterSec} सेकंड प्रतीक्षा करें।`,
                429,
                { retryAfterSec: rate.retryAfterSec },
                { "Retry-After": String(rate.retryAfterSec) }
            );
        }

        if (!normalizedUser) {
            // ==================== MAIN ADMIN LOGIN ====================
            let adminRow = await env.CMS_DB.prepare(
                `SELECT password_hash, salt, iterations, updated_at FROM admin_config WHERE id = 1`
            ).first();

            let passwordOk = false;
            if (adminRow) {
                passwordOk = await verifyPassword(
                    password,
                    env.PASSWORD_PEPPER,
                    adminRow.salt,
                    adminRow.password_hash,
                    adminRow.iterations
                );
            } else {
                // First-time bootstrap from encrypted Worker secret ADMIN_INITIAL_PASSWORD
                const initialSecret = String(env.ADMIN_INITIAL_PASSWORD || "");
                if (!initialSecret) {
                    return errorResponse(
                        "एडमिन पासवर्ड कॉन्फ़िगर नहीं है। कृपया Cloudflare में ADMIN_INITIAL_PASSWORD secret सेट करें।",
                        500
                    );
                }
                passwordOk = await timingSafeEqualStr(password, initialSecret);
                if (passwordOk) {
                    const hashed = await hashPassword(password, env.PASSWORD_PEPPER, PBKDF2_ITERATIONS);
                    const nowIso = new Date().toISOString();
                    await env.CMS_DB.prepare(
                        `INSERT OR REPLACE INTO admin_config (id, password_hash, salt, iterations, updated_at)
                         VALUES (1, ?, ?, ?, ?)`
                    ).bind(hashed.hash, hashed.salt, hashed.iterations, nowIso).run();
                }
            }

            if (!passwordOk) {
                const fail = await recordRateLimitFailure(env.CMS_DB, buckets);
                await writeAuditLog(env.CMS_DB, {
                    role: "anonymous",
                    username: "admin",
                    action: "login_failed",
                    target: "admin",
                    details: `Attempt #${fail.failCount}`,
                    ip
                });
                if (fail.retryAfterSec > 0) {
                    return errorResponse(
                        `⏳ बहुत अधिक गलत प्रयास! कृपया ${fail.retryAfterSec} सेकंड प्रतीक्षा करें।`,
                        429,
                        { retryAfterSec: fail.retryAfterSec },
                        { "Retry-After": String(fail.retryAfterSec) }
                    );
                }
                return errorResponse("❌ गलत मुख्य एडमिन पासवर्ड! कृपया सही पासवर्ड दर्ज करें।", 401);
            }

            await clearRateLimit(env.CMS_DB, buckets);
            const sess = await createSession(env.CMS_DB, request, {
                role: "admin",
                userId: "admin",
                username: "admin"
            });
            await writeAuditLog(env.CMS_DB, {
                role: "admin",
                username: "admin",
                action: "login_success",
                target: "admin",
                ip
            });

            return jsonResponse(
                {
                    authenticated: true,
                    csrfToken: sess.csrfToken,
                    user: {
                        role: "admin",
                        id: "admin",
                        username: "admin",
                        display_name: "मुख्य एडमिन",
                        permission: "admin"
                    }
                },
                200,
                { "Set-Cookie": sess.cookieHeader }
            );
        }

        // ==================== SUB-EDITOR LOGIN ====================
        const editor = await env.CMS_DB.prepare(
            `SELECT id, username, display_name, password_hash, salt, iterations, permission, active
             FROM editors WHERE username = ?`
        ).bind(normalizedUser).first();

        let passwordOk = false;
        if (editor) {
            passwordOk = await verifyPassword(
                password,
                env.PASSWORD_PEPPER,
                editor.salt,
                editor.password_hash,
                editor.iterations
            );
        }

        // Anti-enumeration: reject wrong password BEFORE revealing suspension status
        if (!editor || !passwordOk) {
            const fail = await recordRateLimitFailure(env.CMS_DB, buckets);
            await writeAuditLog(env.CMS_DB, {
                role: "anonymous",
                username: normalizedUser,
                action: "login_failed",
                target: normalizedUser,
                details: `Attempt #${fail.failCount}`,
                ip
            });
            if (fail.retryAfterSec > 0) {
                return errorResponse(
                    `⏳ बहुत अधिक गलत प्रयास! कृपया ${fail.retryAfterSec} सेकंड प्रतीक्षा करें।`,
                    429,
                    { retryAfterSec: fail.retryAfterSec },
                    { "Retry-After": String(fail.retryAfterSec) }
                );
            }
            return errorResponse("❌ गलत ईमेल/यूज़रनेम या पासवर्ड! कृपया पुनः जांचें।", 401);
        }

        if (Number(editor.active) !== 1) {
            await writeAuditLog(env.CMS_DB, {
                role: "editor",
                username: editor.username,
                action: "login_blocked_suspended",
                target: editor.id,
                ip
            });
            return errorResponse("⛔ आपका संपादक खाता फिलहाल निलंबित (Suspended) है। कृपया मुख्य एडमिन से संपर्क करें।", 403);
        }

        await clearRateLimit(env.CMS_DB, buckets);
        const sess = await createSession(env.CMS_DB, request, {
            role: "editor",
            userId: editor.id,
            username: editor.username
        });
        await writeAuditLog(env.CMS_DB, {
            role: "editor",
            username: editor.username,
            action: "login_success",
            target: editor.id,
            details: `permission=${editor.permission}`,
            ip
        });

        return jsonResponse(
            {
                authenticated: true,
                csrfToken: sess.csrfToken,
                user: {
                    role: "editor",
                    id: editor.id,
                    username: editor.username,
                    display_name: editor.display_name || editor.username,
                    permission: editor.permission === "all_articles" ? "all_articles" : "own_only"
                }
            },
            200,
            { "Set-Cookie": sess.cookieHeader }
        );
    }

    // 3. POST /api/auth/logout
    if (pathname === "/api/auth/logout" && method === "POST") {
        if (!verifyOrigin(request, env)) {
            return errorResponse("Invalid request origin.", 403);
        }
        const session = await authenticateRequest(request, env);
        if (session) {
            const csrfCheck = await verifyOriginAndCsrf(request, env, session);
            if (!csrfCheck.ok) {
                return errorResponse(csrfCheck.error, 403);
            }
            await env.CMS_DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(session.tokenHash).run();
            await writeAuditLog(env.CMS_DB, {
                role: session.role,
                username: session.username,
                action: "logout",
                ip
            });
        }
        return jsonResponse({ ok: true }, 200, { "Set-Cookie": buildClearSessionCookieHeader(request) });
    }

    // 4. POST /api/auth/change-password (Main Admin Only)
    if (pathname === "/api/auth/change-password" && method === "POST") {
        const session = await authenticateRequest(request, env);
        if (!session) return errorResponse("सत्र समाप्त हो गया है। कृपया पुनः लॉगिन करें।", 401);
        if (session.role !== "admin") return errorResponse("⛔ केवल मुख्य एडमिन पासवर्ड बदल सकते हैं।", 403);

        const csrfCheck = await verifyOriginAndCsrf(request, env, session);
        if (!csrfCheck.ok) return errorResponse(csrfCheck.error, 403);

        const body = await readJsonBody(request, 16 * 1024);
        const currentPassword = String(body.currentPassword || "");
        const newPassword = String(body.newPassword || "");

        if (!currentPassword) {
            return errorResponse("कृपया वर्तमान मुख्य एडमिन पासवर्ड दर्ज करें।", 400);
        }
        if (newPassword.length < MIN_PASSWORD_LENGTH) {
            return errorResponse(`नया पासवर्ड कम से कम ${MIN_PASSWORD_LENGTH} अक्षरों का होना चाहिए।`, 400);
        }

        const adminRow = await env.CMS_DB.prepare(
            `SELECT password_hash, salt, iterations FROM admin_config WHERE id = 1`
        ).first();
        if (!adminRow) {
            return errorResponse("एडमिन पासवर्ड रिकॉर्ड नहीं मिला।", 500);
        }

        const validCurrent = await verifyPassword(
            currentPassword,
            env.PASSWORD_PEPPER,
            adminRow.salt,
            adminRow.password_hash,
            adminRow.iterations
        );
        if (!validCurrent) {
            return errorResponse("❌ वर्तमान मुख्य एडमिन पासवर्ड गलत है।", 401);
        }

        const hashed = await hashPassword(newPassword, env.PASSWORD_PEPPER, PBKDF2_ITERATIONS);
        const nowIso = new Date().toISOString();
        await env.CMS_DB.prepare(
            `UPDATE admin_config SET password_hash = ?, salt = ?, iterations = ?, updated_at = ? WHERE id = 1`
        ).bind(hashed.hash, hashed.salt, hashed.iterations, nowIso).run();

        // Revoke all other admin sessions on password change
        await revokeUserSessions(env.CMS_DB, "admin", session.tokenHash);
        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: "admin",
            action: "admin_password_changed",
            details: "Other admin sessions revoked",
            ip
        });

        return jsonResponse({ ok: true, updated_at: nowIso });
    }

    // 5. POST /api/auth/recover-admin (Forgot Main Admin Password via server-side ADMIN_RECOVERY_KEY)
    if (pathname === "/api/auth/recover-admin" && method === "POST") {
        if (!verifyOrigin(request, env)) {
            return errorResponse("Invalid request origin.", 403);
        }

        const recoverySecret = String(env.ADMIN_RECOVERY_KEY || "").trim();
        if (!recoverySecret || recoverySecret.length < 12) {
            return errorResponse(
                "एडमिन रिकवरी की (ADMIN_RECOVERY_KEY) सर्वर पर सेट नहीं है। कृपया Cloudflare Dashboard से रीसेट करें।",
                503
            );
        }

        const buckets = [`ip:${ip}`, `recovery:admin`];
        const rate = await checkRateLimit(env.CMS_DB, buckets);
        if (!rate.allowed) {
            return errorResponse(
                `⏳ बहुत अधिक गलत प्रयास! कृपया ${rate.retryAfterSec} सेकंड प्रतीक्षा करें।`,
                429,
                { retryAfterSec: rate.retryAfterSec },
                { "Retry-After": String(rate.retryAfterSec) }
            );
        }

        const body = await readJsonBody(request, 16 * 1024);
        const providedKey = String(body.recoveryKey || "").trim();
        const newPassword = String(body.newPassword || "");

        if (!providedKey) {
            return errorResponse("कृपया Admin Recovery Key दर्ज करें।", 400);
        }
        if (newPassword.length < MIN_PASSWORD_LENGTH) {
            return errorResponse(`नया पासवर्ड कम से कम ${MIN_PASSWORD_LENGTH} अक्षरों का होना चाहिए।`, 400);
        }

        const keyValid = await timingSafeEqualStr(providedKey, recoverySecret);
        if (!keyValid) {
            const fail = await recordRateLimitFailure(env.CMS_DB, buckets);
            await writeAuditLog(env.CMS_DB, {
                role: "anonymous",
                username: "admin",
                action: "admin_recovery_failed",
                details: `Attempt #${fail.failCount}`,
                ip
            });
            return errorResponse("❌ अमान्य Admin Recovery Key! कृपया सही कुंजी दर्ज करें।", 401);
        }

        await clearRateLimit(env.CMS_DB, buckets);
        const hashed = await hashPassword(newPassword, env.PASSWORD_PEPPER, PBKDF2_ITERATIONS);
        const nowIso = new Date().toISOString();
        await env.CMS_DB.prepare(
            `INSERT OR REPLACE INTO admin_config (id, password_hash, salt, iterations, updated_at)
             VALUES (1, ?, ?, ?, ?)`
        ).bind(hashed.hash, hashed.salt, hashed.iterations, nowIso).run();

        // Revoke all old admin sessions & issue a fresh session
        await revokeUserSessions(env.CMS_DB, "admin");
        const sess = await createSession(env.CMS_DB, request, {
            role: "admin",
            userId: "admin",
            username: "admin"
        });
        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: "admin",
            action: "admin_password_recovered",
            details: "All previous admin sessions revoked",
            ip
        });

        return jsonResponse(
            {
                authenticated: true,
                csrfToken: sess.csrfToken,
                user: {
                    role: "admin",
                    id: "admin",
                    username: "admin",
                    display_name: "मुख्य एडमिन",
                    permission: "admin"
                }
            },
            200,
            { "Set-Cookie": sess.cookieHeader }
        );
    }

    return errorResponse("Not Found", 404);
}
