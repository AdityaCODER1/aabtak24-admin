/**
 * Server-side authentication, peppered PBKDF2-SHA256 password hashing,
 * D1-backed HttpOnly sessions, CSRF + Origin validation, and server-side rate limiting.
 */

import { bytesToBase64 } from "./sanitize.js";

export const SESSION_COOKIE_NAME = "aabtak_session";
export const PBKDF2_ITERATIONS = 100000; // Cloudflare Workers Web Crypto cap; combined with HMAC-SHA256 server pepper
export const MIN_PASSWORD_LENGTH = 8;
export const IDLE_TIMEOUT_MS = 60 * 60 * 1000; // 60 minutes inactivity auto-logout
export const MAX_SESSION_MS = 24 * 60 * 60 * 1000; // 24 hours absolute max session lifetime

function b64ToBytes(b64) {
    const bin = atob(String(b64 || ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

export async function sha256Hex(str) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(str ?? "")));
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function randomHex(byteLength = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
    return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqualBytes(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

export async function timingSafeEqualStr(a, b) {
    const ha = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(a ?? ""))));
    const hb = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(b ?? ""))));
    return timingSafeEqualBytes(ha, hb);
}

/**
 * Applies a server-side secret HMAC-SHA256 pepper to the password before PBKDF2-SHA256.
 * Even if the D1 database were ever leaked, hashes cannot be brute-forced without env.PASSWORD_PEPPER.
 */
async function applyPepper(password, pepper) {
    if (!pepper || String(pepper).length < 16) {
        throw new Error("Server secret PASSWORD_PEPPER is missing or too short (minimum 16 characters).");
    }
    const hmacKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(String(pepper)),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const mac = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(String(password)));
    return new Uint8Array(mac);
}

export async function hashPassword(password, pepper, iterations = PBKDF2_ITERATIONS) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const peppered = await applyPepper(password, pepper);
    const keyMaterial = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
    const derived = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        keyMaterial,
        256
    );
    return {
        hash: bytesToBase64(new Uint8Array(derived)),
        salt: bytesToBase64(salt),
        iterations
    };
}

export async function verifyPassword(password, pepper, saltB64, expectedHashB64, iterations = PBKDF2_ITERATIONS) {
    try {
        const salt = b64ToBytes(saltB64);
        const expectedBytes = b64ToBytes(expectedHashB64);
        const peppered = await applyPepper(password, pepper);
        const keyMaterial = await crypto.subtle.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
        const derived = await crypto.subtle.deriveBits(
            { name: "PBKDF2", salt, iterations: Number(iterations) || PBKDF2_ITERATIONS, hash: "SHA-256" },
            keyMaterial,
            256
        );
        return timingSafeEqualBytes(new Uint8Array(derived), expectedBytes);
    } catch (_) {
        return false;
    }
}

export function getClientIp(request) {
    return (
        request.headers.get("CF-Connecting-IP") ||
        request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
        "unknown"
    );
}

export function parseCookies(request) {
    const header = request.headers.get("Cookie") || "";
    const out = {};
    for (const part of header.split(";")) {
        const idx = part.indexOf("=");
        if (idx === -1) continue;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (k) out[k] = v;
    }
    return out;
}

export function isSecureContextRequest(request) {
    try {
        const u = new URL(request.url);
        if (u.protocol === "https:") return true;
        if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return false;
        return true;
    } catch (_) {
        return true;
    }
}

export function buildSessionCookieHeader(sessionToken, request, maxAgeSeconds = 86400) {
    const secureFlag = isSecureContextRequest(request) ? "; Secure" : "";
    return `${SESSION_COOKIE_NAME}=${sessionToken}; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}`;
}

export function buildClearSessionCookieHeader(request) {
    const secureFlag = isSecureContextRequest(request) ? "; Secure" : "";
    return `${SESSION_COOKIE_NAME}=; HttpOnly${secureFlag}; SameSite=Strict; Path=/; Max-Age=0`;
}

export async function createSession(db, request, { role, userId, username }) {
    const now = Date.now();
    const sessionToken = randomHex(32);
    const tokenHash = await sha256Hex(sessionToken);
    const csrfToken = randomHex(32);
    const expiresAt = now + MAX_SESSION_MS;
    const ip = getClientIp(request);
    const userAgent = String(request.headers.get("User-Agent") || "").slice(0, 200);

    // Opportunistic cleanup of expired sessions
    await db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(now).run();

    await db.prepare(
        `INSERT INTO sessions (token_hash, user_role, user_id, username, csrf_token, created_at, last_active_at, expires_at, ip, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
        tokenHash,
        role,
        userId,
        username,
        csrfToken,
        now,
        now,
        expiresAt,
        ip,
        userAgent
    ).run();

    return {
        sessionToken,
        tokenHash,
        csrfToken,
        cookieHeader: buildSessionCookieHeader(sessionToken, request, Math.floor(MAX_SESSION_MS / 1000))
    };
}

export async function revokeUserSessions(db, userId, exceptTokenHash = null) {
    if (exceptTokenHash) {
        await db.prepare(`DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`)
            .bind(userId, exceptTokenHash)
            .run();
    } else {
        await db.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId).run();
    }
}

export async function authenticateRequest(request, env) {
    const cookies = parseCookies(request);
    const rawToken = cookies[SESSION_COOKIE_NAME];
    if (!rawToken || rawToken.length < 32) return null;

    const tokenHash = await sha256Hex(rawToken);
    const now = Date.now();

    const row = await env.CMS_DB.prepare(
        `SELECT token_hash, user_role, user_id, username, csrf_token, created_at, last_active_at, expires_at
         FROM sessions WHERE token_hash = ?`
    ).bind(tokenHash).first();

    if (!row) return null;

    if (now >= Number(row.expires_at) || now - Number(row.last_active_at) >= IDLE_TIMEOUT_MS) {
        await env.CMS_DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
        return null;
    }

    let displayName = "मुख्य एडमिन";
    let permission = "admin";
    let username = "admin";

    if (row.user_role === "editor") {
        const editor = await env.CMS_DB.prepare(
            `SELECT id, username, display_name, permission, active FROM editors WHERE id = ?`
        ).bind(row.user_id).first();

        if (!editor || Number(editor.active) !== 1) {
            // Editor was suspended or deleted: immediately revoke all sessions
            await revokeUserSessions(env.CMS_DB, row.user_id);
            return null;
        }
        username = editor.username;
        displayName = editor.display_name || editor.username;
        permission = editor.permission === "all_articles" ? "all_articles" : "own_only";
    }

    // Throttle sliding idle timestamp updates (write at most once per 60s)
    if (now - Number(row.last_active_at) > 60_000) {
        await env.CMS_DB.prepare(`UPDATE sessions SET last_active_at = ? WHERE token_hash = ?`)
            .bind(now, tokenHash)
            .run();
    }

    return {
        role: row.user_role,
        userId: row.user_id,
        username,
        displayName,
        permission,
        csrfToken: row.csrf_token,
        tokenHash
    };
}

export function verifyOrigin(request, env) {
    const origin = request.headers.get("Origin");
    // For state-changing requests, browsers always send Origin
    if (!origin) return false;

    const configured = String(env.ALLOWED_ORIGIN || "").trim();
    if (configured) {
        const allowedOrigins = configured.split(",").map(s => s.trim()).filter(Boolean);
        return allowedOrigins.includes(origin);
    }

    const reqUrl = new URL(request.url);
    return origin === reqUrl.origin;
}

export async function verifyOriginAndCsrf(request, env, session) {
    if (!verifyOrigin(request, env)) {
        return { ok: false, error: "Invalid request origin." };
    }
    const headerToken = request.headers.get("X-CSRF-Token") || "";
    if (!session || !headerToken) {
        return { ok: false, error: "Missing CSRF token." };
    }
    const valid = await timingSafeEqualStr(headerToken, session.csrfToken);
    if (!valid) {
        return { ok: false, error: "Invalid CSRF token." };
    }
    return { ok: true };
}

/**
 * Progressive server-side login rate limiter stored atomically in D1.
 * 5 failures -> 30s, 10 -> 5 min, 15+ -> 30 min.
 */
export async function checkRateLimit(db, bucketKeys) {
    const now = Date.now();
    let maxWaitMs = 0;
    for (const key of bucketKeys) {
        const row = await db.prepare(
            `SELECT fail_count, locked_until FROM login_attempts WHERE bucket_key = ?`
        ).bind(key).first();
        if (row && Number(row.locked_until) > now) {
            maxWaitMs = Math.max(maxWaitMs, Number(row.locked_until) - now);
        }
    }
    if (maxWaitMs > 0) {
        return { allowed: false, retryAfterSec: Math.ceil(maxWaitMs / 1000) };
    }
    return { allowed: true, retryAfterSec: 0 };
}

export async function recordRateLimitFailure(db, bucketKeys) {
    const now = Date.now();
    let maxLockedUntil = 0;
    let maxCount = 0;

    for (const key of bucketKeys) {
        const row = await db.prepare(
            `SELECT fail_count, locked_until, updated_at FROM login_attempts WHERE bucket_key = ?`
        ).bind(key).first();

        // Reset stale counters older than 2 hours
        let nextCount = 1;
        if (row && now - Number(row.updated_at) < 2 * 60 * 60 * 1000) {
            nextCount = Number(row.fail_count) + 1;
        }

        let lockedUntil = 0;
        if (nextCount >= 15) {
            lockedUntil = now + 30 * 60 * 1000;
        } else if (nextCount >= 10) {
            lockedUntil = now + 5 * 60 * 1000;
        } else if (nextCount >= 5 && nextCount % 5 === 0) {
            lockedUntil = now + 30 * 1000;
        }

        await db.prepare(
            `INSERT INTO login_attempts (bucket_key, fail_count, locked_until, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(bucket_key) DO UPDATE SET
                 fail_count = excluded.fail_count,
                 locked_until = excluded.locked_until,
                 updated_at = excluded.updated_at`
        ).bind(key, nextCount, lockedUntil, now).run();

        if (lockedUntil > maxLockedUntil) maxLockedUntil = lockedUntil;
        if (nextCount > maxCount) maxCount = nextCount;
    }

    return {
        failCount: maxCount,
        retryAfterSec: maxLockedUntil > now ? Math.ceil((maxLockedUntil - now) / 1000) : 0
    };
}

export async function clearRateLimit(db, bucketKeys) {
    for (const key of bucketKeys) {
        await db.prepare(`DELETE FROM login_attempts WHERE bucket_key = ?`).bind(key).run();
    }
}
