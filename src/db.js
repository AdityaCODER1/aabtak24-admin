/**
 * Cloudflare D1 database schema bootstrap and query helpers.
 * All credentials, editor accounts, sessions, rate-limit counters, and audit logs
 * live privately inside Cloudflare D1 — never in public GitHub repositories.
 */

let schemaBootstrapped = false;

const SCHEMA_STATEMENTS = [
    `CREATE TABLE IF NOT EXISTS admin_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        iterations INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS editors (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        iterations INTEGER NOT NULL,
        permission TEXT NOT NULL CHECK (permission IN ('own_only', 'all_articles')),
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_role TEXT NOT NULL CHECK (user_role IN ('admin', 'editor')),
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_active_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        ip TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT ''
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
    `CREATE TABLE IF NOT EXISTS login_attempts (
        bucket_key TEXT PRIMARY KEY,
        fail_count INTEGER NOT NULL DEFAULT 0,
        locked_until INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_role TEXT NOT NULL,
        actor_username TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        details TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(id DESC)`
];

export function resetSchemaCacheForTests() {
    schemaBootstrapped = false;
}

export async function ensureSchema(db) {
    if (!db) {
        throw new Error("Cloudflare D1 binding CMS_DB is not configured.");
    }
    if (schemaBootstrapped) return;
    for (const sql of SCHEMA_STATEMENTS) {
        await db.prepare(sql).run();
    }
    schemaBootstrapped = true;
}

export async function writeAuditLog(db, { role, username, action, target = "", details = "", ip = "" }) {
    try {
        await db.prepare(
            `INSERT INTO audit_logs (actor_role, actor_username, action, target, details, ip, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(
            String(role || "system"),
            String(username || "system"),
            String(action || ""),
            String(target || "").slice(0, 200),
            String(details || "").slice(0, 500),
            String(ip || "").slice(0, 64),
            new Date().toISOString()
        ).run();
    } catch (_) {
        // Audit logging should never crash a primary operation
    }
}
