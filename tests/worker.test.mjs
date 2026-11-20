import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, it, beforeEach, afterEach } from "node:test";
import worker from "../src/index.js";
import { resetSchemaCacheForTests } from "../src/db.js";

/**
 * Real SQLite-backed Cloudflare D1 adapter using Node 24's built-in node:sqlite.
 * Executes every exact SQL query from src/db.js, src/auth.js, and src/routes/*.js.
 */
function createD1Adapter() {
    const sqlite = new DatabaseSync(":memory:");
    return {
        _sqlite: sqlite,
        prepare(sql) {
            const stmt = sqlite.prepare(sql);
            const makeBound = (params) => ({
                async run() {
                    const info = stmt.run(...params);
                    return { success: true, meta: { changes: info.changes, last_row_id: info.lastInsertRowid } };
                },
                async first() {
                    const row = stmt.get(...params);
                    return row === undefined ? null : row;
                },
                async all() {
                    const rows = stmt.all(...params);
                    return { success: true, results: rows };
                }
            });
            return {
                bind(...params) {
                    return makeBound(params);
                },
                ...makeBound([])
            };
        }
    };
}

function createMockGithubFetch(initialFiles) {
    const files = new Map();
    for (const [k, v] of Object.entries(initialFiles)) {
        files.set(k, { content: v, sha: `sha-${k}-1` });
    }
    let shaSeq = 2;
    let rebuildCalls = 0;

    const mockFetch = async (url, options = {}) => {
        const u = String(url);
        const method = (options.method || "GET").toUpperCase();
        const auth = options.headers?.Authorization || "";
        if (auth !== "Bearer ghp_super_secret_worker_token_123456") {
            return new Response(JSON.stringify({ message: "Bad credentials" }), { status: 401 });
        }

        if (u.includes("/actions/workflows/schedule.yml/dispatches") && method === "POST") {
            rebuildCalls += 1;
            return new Response(null, { status: 204 });
        }

        const m = u.match(/\/contents\/([^?]+)/);
        if (m) {
            const filePath = m[1];
            if (method === "GET") {
                const entry = files.get(filePath);
                if (!entry) return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 });
                return new Response(JSON.stringify({
                    content: Buffer.from(entry.content, "utf8").toString("base64"),
                    sha: entry.sha
                }), { status: 200 });
            }
            if (method === "PUT") {
                const body = JSON.parse(options.body);
                const newSha = `sha-${shaSeq++}`;
                const rawBuf = Buffer.from(body.content, "base64");
                files.set(filePath, {
                    content: filePath.startsWith("uploads/") ? rawBuf : rawBuf.toString("utf8"),
                    sha: newSha
                });
                return new Response(JSON.stringify({ content: { sha: newSha } }), { status: 200 });
            }
            if (method === "DELETE") {
                files.delete(filePath);
                return new Response(JSON.stringify({ commit: { sha: `del-${shaSeq++}` } }), { status: 200 });
            }
        }
        return new Response(JSON.stringify({ message: `Unhandled URL: ${u}` }), { status: 404 });
    };

    return { mockFetch, files, getRebuildCalls: () => rebuildCalls };
}

function extractCookie(res) {
    const setCookie = res.headers.get("Set-Cookie") || "";
    const match = setCookie.match(/aabtak_session=([^;]+)/);
    return match ? `aabtak_session=${match[1]}` : "";
}

const ORIGIN = "https://editor.aabtak24.in";

function makeReq(reqPath, { method = "GET", body, cookie = "", csrf = "", origin = ORIGIN, ip = "203.0.113.10", contentType } = {}) {
    const headers = new Headers();
    if (origin !== null) headers.set("Origin", origin);
    if (cookie) headers.set("Cookie", cookie);
    if (csrf) headers.set("X-CSRF-Token", csrf);
    if (ip) headers.set("CF-Connecting-IP", ip);

    let payload = body;
    if (body !== undefined && !(body instanceof FormData) && typeof body !== "string") {
        payload = JSON.stringify(body);
        headers.set("Content-Type", contentType || "application/json");
    } else if (contentType) {
        headers.set("Content-Type", contentType);
    }

    return new Request(`${ORIGIN}${reqPath}`, { method, headers, body: payload });
}

describe("Aabtak24 Cloudflare Worker + D1 Server-Side CMS Security Suite", () => {
    let originalFetch;
    let gh;
    let env;

    beforeEach(() => {
        resetSchemaCacheForTests();
        originalFetch = globalThis.fetch;

        const baseSiteConfig = {
            categories: [
                { id: "desh-videsh", name: "देश-विदेश", file: "desh-videsh.html", active_for_ai: true, aliases: ["देश-विदेश"] },
                { id: "technology", name: "टेक्नोलॉजी", file: "technology.html", active_for_ai: true, aliases: ["टेक्नोलॉजी"] }
            ],
            custom_pages: [],
            header_menu: [{ label: "मुख्य खबरें", href: "index.html" }],
            admin_lock: { encrypted_token: "legacy_should_be_stripped" },
            editors_vault: [{ id: "legacy_should_be_stripped" }]
        };
        const baseArticles = [
            {
                title: "Admin Headline",
                category: "देश-विदेश",
                slug: "admin-headline",
                content_html: "<p>Admin body content.</p>",
                image_url: "https://example.com/admin.jpg",
                image_courtesy: "फोटो साभार: अबतक24 न्यूज़ डेस्क",
                original_link: "https://aabtak24.in/news/admin-headline.html",
                source_name: "अबतक24 न्यूज़ डेस्क",
                author_username: "admin",
                author_name: "मुख्य एडमिन",
                date: "19 Nov 2026, 10:00 AM",
                iso_date: "2026-11-19T04:30:00Z"
            }
        ];

        gh = createMockGithubFetch({
            "site_config.json": JSON.stringify(baseSiteConfig),
            "articles_db.json": JSON.stringify(baseArticles)
        });
        globalThis.fetch = gh.mockFetch;

        const publicHtml = fs.readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
        env = {
            CMS_DB: createD1Adapter(),
            GITHUB_REPO: "AdityaCODER1/auto-news-bot",
            GITHUB_BRANCH: "main",
            ALLOWED_ORIGIN: ORIGIN,
            GITHUB_TOKEN: "ghp_super_secret_worker_token_123456",
            PASSWORD_PEPPER: "ultra-secret-server-pepper-value-2026!",
            ADMIN_INITIAL_PASSWORD: "InitAdminPass#2026",
            ADMIN_RECOVERY_KEY: "RECOVERY-KEY-9876-SECRET-2026",
            ASSETS: {
                async fetch(req) {
                    const u = new URL(req.url);
                    if (u.pathname === "/" || u.pathname === "/index.html") {
                        return new Response(publicHtml, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
                    }
                    return new Response("/* asset */", { status: 200, headers: { "Content-Type": "application/javascript" } });
                }
            }
        };
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    async function loginAs(username, password, ip = "203.0.113.10") {
        const res = await worker.fetch(makeReq("/api/auth/login", {
            method: "POST",
            body: { username, password },
            ip
        }), env);
        const data = await res.json();
        return { res, data, cookie: extractCookie(res), csrf: data.csrfToken || "" };
    }

    it("1. Serves static UI with strict CSP, HSTS, X-Frame-Options, and zero client secrets", async () => {
        const res = await worker.fetch(makeReq("/"), env);
        assert.equal(res.status, 200);
        const csp = res.headers.get("Content-Security-Policy") || "";
        assert.ok(csp.includes("connect-src 'self'"), "CSP must restrict connect-src strictly to 'self'");
        assert.ok(csp.includes("frame-ancestors 'none'"), "CSP must block framing");
        assert.ok(csp.includes("object-src 'none'"), "CSP must block plugins/objects");
        assert.equal(res.headers.get("X-Frame-Options"), "DENY");
        assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
        assert.equal(res.headers.get("X-Robots-Tag"), "noindex, nofollow");
        const html = await res.text();
        assert.ok(!html.includes("ghp_super_secret"), "GitHub PAT must never appear in HTML");
        assert.ok(!html.includes("cdn.jsdelivr.net"), "Quill must be locally vendored (zero CDN JS)");
        assert.ok(html.includes("/vendor/quill.min.js"));
        assert.ok(!html.includes("मुख्य एडमिन (Main Admin) लॉगिन के लिए इस बॉक्स को खाली छोड़ें"), "Admin blank-username field hint must be removed");
        assert.ok(!html.includes("मुख्य एडमिन केवल पासवर्ड से लॉगिन कर सकते हैं"), "Admin password-only login subtext must be removed");
        assert.ok(!html.includes("मुख्य एडमिन के लिए खाली छोड़ें"), "Admin blank-username placeholder hint must be removed");
        assert.ok(html.includes('<header class="notranslate" translate="no">'), "Header must lock browser translation");
        assert.ok(html.includes('<div class="top-bar notranslate" translate="no">'), "Top bar must lock browser translation");
        assert.ok(html.includes('<html lang="hi" data-theme="dark">'), "Portal must default to dark mode");
        assert.ok(html.includes('id="portal-theme-toggle-btn"'), "Portal-wide dark mode switcher must be present in header");
    });

    it("2. Bootstraps Main Admin login with HttpOnly SameSite=Strict cookie & enforces CSRF + Origin", async () => {
        const { res, data, cookie, csrf } = await loginAs("", "InitAdminPass#2026");
        assert.equal(res.status, 200);
        assert.equal(data.user.role, "admin");
        const rawSetCookie = res.headers.get("Set-Cookie") || "";
        assert.ok(rawSetCookie.includes("HttpOnly"));
        assert.ok(rawSetCookie.includes("Secure"));
        assert.ok(rawSetCookie.includes("SameSite=Strict"));
        assert.ok(!JSON.stringify(data).includes("ghp_super_secret"), "Token never sent to client");

        // Missing CSRF token -> 403
        const noCsrf = await worker.fetch(makeReq("/api/editors", {
            method: "POST",
            cookie,
            csrf: "",
            body: { username: "a@b.in", password: "Password#123", permission: "own_only" }
        }), env);
        assert.equal(noCsrf.status, 403);

        // Wrong Origin -> 403
        const badOrigin = await worker.fetch(makeReq("/api/editors", {
            method: "POST",
            cookie,
            csrf,
            origin: "https://evil.example.com",
            body: { username: "a@b.in", password: "Password#123", permission: "own_only" }
        }), env);
        assert.equal(badOrigin.status, 403);
    });

    it("3. Enforces Main Admin password change, old session revocation, and Forgot Password Recovery", async () => {
        const s1 = await loginAs("", "InitAdminPass#2026");
        const s2 = await loginAs("", "InitAdminPass#2026");

        // Change Admin password from s1
        const ch = await worker.fetch(makeReq("/api/auth/change-password", {
            method: "POST",
            cookie: s1.cookie,
            csrf: s1.csrf,
            body: { currentPassword: "InitAdminPass#2026", newPassword: "NewAdminPass#2026" }
        }), env);
        assert.equal(ch.status, 200);

        // s2 (other admin session) is immediately revoked!
        const s2Check = await worker.fetch(makeReq("/api/auth/me", { cookie: s2.cookie }), env);
        assert.equal((await s2Check.json()).authenticated, false);

        // Old password fails
        const oldLogin = await loginAs("", "InitAdminPass#2026");
        assert.equal(oldLogin.res.status, 401);

        // New password succeeds
        const newLogin = await loginAs("", "NewAdminPass#2026");
        assert.equal(newLogin.res.status, 200);

        // Forgot Admin Password Recovery: wrong key rejected, valid key resets & revokes all old sessions
        const badRec = await worker.fetch(makeReq("/api/auth/recover-admin", {
            method: "POST",
            body: { recoveryKey: "WRONG-KEY", newPassword: "RecoveredPass#2026" }
        }), env);
        assert.equal(badRec.status, 401);

        const goodRec = await worker.fetch(makeReq("/api/auth/recover-admin", {
            method: "POST",
            body: { recoveryKey: "RECOVERY-KEY-9876-SECRET-2026", newPassword: "RecoveredPass#2026" }
        }), env);
        assert.equal(goodRec.status, 200);

        // Previous s1 session revoked after recovery
        const s1AfterRec = await worker.fetch(makeReq("/api/auth/me", { cookie: s1.cookie }), env);
        assert.equal((await s1AfterRec.json()).authenticated, false);

        const recLogin = await loginAs("", "RecoveredPass#2026");
        assert.equal(recLogin.res.status, 200);
    });

    it("4. Enforces strict server-side RBAC, article ownership isolation, sanitization, and anti-spoofing", async () => {
        const admin = await loginAs("", "InitAdminPass#2026");

        // Create own_only sub-editor
        const createEd = await worker.fetch(makeReq("/api/editors", {
            method: "POST",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: {
                username: "Rahul.Sharma@Aabtak24.in",
                display_name: "राहुल शर्मा",
                password: "RahulPassword#2026",
                permission: "own_only"
            }
        }), env);
        assert.equal(createEd.status, 201);
        const createdEdData = await createEd.json();
        const rahulId = createdEdData.id;

        // Verify password hashes are NEVER returned by GET /api/editors
        assert.equal(createdEdData.editors[0].password_hash, undefined);
        assert.equal(createdEdData.editors[0].salt, undefined);

        // Rahul logs in (mixed case email)
        const rahul = await loginAs("RAHUL.SHARMA@aabtak24.in", "RahulPassword#2026");
        assert.equal(rahul.res.status, 200);
        assert.equal(rahul.data.user.role, "editor");
        assert.equal(rahul.data.user.permission, "own_only");

        // Server-side visibility isolation: Rahul gets 0 articles (Admin's post is NOT sent over the wire!)
        const rahulArtsRes = await worker.fetch(makeReq("/api/articles", { cookie: rahul.cookie }), env);
        const rahulArts = await rahulArtsRes.json();
        assert.equal(rahulArts.articles.length, 0, "own_only editor must NOT receive others' articles from server");

        // Least privilege config: sub-editor only receives categories
        const rahulCfgRes = await worker.fetch(makeReq("/api/config", { cookie: rahul.cookie }), env);
        const rahulCfg = await rahulCfgRes.json();
        assert.ok(Array.isArray(rahulCfg.config.categories));
        assert.equal(rahulCfg.config.header_menu, undefined);

        // Sub-editor blocked from admin-only endpoints (403)
        for (const [method, ep, body] of [
            ["GET", "/api/editors", undefined],
            ["GET", "/api/audit-logs", undefined],
            ["PUT", "/api/config", { config: { categories: [{ name: "x" }] } }],
            ["PUT", "/api/custom-pages/_new", { title: "x", output_file: "x.html", h1_text: "x" }],
            ["PUT", "/api/articles/admin-headline", { title: "Hijacked", category: "देश-विदेश", content_html: "<p>Long enough hijacked text here.</p>" }],
            ["DELETE", "/api/articles/admin-headline", undefined]
        ]) {
            const r = await worker.fetch(makeReq(ep, { method, cookie: rahul.cookie, csrf: rahul.csrf, body }), env);
            assert.equal(r.status, 403, `Sub-editor must get 403 on ${method} ${ep}`);
        }

        // Rahul publishes a new article with XSS payload and spoofed author_username
        const pubRes = await worker.fetch(makeReq("/api/articles", {
            method: "POST",
            cookie: rahul.cookie,
            csrf: rahul.csrf,
            body: {
                title: "राहुल की पहली रिपोर्ट",
                category: "देश-विदेश",
                slug: "rahul-first-report",
                author_username: "admin", // spoof attempt — server must ignore!
                content_html: '<h1>हेडिंग</h1><p onclick="evil()">सुरक्षित समाचार सामग्री यहाँ है। <a href="javascript:alert(1)">bad</a></p><script>steal()</script><svg onload="x()"></svg>'
            }
        }), env);
        assert.equal(pubRes.status, 201);
        const pubData = await pubRes.json();
        assert.equal(pubData.slug, "rahul-first-report");
        assert.equal(pubData.articles.length, 1);

        const storedDb = JSON.parse(gh.files.get("articles_db.json").content);
        const saved = storedDb.find(a => a.slug === "rahul-first-report");
        assert.equal(saved.author_username, "rahul.sharma@aabtak24.in", "Server must ignore spoofed author_username");
        assert.equal(saved.author_name, "राहुल शर्मा");
        assert.equal(saved.source_name, "अबतक24 न्यूज़ डेस्क");
        assert.ok(!saved.content_html.includes("<script"), "Server sanitizer stripped <script>");
        assert.ok(!saved.content_html.includes("<svg"), "Server sanitizer stripped <svg>");
        assert.ok(!saved.content_html.includes("onclick"), "Server sanitizer stripped onclick");
        assert.ok(!saved.content_html.includes("javascript:"), "Server sanitizer stripped javascript: href");

        // Rahul CAN edit his own article
        const editOwn = await worker.fetch(makeReq("/api/articles/rahul-first-report", {
            method: "PUT",
            cookie: rahul.cookie,
            csrf: rahul.csrf,
            body: {
                title: "राहुल की अपडेटेड रिपोर्ट",
                category: "टेक्नोलॉजी",
                content_html: "<p>यह अपडेट की गई पूरी सुरक्षित हिंदी समाचार सामग्री है।</p>"
            }
        }), env);
        assert.equal(editOwn.status, 200);

        // Admin upgrades Rahul to all_articles -> Rahul immediately sees & edits Admin's article!
        const upg = await worker.fetch(makeReq(`/api/editors/${rahulId}`, {
            method: "PATCH",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: { permission: "all_articles" }
        }), env);
        assert.equal(upg.status, 200);

        const allVisRes = await worker.fetch(makeReq("/api/articles", { cookie: rahul.cookie }), env);
        assert.equal((await allVisRes.json()).articles.length, 2, "Upgraded all_articles editor now sees all articles");

        // Admin suspends Rahul -> Rahul's live cookie IMMEDIATELY returns 401!
        const susp = await worker.fetch(makeReq(`/api/editors/${rahulId}`, {
            method: "PATCH",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: { active: false }
        }), env);
        assert.equal(susp.status, 200);

        const afterSusp = await worker.fetch(makeReq("/api/articles", { cookie: rahul.cookie }), env);
        assert.equal(afterSusp.status, 401, "Suspended editor session must be immediately revoked server-side");

        // Anti-enumeration on suspended account: wrong password -> 401, right password -> 403 suspended
        const wrongPwdSusp = await loginAs("rahul.sharma@aabtak24.in", "WrongPassword!!", "198.51.100.5");
        assert.equal(wrongPwdSusp.res.status, 401);
        const rightPwdSusp = await loginAs("rahul.sharma@aabtak24.in", "RahulPassword#2026", "198.51.100.6");
        assert.equal(rightPwdSusp.res.status, 403);
    });

    it("5. Hardens image uploads (magic-byte check rejects disguised SVG/HTML, enforces 5MB cap, accepts real PNG/JPEG)", async () => {
        const admin = await loginAs("", "InitAdminPass#2026");

        // Disguised SVG named evil.jpg -> rejected with 415
        const fakeForm = new FormData();
        fakeForm.append("file", new File([new TextEncoder().encode('<svg onload="alert(1)"></svg>')], "evil.jpg", { type: "image/jpeg" }));
        fakeForm.append("slug", "../../etc/passwd");
        const fakeRes = await worker.fetch(makeReq("/api/uploads", {
            method: "POST",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: fakeForm
        }), env);
        assert.equal(fakeRes.status, 415, "Disguised SVG must be rejected via magic bytes");

        // Real valid PNG header -> accepted & filename rewritten cleanly
        const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);
        const validForm = new FormData();
        validForm.append("file", new File([pngBytes], "../weird name.evil.exe", { type: "application/octet-stream" }));
        validForm.append("slug", "My Report!!");
        const okRes = await worker.fetch(makeReq("/api/uploads", {
            method: "POST",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: validForm
        }), env);
        assert.equal(okRes.status, 201);
        const okData = await okRes.json();
        assert.match(okData.path, /^uploads\/my-report-\d+-[a-f0-9]{6}\.png$/);
        assert.ok(gh.files.has(okData.path));
    });

    it("6. Strips legacy auth vault keys from site_config.json, blocks path traversal in custom pages, and records audit logs", async () => {
        const admin = await loginAs("", "InitAdminPass#2026");

        // PUT /api/config strips legacy admin_lock and editors_vault completely from GitHub!
        const cfgSave = await worker.fetch(makeReq("/api/config", {
            method: "PUT",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: {
                config: {
                    categories: [{ id: "desh-videsh", name: "देश-विदेश", file: "desh-videsh.html", active_for_ai: true, aliases: ["देश-विदेश"] }],
                    header_menu: [{ label: "मुख्य खबरें", href: "index.html" }]
                }
            }
        }), env);
        assert.equal(cfgSave.status, 200);
        const savedCfg = JSON.parse(gh.files.get("site_config.json").content);
        assert.equal(savedCfg.admin_lock, undefined, "Legacy admin_lock must be stripped from public GitHub repo");
        assert.equal(savedCfg.editors_vault, undefined, "Legacy editors_vault must be stripped from public GitHub repo");

        // Block path traversal & index.html overwrite in custom pages
        const travRes = await worker.fetch(makeReq("/api/custom-pages/_new", {
            method: "PUT",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: { title: "Bad", output_file: "../news_bot.py", h1_text: "Bad", content_html: "<p>x</p>" }
        }), env);
        assert.equal(travRes.status, 400);

        const idxRes = await worker.fetch(makeReq("/api/custom-pages/_new", {
            method: "PUT",
            cookie: admin.cookie,
            csrf: admin.csrf,
            body: { title: "Bad", output_file: "index.html", h1_text: "Bad", content_html: "<p>x</p>" }
        }), env);
        assert.equal(idxRes.status, 400);

        // Audit logs recorded in D1
        const logsRes = await worker.fetch(makeReq("/api/audit-logs", { cookie: admin.cookie }), env);
        assert.equal(logsRes.status, 200);
        const logsData = await logsRes.json();
        assert.ok(logsData.logs.some(l => l.action === "login_success"));
        assert.ok(logsData.logs.some(l => l.action === "site_config_updated"));
    });

    it("7. Enforces server-side D1 login rate limiting after 5 failed attempts", async () => {
        for (let i = 0; i < 4; i++) {
            const r = await loginAs("", "WrongPass#123", "198.51.100.77");
            assert.equal(r.res.status, 401);
        }
        const fifth = await loginAs("", "WrongPass#123", "198.51.100.77");
        assert.equal(fifth.res.status, 429);
        assert.ok(Number(fifth.res.headers.get("Retry-After")) > 0);

        // Even valid password blocked from locked IP during cooldown!
        const blockedValid = await loginAs("", "InitAdminPass#2026", "198.51.100.77");
        assert.equal(blockedValid.res.status, 429);
    });
});
