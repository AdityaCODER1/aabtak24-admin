/**
 * Site Configuration & Custom Static Pages routes:
 *  - GET    /api/config              (Sub-editors receive ONLY { categories }; Admin receives full config)
 *  - PUT    /api/config              (Main Admin ONLY — commits site_config.json & triggers rebuild)
 *  - GET    /api/custom-pages/:id    (Main Admin ONLY — reads fragment under pages/*.html)
 *  - PUT    /api/custom-pages/:id    (Main Admin ONLY — sanitizes & saves fragment + site_config.json)
 *  - DELETE /api/custom-pages/:id    (Main Admin ONLY — deletes fragment + removes from site_config.json)
 */

import { authenticateRequest, getClientIp, verifyOriginAndCsrf } from "../auth.js";
import { writeAuditLog } from "../db.js";
import { ghDeleteFile, ghGetFile, ghPutFile, mutateJsonFileWithRetry, triggerRebuild } from "../github.js";
import { errorResponse, jsonResponse, readJsonBody } from "../http.js";
import {
    cleanSlug,
    escapeHtml,
    sanitizeRichHtml,
    validateCustomPageFilename,
    validateFragmentPath
} from "../sanitize.js";

const MANAGED_PUBLIC_KEYS = ["categories", "custom_pages", "header", "header_menu", "footer", "homepage"];
const LEGACY_SECRET_KEYS = new Set(["admin_lock", "editors_vault"]);

function stripLegacyAuthKeys(obj) {
    const out = {};
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        for (const [k, v] of Object.entries(obj)) {
            if (!LEGACY_SECRET_KEYS.has(k)) {
                out[k] = v;
            }
        }
    }
    return out;
}

export async function handleConfigRoutes(request, env, pathname) {
    const method = request.method.toUpperCase();
    const session = await authenticateRequest(request, env);
    if (!session) {
        return errorResponse("सत्र समाप्त हो गया है। कृपया पुनः लॉगिन करें।", 401);
    }

    const ip = getClientIp(request);

    // 1. GET /api/config
    if (pathname === "/api/config" && method === "GET") {
        const cfgFile = await ghGetFile(env, "site_config.json");
        const parsed = cfgFile && cfgFile.content ? stripLegacyAuthKeys(JSON.parse(cfgFile.content)) : null;

        // Least privilege: Sub-editors only receive the categories list needed for publishing articles
        if (session.role !== "admin") {
            return jsonResponse({
                config: parsed ? { categories: Array.isArray(parsed.categories) ? parsed.categories : [] } : null
            });
        }

        return jsonResponse({ config: parsed });
    }

    // Everything else in /api/config and /api/custom-pages is STRICTLY Main Admin only
    if (session.role !== "admin") {
        return errorResponse("⛔ यह अनुभाग केवल मुख्य एडमिन (Main Admin) के लिए आरक्षित है।", 403);
    }

    // 2. PUT /api/config
    if (pathname === "/api/config" && method === "PUT") {
        const csrfCheck = await verifyOriginAndCsrf(request, env, session);
        if (!csrfCheck.ok) return errorResponse(csrfCheck.error, 403);

        const body = await readJsonBody(request, 512 * 1024);
        const incomingConfig = body.config;
        const commitMsg = String(body.commitMessage || "Update site_config.json via Admin CMS").trim().slice(0, 160);

        if (!incomingConfig || typeof incomingConfig !== "object" || Array.isArray(incomingConfig)) {
            return errorResponse("Invalid site configuration payload.", 400);
        }
        if (!Array.isArray(incomingConfig.categories) || !incomingConfig.categories.length) {
            return errorResponse("कम से कम एक समाचार श्रेणी आवश्यक है।", 400);
        }

        const { data: savedConfig } = await mutateJsonFileWithRetry(
            env,
            "site_config.json",
            {},
            (latest) => {
                const base = stripLegacyAuthKeys(latest);
                for (const k of MANAGED_PUBLIC_KEYS) {
                    if (Object.prototype.hasOwnProperty.call(incomingConfig, k)) {
                        base[k] = incomingConfig[k];
                    }
                }
                return { nextData: base };
            },
            () => commitMsg
        );

        await triggerRebuild(env);
        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: session.username,
            action: "site_config_updated",
            target: "site_config.json",
            details: commitMsg,
            ip
        });

        return jsonResponse({ ok: true, config: savedConfig });
    }

    // 3. GET / PUT / DELETE /api/custom-pages/:id
    const pageMatch = pathname.match(/^\/api\/custom-pages\/([^/]+)$/);
    if (!pageMatch) {
        return errorResponse("Not Found", 404);
    }
    const rawPageId = decodeURIComponent(pageMatch[1]).trim();

    if (method === "GET") {
        const cfgFile = await ghGetFile(env, "site_config.json");
        const parsed = cfgFile && cfgFile.content ? JSON.parse(cfgFile.content) : {};
        const pages = Array.isArray(parsed.custom_pages) ? parsed.custom_pages : [];
        const page = pages.find(p => p && p.id === rawPageId);
        if (!page) {
            return errorResponse("कस्टम पेज नहीं मिला।", 404);
        }
        const safeFragPath = validateFragmentPath(page.source_fragment);
        if (!safeFragPath) {
            return errorResponse("अमान्य पेज फ़्रैगमेंट पथ।", 400);
        }
        const fragFile = await ghGetFile(env, safeFragPath);
        return jsonResponse({
            page,
            fragmentHtml: fragFile ? fragFile.content : ""
        });
    }

    const csrfCheck = await verifyOriginAndCsrf(request, env, session);
    if (!csrfCheck.ok) return errorResponse(csrfCheck.error, 403);

    if (method === "PUT") {
        const body = await readJsonBody(request, 512 * 1024);
        const title = String(body.title || "").trim().slice(0, 200);
        const outputFile = validateCustomPageFilename(body.output_file);
        const h1Text = String(body.h1_text || "").trim().slice(0, 200);
        const badgeText = String(body.badge_text || "").trim().slice(0, 120);
        const metaDesc = String(body.meta_description || title).trim().slice(0, 320);
        const includeSitemap = body.include_in_sitemap !== false;
        const allowedFreqs = new Set(["daily", "weekly", "monthly", "yearly"]);
        const changefreq = allowedFreqs.has(String(body.changefreq || "")) ? String(body.changefreq) : "monthly";
        const addToHeader = Boolean(body.add_to_header);
        const addToFooter = Boolean(body.add_to_footer);
        const footerColIdx = body.footer_col_idx !== undefined && body.footer_col_idx !== ""
            ? parseInt(body.footer_col_idx, 10)
            : NaN;

        if (!title || !outputFile || !h1Text) {
            return errorResponse("⚠️ कृपया मान्य Page Title, HTML फ़ाइल नाम (index.html नहीं), और H1 Heading भरें।", 400);
        }

        const pageId = cleanSlug(rawPageId === "_new" ? outputFile.replace(/\.html$/, "") : rawPageId) || `page-${Date.now()}`;
        const fragmentPath = validateFragmentPath(`pages/${outputFile}`);
        if (!fragmentPath) {
            return errorResponse("अमान्य फ़्रैगमेंट फ़ाइल नाम।", 400);
        }

        const sanitizedInner = sanitizeRichHtml(
            String(body.content_html || "")
                .replace(/<h3\b[^>]*>/gi, "<h2>")
                .replace(/<\/h3\s*>/gi, "</h2>")
        );

        const fragmentHtml = `<article class="article-box">
    <a href="index.html" class="back-btn">← मुख्य पृष्ठ पर वापस जाएं</a>
    ${badgeText ? `<div><span class="badge">${escapeHtml(badgeText)}</span></div>` : ""}
    <h1 class="single-title">${escapeHtml(h1Text)}</h1>
    <div class="article-content">
        ${sanitizedInner}
    </div>
</article>`;

        const existingFrag = await ghGetFile(env, fragmentPath);
        await ghPutFile(
            env,
            fragmentPath,
            fragmentHtml,
            `Save custom page fragment: ${fragmentPath}`,
            existingFrag ? existingFrag.sha : null
        );

        const pageRecord = {
            id: pageId,
            title,
            meta_description: metaDesc,
            source_fragment: fragmentPath,
            output_file: outputFile,
            include_in_sitemap: includeSitemap,
            changefreq
        };

        const { data: savedConfig } = await mutateJsonFileWithRetry(
            env,
            "site_config.json",
            {},
            (latest) => {
                const base = stripLegacyAuthKeys(latest);
                if (!Array.isArray(base.custom_pages)) base.custom_pages = [];
                if (!Array.isArray(base.header_menu)) base.header_menu = [];

                const existingIdx = base.custom_pages.findIndex(p => p && p.id === pageId);
                if (existingIdx !== -1) {
                    base.custom_pages[existingIdx] = pageRecord;
                } else {
                    base.custom_pages.push(pageRecord);
                    if (addToHeader && !base.header_menu.some(h => h && h.href === outputFile)) {
                        const navLabel = badgeText.split("/")[0].trim() || title.split("|")[0].trim();
                        base.header_menu.push({ label: navLabel, href: outputFile });
                    }
                    if (addToFooter) {
                        if (!base.footer || typeof base.footer !== "object") base.footer = { columns: [] };
                        if (!Array.isArray(base.footer.columns)) base.footer.columns = [];
                        let targetCol = null;
                        if (!Number.isNaN(footerColIdx) && footerColIdx >= 0 && base.footer.columns[footerColIdx]) {
                            targetCol = base.footer.columns[footerColIdx];
                        } else if (base.footer.columns.length) {
                            targetCol = base.footer.columns.find(c => c && c.id === "pages") || base.footer.columns[base.footer.columns.length - 1];
                        } else {
                            targetCol = { id: "pages", title: "संस्थान एवं नीतियाँ", links: [] };
                            base.footer.columns.push(targetCol);
                        }
                        if (!Array.isArray(targetCol.links)) targetCol.links = [];
                        if (!targetCol.links.some(l => l && l.href === outputFile)) {
                            const footerLabel = title.split("|")[0].trim() || badgeText.split("/")[0].trim() || outputFile;
                            targetCol.links.push({ label: footerLabel, href: outputFile });
                        }
                    }
                }
                return { nextData: base };
            },
            () => `Register custom page ${outputFile} in site_config.json`
        );

        await triggerRebuild(env);
        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: session.username,
            action: "custom_page_saved",
            target: outputFile,
            details: title,
            ip
        });

        return jsonResponse({ ok: true, page: pageRecord, config: savedConfig });
    }

    if (method === "DELETE") {
        const cfgFile = await ghGetFile(env, "site_config.json");
        const parsed = cfgFile && cfgFile.content ? JSON.parse(cfgFile.content) : {};
        const pages = Array.isArray(parsed.custom_pages) ? parsed.custom_pages : [];
        const target = pages.find(p => p && p.id === rawPageId);
        if (!target) {
            return errorResponse("कस्टम पेज नहीं मिला।", 404);
        }

        const safeFragPath = validateFragmentPath(target.source_fragment);
        if (safeFragPath) {
            const fragFile = await ghGetFile(env, safeFragPath);
            if (fragFile) {
                await ghDeleteFile(env, safeFragPath, `Delete fragment ${safeFragPath}`, fragFile.sha);
            }
        }

        const { data: savedConfig } = await mutateJsonFileWithRetry(
            env,
            "site_config.json",
            {},
            (latest) => {
                const base = stripLegacyAuthKeys(latest);
                base.custom_pages = (Array.isArray(base.custom_pages) ? base.custom_pages : []).filter(p => p && p.id !== rawPageId);
                base.header_menu = (Array.isArray(base.header_menu) ? base.header_menu : []).filter(h => h && h.href !== target.output_file);
                if (base.footer && Array.isArray(base.footer.columns)) {
                    base.footer.columns.forEach(col => {
                        if (col && Array.isArray(col.links)) {
                            col.links = col.links.filter(l => l && l.href !== target.output_file);
                        }
                    });
                }
                return { nextData: base };
            },
            () => `Remove custom page ${target.output_file} from site_config.json`
        );

        await triggerRebuild(env);
        await writeAuditLog(env.CMS_DB, {
            role: "admin",
            username: session.username,
            action: "custom_page_deleted",
            target: target.output_file,
            ip
        });

        return jsonResponse({ ok: true, config: savedConfig });
    }

    return errorResponse("Method Not Allowed", 405);
}
