/**
 * Article routes with strict server-side RBAC, ownership enforcement, and HTML sanitization:
 *  - GET    /api/articles         (own_only editors ONLY receive their own articles from server!)
 *  - POST   /api/articles         (creates article with trusted server session author attribution)
 *  - PUT    /api/articles/:slug   (server verifies ownership for own_only editors before modifying)
 *  - DELETE /api/articles/:slug   (server verifies ownership for own_only editors before deleting)
 */

import { authenticateRequest, getClientIp, verifyOriginAndCsrf } from "../auth.js";
import { writeAuditLog } from "../db.js";
import { ghGetFile, mutateJsonFileWithRetry, triggerRebuild } from "../github.js";
import { errorResponse, jsonResponse, readJsonBody } from "../http.js";
import {
    cleanSlug,
    normalizeUsername,
    sanitizeImageUrl,
    sanitizeRichHtml,
    stripHtmlToText
} from "../sanitize.js";

const DEFAULT_ARTICLE_IMAGE = "https://images.unsplash.com/photo-1504711434969-e33886168f5c?auto=format&fit=crop&w=1200&q=80";

function canManageAll(session) {
    return session.role === "admin" || session.permission === "all_articles";
}

function isArticleOwnedBy(article, session) {
    if (!article || !session) return false;
    const author = normalizeUsername(article.author_username);
    const current = normalizeUsername(session.username);
    return Boolean(author && current && author === current);
}

function formatIndiaDate(dateObj = new Date()) {
    try {
        return dateObj.toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            hour12: true
        });
    } catch (_) {
        return dateObj.toISOString();
    }
}

export async function handleArticlesRoutes(request, env, pathname) {
    const method = request.method.toUpperCase();
    const session = await authenticateRequest(request, env);
    if (!session) {
        return errorResponse("सत्र समाप्त हो गया है। कृपया पुनः लॉगिन करें।", 401);
    }

    const ip = getClientIp(request);

    // 1. GET /api/articles
    if (pathname === "/api/articles" && method === "GET") {
        const dbFile = await ghGetFile(env, "articles_db.json");
        const allArticles = dbFile && dbFile.content ? JSON.parse(dbFile.content) : [];
        const list = Array.isArray(allArticles) ? allArticles : [];

        // True server-side visibility isolation: own_only editors never even receive others' articles
        const visible = canManageAll(session)
            ? list
            : list.filter(art => isArticleOwnedBy(art, session));

        return jsonResponse({ articles: visible });
    }

    // All mutations require strict Origin + CSRF verification
    const csrfCheck = await verifyOriginAndCsrf(request, env, session);
    if (!csrfCheck.ok) {
        return errorResponse(csrfCheck.error, 403);
    }

    // 2. POST /api/articles (Create New Article)
    if (pathname === "/api/articles" && method === "POST") {
        const body = await readJsonBody(request, 512 * 1024);
        const title = String(body.title || "").trim().slice(0, 300);
        const category = String(body.category || "").trim().slice(0, 80) || "देश-विदेश";
        const rawSlug = String(body.slug || "").trim();
        const rawImg = String(body.image_url || "").trim();
        const courtesy = String(body.image_courtesy || "").trim().slice(0, 200) || "फोटो साभार: अबतक24 न्यूज़ डेस्क";

        const normalizedHeadings = String(body.content_html || "")
            .replace(/<h[12]\b[^>]*>/gi, "<h3>")
            .replace(/<\/h[12]\s*>/gi, "</h3>");
        const cleanedHtml = sanitizeRichHtml(normalizedHeadings);
        const plainText = stripHtmlToText(cleanedHtml);

        if (!title || plainText.length < 15) {
            return errorResponse("⚠️ कृपया समाचार का शीर्षक और पर्याप्त सामग्री दोनों भरें।", 400);
        }

        let finalImageUrl = DEFAULT_ARTICLE_IMAGE;
        if (rawImg) {
            const safeImg = sanitizeImageUrl(rawImg);
            if (!safeImg) {
                return errorResponse("⚠️ अमान्य फ़ोटो लिंक! केवल https:// या अपलोड की गई फ़ोटो ही मान्य है।", 400);
            }
            finalImageUrl = safeImg;
        }

        const now = new Date();
        const nowStr = formatIndiaDate(now);
        const isoNow = now.toISOString();

        let createdSlug = "";
        const { data: updatedArticles } = await mutateJsonFileWithRetry(
            env,
            "articles_db.json",
            [],
            (freshArticles) => {
                const list = Array.isArray(freshArticles) ? freshArticles : [];
                let slug = cleanSlug(rawSlug) || `report-${Math.floor(Date.now() / 1000)}`;
                while (list.some(a => a && a.slug === slug)) {
                    slug = `${slug}-${Math.floor(100 + Math.random() * 900)}`;
                }
                createdSlug = slug;

                list.unshift({
                    title,
                    category,
                    slug,
                    content_html: cleanedHtml,
                    image_url: finalImageUrl,
                    image_courtesy: courtesy,
                    original_link: `https://aabtak24.in/news/${slug}.html`,
                    source_name: "अबतक24 न्यूज़ डेस्क",
                    author_username: session.username,
                    author_name: session.displayName || session.username,
                    date: nowStr,
                    iso_date: isoNow
                });
                return { nextData: list.slice(0, 100), slug };
            },
            () => `Publish article: ${title}`
        );

        await triggerRebuild(env);
        await writeAuditLog(env.CMS_DB, {
            role: session.role,
            username: session.username,
            action: "article_created",
            target: createdSlug,
            details: title,
            ip
        });

        const visible = canManageAll(session)
            ? updatedArticles
            : updatedArticles.filter(art => isArticleOwnedBy(art, session));

        return jsonResponse({ ok: true, slug: createdSlug, articles: visible }, 201);
    }

    // 3. PUT / DELETE /api/articles/:slug
    const slugMatch = pathname.match(/^\/api\/articles\/([^/]+)$/);
    if (!slugMatch) {
        return errorResponse("Not Found", 404);
    }
    const targetSlug = decodeURIComponent(slugMatch[1]).trim();
    if (!targetSlug || targetSlug.includes("/") || targetSlug.includes("..")) {
        return errorResponse("Invalid article slug.", 400);
    }

    if (method === "PUT") {
        const body = await readJsonBody(request, 512 * 1024);
        const title = String(body.title || "").trim().slice(0, 300);
        const category = String(body.category || "").trim().slice(0, 80) || "देश-विदेश";
        const rawImg = String(body.image_url || "").trim();
        const courtesy = String(body.image_courtesy || "").trim().slice(0, 200) || "फोटो साभार: अबतक24 न्यूज़ डेस्क";

        const normalizedHeadings = String(body.content_html || "")
            .replace(/<h[12]\b[^>]*>/gi, "<h3>")
            .replace(/<\/h[12]\s*>/gi, "</h3>");
        const cleanedHtml = sanitizeRichHtml(normalizedHeadings);
        const plainText = stripHtmlToText(cleanedHtml);

        if (!title || plainText.length < 15) {
            return errorResponse("⚠️ कृपया समाचार का शीर्षक और पर्याप्त सामग्री दोनों भरें।", 400);
        }

        let finalImageUrl = DEFAULT_ARTICLE_IMAGE;
        if (rawImg) {
            const safeImg = sanitizeImageUrl(rawImg);
            if (!safeImg) {
                return errorResponse("⚠️ अमान्य फ़ोटो लिंक! केवल https:// या अपलोड की गई फ़ोटो ही मान्य है।", 400);
            }
            finalImageUrl = safeImg;
        }

        try {
            const { data: updatedArticles } = await mutateJsonFileWithRetry(
                env,
                "articles_db.json",
                [],
                (freshArticles) => {
                    const list = Array.isArray(freshArticles) ? freshArticles : [];
                    const idx = list.findIndex(a => a && a.slug === targetSlug);
                    if (idx === -1) {
                        const err = new Error("संपादित किया जाने वाला लेख नहीं मिला।");
                        err.status = 404;
                        throw err;
                    }
                    if (!canManageAll(session) && !isArticleOwnedBy(list[idx], session)) {
                        const err = new Error("⛔ आपको केवल अपने द्वारा प्रकाशित लेखों में सुधार करने की अनुमति है।");
                        err.status = 403;
                        throw err;
                    }

                    list[idx] = {
                        ...list[idx],
                        title,
                        category,
                        content_html: cleanedHtml,
                        image_url: finalImageUrl,
                        image_courtesy: courtesy,
                        updated_by: session.username,
                        updated_at: new Date().toISOString()
                    };
                    return { nextData: list.slice(0, 100) };
                },
                () => `Edit article: ${title}`
            );

            await triggerRebuild(env);
            await writeAuditLog(env.CMS_DB, {
                role: session.role,
                username: session.username,
                action: "article_updated",
                target: targetSlug,
                details: title,
                ip
            });

            const visible = canManageAll(session)
                ? updatedArticles
                : updatedArticles.filter(art => isArticleOwnedBy(art, session));

            return jsonResponse({ ok: true, slug: targetSlug, articles: visible });
        } catch (err) {
            return errorResponse(err.message || "Update failed.", err.status || 500);
        }
    }

    if (method === "DELETE") {
        try {
            const { data: updatedArticles } = await mutateJsonFileWithRetry(
                env,
                "articles_db.json",
                [],
                (freshArticles) => {
                    const list = Array.isArray(freshArticles) ? freshArticles : [];
                    const existing = list.find(a => a && a.slug === targetSlug);
                    if (!existing) {
                        const err = new Error("हटाया जाने वाला लेख नहीं मिला।");
                        err.status = 404;
                        throw err;
                    }
                    if (!canManageAll(session) && !isArticleOwnedBy(existing, session)) {
                        const err = new Error("⛔ आपको केवल अपने द्वारा प्रकाशित लेखों को हटाने की अनुमति है।");
                        err.status = 403;
                        throw err;
                    }
                    return { nextData: list.filter(a => a && a.slug !== targetSlug) };
                },
                () => `Delete article: ${targetSlug}`
            );

            await triggerRebuild(env);
            await writeAuditLog(env.CMS_DB, {
                role: session.role,
                username: session.username,
                action: "article_deleted",
                target: targetSlug,
                ip
            });

            const visible = canManageAll(session)
                ? updatedArticles
                : updatedArticles.filter(art => isArticleOwnedBy(art, session));

            return jsonResponse({ ok: true, articles: visible });
        } catch (err) {
            return errorResponse(err.message || "Delete failed.", err.status || 500);
        }
    }

    return errorResponse("Method Not Allowed", 405);
}
