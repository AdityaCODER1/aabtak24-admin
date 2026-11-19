/**
 * Cloudflare Worker entry point for editor.aabtak24.in
 * - Routes /api/* to server-side authenticated endpoints (D1 + GitHub REST API)
 * - Serves static UI assets from ./public on the exact same origin with strict HTTP security headers
 */

import { ensureSchema } from "./db.js";
import { HTML_SECURITY_HEADERS, errorResponse } from "./http.js";
import { handleArticlesRoutes } from "./routes/articles.js";
import { handleAuthRoutes } from "./routes/auth.js";
import { handleConfigRoutes } from "./routes/config.js";
import { handleEditorsRoutes } from "./routes/editors.js";
import { handleUploadRoutes } from "./routes/uploads.js";

function withSecurityHeaders(response, isVendorAsset = false) {
    const headers = new Headers(response.headers);
    for (const [k, v] of Object.entries(HTML_SECURITY_HEADERS)) {
        headers.set(k, v);
    }
    if (isVendorAsset) {
        headers.set("Cache-Control", "public, max-age=31536000, immutable");
    } else {
        headers.set("Cache-Control", "no-store");
    }
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
    });
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const pathname = url.pathname;

        // 1. Server-side API routes (/api/*)
        if (pathname.startsWith("/api/")) {
            try {
                await ensureSchema(env.CMS_DB);

                if (pathname.startsWith("/api/auth/")) {
                    return await handleAuthRoutes(request, env, pathname);
                }
                if (pathname === "/api/articles" || pathname.startsWith("/api/articles/")) {
                    return await handleArticlesRoutes(request, env, pathname);
                }
                if (pathname === "/api/uploads") {
                    return await handleUploadRoutes(request, env, pathname);
                }
                if (pathname === "/api/config" || pathname.startsWith("/api/custom-pages/")) {
                    return await handleConfigRoutes(request, env, pathname);
                }
                if (pathname === "/api/editors" || pathname.startsWith("/api/editors/") || pathname === "/api/audit-logs") {
                    return await handleEditorsRoutes(request, env, pathname);
                }
                return errorResponse("API endpoint not found.", 404);
            } catch (err) {
                const status = err && Number.isInteger(err.status) ? err.status : 500;
                const msg = err && err.message ? err.message : "Internal Server Error";
                return errorResponse(msg, status);
            }
        }

        // 2. Static CMS UI & locally vendored assets from ./public
        if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
            const assetResponse = await env.ASSETS.fetch(request);
            return withSecurityHeaders(assetResponse, pathname.startsWith("/vendor/"));
        }

        return errorResponse("Static ASSETS binding not configured.", 500);
    }
};
