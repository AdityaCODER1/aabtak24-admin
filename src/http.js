/**
 * Shared HTTP response & strict security header helpers.
 */

export const HTML_SECURITY_HEADERS = {
    "Content-Security-Policy": [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' https: data: blob:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'"
    ].join("; "),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Robots-Tag": "noindex, nofollow"
};

export const API_SECURITY_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Robots-Tag": "noindex, nofollow"
};

export function jsonResponse(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            ...API_SECURITY_HEADERS,
            ...extraHeaders
        }
    });
}

export function errorResponse(message, status = 400, extra = {}, extraHeaders = {}) {
    return jsonResponse({ error: message, ...extra }, status, extraHeaders);
}

export async function readJsonBody(request, maxBytes = 1024 * 1024) {
    const contentType = String(request.headers.get("Content-Type") || "").toLowerCase();
    if (!contentType.includes("application/json")) {
        const err = new Error("Content-Type must be application/json.");
        err.status = 415;
        throw err;
    }
    const text = await request.text();
    if (text.length > maxBytes) {
        const err = new Error("Request body exceeds maximum allowed size.");
        err.status = 413;
        throw err;
    }
    try {
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Body must be a JSON object.");
        }
        return parsed;
    } catch (_) {
        const err = new Error("Invalid JSON request body.");
        err.status = 400;
        throw err;
    }
}
