/**
 * Strict server-side HTML sanitization, URL validation, slug/filename validation,
 * and binary image magic-byte verification.
 * Runs inside Cloudflare Workers before anything is committed to GitHub.
 */

const ALLOWED_TAGS = new Set([
    "p", "br", "h2", "h3", "h4", "strong", "b", "em", "i", "u", "s",
    "blockquote", "ul", "ol", "li", "a", "span", "hr"
]);

const VOID_TAGS = new Set(["br", "hr"]);

const STRIP_WITH_CONTENT_TAGS = [
    "script", "style", "iframe", "object", "embed", "svg", "math",
    "noscript", "template", "form", "textarea", "select", "option", "button"
];

const RESERVED_FILES = new Set([
    "index.html", "404.html", "robots.txt", "sitemap.xml",
    "articles_db.json", "site_config.json", "news_bot.py"
]);

export function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

export function cleanSlug(text) {
    return String(text || "")
        .toLowerCase()
        .replace(/\s+/g, "-")
        .replace(/[^a-z0-9\-]/g, "")
        .replace(/\-+/g, "-")
        .replace(/^\-+|\-+$/g, "")
        .slice(0, 120);
}

export function normalizeUsername(raw) {
    return String(raw || "").trim().toLowerCase();
}

export function sanitizeImageUrl(rawUrl) {
    const u = String(rawUrl || "").trim();
    if (!u) return "";
    if (/^https?:\/\//i.test(u)) {
        try {
            const parsed = new URL(u);
            if (parsed.protocol === "http:" || parsed.protocol === "https:") {
                return parsed.href;
            }
        } catch (_) {
            return "";
        }
    }
    if (/^uploads\/[a-zA-Z0-9][a-zA-Z0-9_\-.]{0,160}\.(jpg|jpeg|png|webp)$/i.test(u) && !u.includes("..")) {
        return u;
    }
    return "";
}

export function sanitizeHref(rawHref) {
    const val = String(rawHref || "").trim();
    if (!val) return "";
    // Remove ASCII control characters & whitespace before protocol inspection
    const collapsed = val.replace(/[\u0000-\u001F\u007F\s]+/g, "");
    const lower = collapsed.toLowerCase();
    if (lower.startsWith("https://") || lower.startsWith("http://") || lower.startsWith("mailto:")) {
        try {
            const parsed = new URL(val);
            if (["http:", "https:", "mailto:"].includes(parsed.protocol)) {
                return parsed.href;
            }
        } catch (_) {
            return "";
        }
        return "";
    }
    if (val.startsWith("#") && /^#[a-zA-Z0-9_\-]{1,80}$/.test(val)) {
        return val;
    }
    if (/^[a-zA-Z0-9_\-./]{1,140}$/.test(val) && !val.includes("..") && !val.startsWith("//")) {
        return val;
    }
    return "";
}

function parseAttributes(attrStr) {
    const attrs = [];
    const re = /([a-zA-Z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let match;
    while ((match = re.exec(attrStr)) !== null) {
        attrs.push({
            name: match[1].toLowerCase(),
            value: match[2] ?? match[3] ?? match[4] ?? ""
        });
    }
    return attrs;
}

/**
 * Strict allowlist HTML sanitizer for Quill rich-text content.
 * Strips dangerous elements (with their body), HTML comments, event handlers,
 * inline styles, and unsafe URL schemes.
 */
export function sanitizeRichHtml(dirtyHtml) {
    let html = String(dirtyHtml || "");

    // 1. Remove HTML comments and CDATA
    html = html.replace(/<!--[\s\S]*?-->/g, "");
    html = html.replace(/<!\[CDATA\[[\s\S]*?\]\]>/gi, "");

    // 2. Remove dangerous tags AND everything inside them
    for (const tag of STRIP_WITH_CONTENT_TAGS) {
        const pairRe = new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}\\s*>`, "gi");
        html = html.replace(pairRe, "");
        const openOnlyRe = new RegExp(`<\\/?${tag}\\b[^>]*>`, "gi");
        html = html.replace(openOnlyRe, "");
    }

    // 3. Walk all remaining tags and enforce strict allowlist + safe attributes
    html = html.replace(/<(\/?)([a-zA-Z0-9]+)([^>]*)>/g, (_full, closingSlash, rawTag, attrStr) => {
        const tag = rawTag.toLowerCase();
        if (!ALLOWED_TAGS.has(tag)) {
            return "";
        }
        if (closingSlash) {
            return VOID_TAGS.has(tag) ? "" : `</${tag}>`;
        }
        if (VOID_TAGS.has(tag)) {
            return `<${tag}>`;
        }

        const attrs = parseAttributes(attrStr || "");
        const safeParts = [];

        if (tag === "a") {
            let safeHref = "";
            let openBlank = false;
            for (const a of attrs) {
                if (a.name === "href") {
                    safeHref = sanitizeHref(a.value);
                } else if (a.name === "target" && a.value.trim().toLowerCase() === "_blank") {
                    openBlank = true;
                }
            }
            if (safeHref) {
                safeParts.push(`href="${escapeHtml(safeHref)}"`);
            }
            if (openBlank) {
                safeParts.push(`target="_blank"`, `rel="noopener noreferrer"`);
            }
        } else if (["p", "li", "span", "h2", "h3", "h4"].includes(tag)) {
            const clsAttr = attrs.find(a => a.name === "class");
            if (clsAttr && clsAttr.value) {
                const safeClasses = clsAttr.value
                    .split(/\s+/)
                    .filter(c => /^(ql-indent-[1-8]|ql-align-(center|right|justify))$/.test(c));
                if (safeClasses.length) {
                    safeParts.push(`class="${safeClasses.join(" ")}"`);
                }
            }
        }

        return safeParts.length ? `<${tag} ${safeParts.join(" ")}>` : `<${tag}>`;
    });

    return html.trim();
}

export function stripHtmlToText(html) {
    return String(html || "")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/\s+/g, " ")
        .trim();
}

/**
 * Verifies real binary magic bytes for uploaded images (JPEG, PNG, WebP only).
 * Blocks disguised SVG, HTML, JS, GIF, or arbitrary binary uploads.
 */
export function verifyImageMagicBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 12) {
        return { valid: false, reason: "File is too small or empty to be a valid image." };
    }
    // JPEG: FF D8 FF
    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
        return { valid: true, ext: "jpg", mime: "image/jpeg" };
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (
        bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
        bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a
    ) {
        return { valid: true, ext: "png", mime: "image/png" };
    }
    // WebP: RIFF....WEBP
    if (
        bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
        bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
    ) {
        return { valid: true, ext: "webp", mime: "image/webp" };
    }
    return { valid: false, reason: "Only valid JPEG, PNG, or WebP images are permitted." };
}

export function validateCustomPageFilename(raw) {
    let f = String(raw || "").trim().toLowerCase();
    if (!f) return null;
    if (!f.endsWith(".html")) f += ".html";
    if (RESERVED_FILES.has(f)) return null;
    if (!/^[a-z0-9][a-z0-9\-]{0,60}\.html$/.test(f)) return null;
    return f;
}

export function validateFragmentPath(raw) {
    const p = String(raw || "").trim().toLowerCase();
    if (!/^pages\/[a-z0-9][a-z0-9\-]{0,60}\.html$/.test(p) || p.includes("..")) {
        return null;
    }
    return p;
}

export function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const sub = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...sub);
    }
    return btoa(binary);
}

export function utf8ToBase64(str) {
    return bytesToBase64(new TextEncoder().encode(String(str ?? "")));
}

export function base64ToUtf8(b64) {
    const clean = String(b64 || "").replace(/\s/g, "");
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}
