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

const STRIP_WITH_CONTENT_TAGS = new Set([
    "script", "style", "iframe", "object", "embed", "svg", "math",
    "noscript", "template", "form", "textarea", "select", "option",
    "button", "title", "xmp", "plaintext"
]);

const RAW_TEXT_STRIP_TAGS = new Set([
    "script", "style", "textarea", "title", "xmp", "plaintext"
]);

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

function decodeBasicEntities(str) {
    return String(str || "")
        .replace(/&#(\d+);?/g, (_m, dec) => {
            const code = Number.parseInt(dec, 10);
            return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
        })
        .replace(/&#x([0-9a-fA-F]+);?/g, (_m, hex) => {
            const code = Number.parseInt(hex, 16);
            return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
        })
        .replace(/&(amp|lt|gt|quot|apos|colon|tab|newline);/gi, (_m, name) => {
            switch (name.toLowerCase()) {
                case "amp": return "&";
                case "lt": return "<";
                case "gt": return ">";
                case "quot": return "\"";
                case "apos": return "'";
                case "colon": return ":";
                case "tab": return "\t";
                case "newline": return "\n";
                default: return "";
            }
        });
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
    const val = decodeBasicEntities(String(rawHref || "")).trim();
    if (!val) return "";
    // Remove ASCII control characters & whitespace before protocol inspection
    const collapsed = val.replace(/[\u0000-\u001F\u007F\s]+/g, "");
    const lower = collapsed.toLowerCase();
    if (lower.startsWith("https://") || lower.startsWith("http://") || lower.startsWith("mailto:")) {
        try {
            const parsed = new URL(collapsed);
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

function parseAttributesFromSlice(attrStr) {
    const attrs = [];
    let i = 0;
    const len = attrStr.length;
    while (i < len) {
        while (i < len && /[\s/]/.test(attrStr[i])) i++;
        if (i >= len) break;

        const nameStart = i;
        while (i < len && !/[\s=/>]/.test(attrStr[i])) i++;
        const name = attrStr.slice(nameStart, i).toLowerCase();
        if (!name) {
            i++;
            continue;
        }

        while (i < len && /\s/.test(attrStr[i])) i++;
        let value = "";
        if (i < len && attrStr[i] === "=") {
            i++;
            while (i < len && /\s/.test(attrStr[i])) i++;
            if (i < len && (attrStr[i] === '"' || attrStr[i] === "'")) {
                const quote = attrStr[i++];
                const valStart = i;
                while (i < len && attrStr[i] !== quote) i++;
                value = attrStr.slice(valStart, i);
                if (i < len && attrStr[i] === quote) i++;
            } else {
                const valStart = i;
                while (i < len && !/[\s>]/.test(attrStr[i])) i++;
                value = attrStr.slice(valStart, i);
            }
        }
        attrs.push({ name, value });
    }
    return attrs;
}

/**
 * Quote-aware state-machine HTML allowlist sanitizer for Quill rich-text content.
 * Strips dangerous elements with their full body, comments/CDATA/declarations,
 * event handlers, inline styles, and unsafe URL schemes without relying on
 * fragile tag-matching regexes.
 */
export function sanitizeRichHtml(dirtyHtml) {
    const input = String(dirtyHtml || "");
    const len = input.length;
    const out = [];
    let i = 0;
    let skipTag = null;
    let skipDepth = 0;

    while (i < len) {
        const lt = input.indexOf("<", i);
        if (lt === -1) {
            if (!skipTag) {
                out.push(input.slice(i).replace(/>/g, "&gt;"));
            }
            break;
        }

        if (lt > i && !skipTag) {
            out.push(input.slice(i, lt).replace(/>/g, "&gt;"));
        }

        // Comments <!-- ... -->
        if (input.startsWith("<!--", lt)) {
            const endComment = input.indexOf("-->", lt + 4);
            i = endComment === -1 ? len : endComment + 3;
            continue;
        }

        // Declarations / CDATA / Processing Instructions (<!...> or <?...>)
        const nextChar = input[lt + 1] || "";
        if (nextChar === "!" || nextChar === "?") {
            if (input.slice(lt, lt + 9).toUpperCase() === "<![CDATA[") {
                const endCdata = input.indexOf("]]>", lt + 9);
                i = endCdata === -1 ? len : endCdata + 3;
            } else {
                const endDecl = input.indexOf(">", lt + 2);
                i = endDecl === -1 ? len : endDecl + 1;
            }
            continue;
        }

        // Closing vs opening tag check
        let pos = lt + 1;
        let isClosing = false;
        if (input[pos] === "/") {
            isClosing = true;
            pos++;
        }

        if (!/[a-zA-Z]/.test(input[pos] || "")) {
            // Stray '<' not starting a tag
            if (!skipTag) out.push("&lt;");
            i = lt + 1;
            continue;
        }

        const nameStart = pos;
        while (pos < len && /[a-zA-Z0-9:-]/.test(input[pos])) pos++;
        const tag = input.slice(nameStart, pos).toLowerCase();

        // While inside a rawtext stripped tag (<script>, <style>, etc.), only close on </tag>
        if (skipTag && RAW_TEXT_STRIP_TAGS.has(skipTag)) {
            if (isClosing && tag === skipTag) {
                const closeGt = input.indexOf(">", pos);
                i = closeGt === -1 ? len : closeGt + 1;
                skipTag = null;
                skipDepth = 0;
            } else {
                i = lt + 1;
            }
            continue;
        }

        // Scan until unquoted '>' to correctly handle '>' inside attribute quotes
        const attrStart = pos;
        let quote = null;
        let tagEnd = -1;
        while (pos < len) {
            const ch = input[pos];
            if (quote) {
                if (ch === quote) quote = null;
            } else {
                if (ch === '"' || ch === "'") {
                    quote = ch;
                } else if (ch === "<") {
                    // Malformed unclosed tag interrupted by a new '<'
                    break;
                } else if (ch === ">") {
                    tagEnd = pos;
                    break;
                }
            }
            pos++;
        }

        if (tagEnd === -1) {
            // Malformed/unclosed tag: discard cleanly (or advance past '<' if interrupted)
            i = pos < len && input[pos] === "<" ? pos : len;
            continue;
        }

        const attrStr = input.slice(attrStart, tagEnd);
        i = tagEnd + 1;

        if (skipTag) {
            if (tag === skipTag) {
                if (isClosing) {
                    skipDepth--;
                    if (skipDepth <= 0) {
                        skipTag = null;
                        skipDepth = 0;
                    }
                } else if (!/\/\s*$/.test(attrStr)) {
                    skipDepth++;
                }
            }
            continue;
        }

        if (!isClosing && STRIP_WITH_CONTENT_TAGS.has(tag)) {
            if (!/\/\s*$/.test(attrStr) || RAW_TEXT_STRIP_TAGS.has(tag)) {
                skipTag = tag;
                skipDepth = 1;
            }
            continue;
        }

        if (!ALLOWED_TAGS.has(tag)) {
            continue;
        }

        if (isClosing) {
            if (!VOID_TAGS.has(tag)) {
                out.push(`</${tag}>`);
            }
            continue;
        }

        if (VOID_TAGS.has(tag)) {
            out.push(`<${tag}>`);
            continue;
        }

        const attrs = parseAttributesFromSlice(attrStr);
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

        out.push(safeParts.length ? `<${tag} ${safeParts.join(" ")}>` : `<${tag}>`);
    }

    return out.join("").trim();
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
