/**
 * Hardened image upload endpoint:
 *  - POST /api/uploads
 * Enforces:
 *  1. Authenticated session + Origin + CSRF check
 *  2. Maximum 5 MB binary size
 *  3. Exact binary magic-byte inspection (JPEG, PNG, WebP ONLY — rejects SVG/HTML/JS/spoofed files)
 *  4. Server-generated safe filename (never trusts user-supplied filename or extension)
 */

import { authenticateRequest, getClientIp, randomHex, verifyOriginAndCsrf } from "../auth.js";
import { writeAuditLog } from "../db.js";
import { ghPutBinaryFile } from "../github.js";
import { errorResponse, jsonResponse } from "../http.js";
import { bytesToBase64, cleanSlug, verifyImageMagicBytes } from "../sanitize.js";

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_MULTIPART_BODY_BYTES = MAX_UPLOAD_BYTES + 256 * 1024; // 5 MB image + multipart overhead

async function readBoundedMultipart(request, rawContentType, maxBytes) {
    const clHeader = request.headers.get("Content-Length");
    if (clHeader !== null) {
        const declared = Number(clHeader);
        if (Number.isFinite(declared) && declared > maxBytes) {
            const err = new Error("⚠️ फ़ोटो का आकार 5 MB से अधिक नहीं हो सकता।");
            err.status = 413;
            throw err;
        }
    }

    if (!request.body || typeof request.body.getReader !== "function") {
        return request.formData();
    }

    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
            total += value.byteLength;
            if (total > maxBytes) {
                try { await reader.cancel(); } catch (_) {}
                const err = new Error("⚠️ फ़ोटो का आकार 5 MB से अधिक नहीं हो सकता।");
                err.status = 413;
                throw err;
            }
            chunks.push(value);
        }
    }

    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.byteLength;
    }

    return new Response(merged, {
        headers: { "Content-Type": rawContentType }
    }).formData();
}

export async function handleUploadRoutes(request, env, pathname) {
    if (pathname !== "/api/uploads" || request.method.toUpperCase() !== "POST") {
        return errorResponse("Not Found", 404);
    }

    const session = await authenticateRequest(request, env);
    if (!session) {
        return errorResponse("सत्र समाप्त हो गया है। कृपया पुनः लॉगिन करें।", 401);
    }

    const csrfCheck = await verifyOriginAndCsrf(request, env, session);
    if (!csrfCheck.ok) {
        return errorResponse(csrfCheck.error, 403);
    }

    const rawContentType = String(request.headers.get("Content-Type") || "");
    const contentType = rawContentType.toLowerCase();
    if (!contentType.includes("multipart/form-data")) {
        return errorResponse("Uploads must use multipart/form-data.", 415);
    }

    let formData;
    try {
        formData = await readBoundedMultipart(request, rawContentType, MAX_MULTIPART_BODY_BYTES);
    } catch (err) {
        if (err && err.status === 413) {
            return errorResponse(err.message, 413);
        }
        return errorResponse("Invalid multipart form data.", 400);
    }

    const file = formData.get("file");
    if (!file || typeof file.arrayBuffer !== "function") {
        return errorResponse("कृपया अपलोड करने के लिए एक छवि फ़ाइल चुनें।", 400);
    }

    if (typeof file.size === "number" && file.size > MAX_UPLOAD_BYTES) {
        return errorResponse("⚠️ फ़ोटो का आकार 5 MB से अधिक नहीं हो सकता।", 413);
    }

    const arrayBuf = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuf);
    if (bytes.length === 0) {
        return errorResponse("खाली फ़ाइल अपलोड नहीं की जा सकती।", 400);
    }
    if (bytes.length > MAX_UPLOAD_BYTES) {
        return errorResponse("⚠️ फ़ोटो का आकार 5 MB से अधिक नहीं हो सकता।", 413);
    }

    const magic = verifyImageMagicBytes(bytes);
    if (!magic.valid) {
        return errorResponse(`⚠️ अमान्य छवि फ़ाइल! केवल असली JPEG, PNG या WebP फ़ोटो ही अपलोड की जा सकती हैं।`, 415);
    }

    const rawSlugHint = cleanSlug(String(formData.get("slug") || "")) || "img";
    const safePrefix = rawSlugHint.slice(0, 60);
    const imgPath = `uploads/${safePrefix}-${Math.floor(Date.now() / 1000)}-${randomHex(3)}.${magic.ext}`;

    const b64 = bytesToBase64(bytes);
    await ghPutBinaryFile(env, imgPath, b64, `Upload image ${imgPath} by ${session.username}`);

    await writeAuditLog(env.CMS_DB, {
        role: session.role,
        username: session.username,
        action: "image_uploaded",
        target: imgPath,
        details: `${magic.mime} (${bytes.length} bytes)`,
        ip: getClientIp(request)
    });

    return jsonResponse({ ok: true, path: imgPath, mime: magic.mime, size: bytes.length }, 201);
}
