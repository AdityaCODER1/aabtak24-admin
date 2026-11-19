/**
 * Server-side GitHub REST API client.
 * Uses ONLY env.GITHUB_TOKEN (Cloudflare encrypted Worker secret).
 * The token never leaves this Worker and is never exposed to browsers.
 */

import { base64ToUtf8, utf8ToBase64 } from "./sanitize.js";

function getRepoConfig(env) {
    const repo = String(env.GITHUB_REPO || "AdityaCODER1/auto-news-bot").trim();
    const branch = String(env.GITHUB_BRANCH || "main").trim();
    const token = String(env.GITHUB_TOKEN || "").trim();
    if (!token) {
        throw new Error("Server secret GITHUB_TOKEN is not configured in Cloudflare Workers.");
    }
    return { repo, branch, token };
}

export async function ghRequest(env, endpoint, options = {}) {
    const { repo, token } = getRepoConfig(env);
    const res = await fetch(`https://api.github.com/repos/${repo}${endpoint}`, {
        ...options,
        headers: {
            "Authorization": `Bearer ${token}`,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Aabtak24-Editor-Worker/2.0",
            ...(options.body ? { "Content-Type": "application/json" } : {}),
            ...(options.headers || {})
        }
    });

    if (!res.ok) {
        let errMsg = `GitHub API Error (${res.status})`;
        try {
            const errJson = await res.json();
            if (errJson && errJson.message) errMsg += `: ${errJson.message}`;
        } catch (_) {}
        const err = new Error(errMsg);
        err.status = res.status;
        throw err;
    }

    if (res.status === 204) return null;
    return res.json();
}

export async function ghGetFile(env, path) {
    const { branch } = getRepoConfig(env);
    try {
        const data = await ghRequest(env, `/contents/${path}?ref=${encodeURIComponent(branch)}&t=${Date.now()}`);
        return {
            content: base64ToUtf8(data.content),
            sha: data.sha
        };
    } catch (e) {
        if (e && e.status === 404) return null;
        throw e;
    }
}

export async function ghPutFile(env, path, utf8Text, message, sha = null) {
    const { branch } = getRepoConfig(env);
    const body = {
        message,
        content: utf8ToBase64(utf8Text),
        branch
    };
    if (sha) body.sha = sha;
    return ghRequest(env, `/contents/${path}`, {
        method: "PUT",
        body: JSON.stringify(body)
    });
}

export async function ghPutBinaryFile(env, path, base64Content, message) {
    const { branch } = getRepoConfig(env);
    return ghRequest(env, `/contents/${path}`, {
        method: "PUT",
        body: JSON.stringify({
            message,
            content: base64Content,
            branch
        })
    });
}

export async function ghDeleteFile(env, path, message, sha) {
    const { branch } = getRepoConfig(env);
    return ghRequest(env, `/contents/${path}`, {
        method: "DELETE",
        body: JSON.stringify({
            message,
            sha,
            branch
        })
    });
}

export async function triggerRebuild(env) {
    const { branch } = getRepoConfig(env);
    await ghRequest(env, `/actions/workflows/schedule.yml/dispatches`, {
        method: "POST",
        body: JSON.stringify({
            ref: branch,
            inputs: { mode: "rebuild" }
        })
    });
}

/**
 * Reads a JSON file from GitHub, applies mutator(parsedData), and writes it back.
 * Automatically retries once on 409 SHA conflict (e.g. concurrent cron bot update).
 */
export async function mutateJsonFileWithRetry(env, path, defaultValue, mutator, commitMessage) {
    for (let attempt = 0; attempt < 2; attempt++) {
        const file = await ghGetFile(env, path);
        const currentData = file && file.content ? JSON.parse(file.content) : structuredClone(defaultValue);
        const result = await mutator(currentData);
        const nextData = result && Object.prototype.hasOwnProperty.call(result, "nextData") ? result.nextData : result;
        const msg = typeof commitMessage === "function" ? commitMessage(result) : commitMessage;

        try {
            const putRes = await ghPutFile(
                env,
                path,
                JSON.stringify(nextData, null, 2),
                msg,
                file ? file.sha : null
            );
            return { data: nextData, meta: result, sha: putRes?.content?.sha || null };
        } catch (err) {
            if (err && err.status === 409 && attempt === 0) {
                continue;
            }
            throw err;
        }
    }
}
