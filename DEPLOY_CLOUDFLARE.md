# Deploying `editor.aabtak24.in` on Cloudflare Workers + D1 (Zero-Downtime Guide)

This guide walks you step-by-step through moving `aabtak24.in` DNS to Cloudflare (Free plan, **$0/month**) without interrupting the live news website (`https://aabtak24.in`), and deploying the new server-side CMS Worker + private Cloudflare D1 database on `https://editor.aabtak24.in`.

> **Good to know:** You do **not** transfer your domain registration or billing away from your current registrar (GoDaddy, Hostinger, Namecheap, BigRock, etc.). You only point your domain's **nameservers (DNS)** to Cloudflare's free DNS.

---

## Step 1: Transfer `aabtak24.in` DNS to Cloudflare (Zero Downtime)

1. Sign up or log in at [https://dash.cloudflare.com](https://dash.cloudflare.com).
2. Click **Add a domain**, enter `aabtak24.in`, and select the **Free ($0)** plan.
3. Cloudflare will automatically scan your existing DNS records. **Before changing nameservers**, double-check that every record below is present in Cloudflare's DNS table:

| Type | Name | Target / IPv4 Address | Proxy Status | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `A` | `@` (`aabtak24.in`) | `185.199.108.153` | **DNS only** (Grey Cloud) | GitHub Pages (`auto-news-bot`) |
| `A` | `@` (`aabtak24.in`) | `185.199.109.153` | **DNS only** (Grey Cloud) | GitHub Pages (`auto-news-bot`) |
| `A` | `@` (`aabtak24.in`) | `185.199.110.153` | **DNS only** (Grey Cloud) | GitHub Pages (`auto-news-bot`) |
| `A` | `@` (`aabtak24.in`) | `185.199.111.153` | **DNS only** (Grey Cloud) | GitHub Pages (`auto-news-bot`) |
| `CNAME` | `www` *(if used)* | `adityacoder1.github.io` | **DNS only** (Grey Cloud) | `www.aabtak24.in` redirect |
| `CNAME` | `editor` *(temporary)* | `adityacoder1.github.io` | **DNS only** (Grey Cloud) | Keeps old portal online until Step 5 |

   - **Why Grey Cloud ("DNS only") for `aabtak24.in`?** Keeping GitHub Pages on Grey Cloud lets GitHub Pages renew its Let's Encrypt HTTPS certificate automatically with zero downtime or TLS warnings.
   - **Check email & verification records:** If you have any `MX`, `TXT` (Google Search Console, AdSense, SPF/DKIM/DMARC), or other subdomain records at your current registrar, verify that Cloudflare imported all of them before proceeding.
4. In Cloudflare Dashboard → `aabtak24.in` → **SSL/TLS → Overview**, set encryption mode to **Full (strict)**. *(Never use "Flexible" with GitHub Pages—it causes redirect loops.)*
5. Copy the **2 Cloudflare Nameservers** shown by Cloudflare (for example, `xxxx.ns.cloudflare.com` and `yyyy.ns.cloudflare.com`).
6. Log in to your domain registrar (GoDaddy / Hostinger / Namecheap / BigRock / etc.) → open **DNS / Nameservers** for `aabtak24.in` → select **Custom Nameservers** → replace the old nameservers with Cloudflare's 2 nameservers → **Save**.
7. Wait 5–30 minutes until Cloudflare shows **`aabtak24.in` is Active** (you will also get an email).
8. Open `https://aabtak24.in` in your browser and confirm the live news site still loads over HTTPS with no errors.

---

## Step 2: Create a New Least-Privilege GitHub Token

Create a fresh GitHub Fine-Grained Personal Access Token that can **only** touch `auto-news-bot` (never exposed to browsers):

1. Go to GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
2. Token name: `aabtak24-cloudflare-worker`
3. Repository access: **Only select repositories** → choose **ONLY** `AdityaCODER1/auto-news-bot`.
4. Under **Repository permissions**, grant only:
   - **Contents**: `Read and write`
   - **Actions**: `Read and write`
   - Leave all other permissions as **No access**.
5. Click **Generate token** and copy the `github_pat_...` value to a temporary clipboard/password manager.
   *(Do **not** revoke your old token yet—wait until Step 6 after the new portal is live.)*

---

## Step 3: Create the Private Cloudflare D1 Database

On your computer (with Node.js 20+ installed), clone/pull `AdityaCODER1/aabtak24-admin` and run:

```bash
cd aabtak24-admin
npm install
npx wrangler login
npx wrangler d1 create aabtak24-cms
```

1. `npx wrangler login` opens your browser to authorize Wrangler with your Cloudflare account.
2. `npx wrangler d1 create aabtak24-cms` prints a snippet containing a `database_id` (a UUID like `12345678-abcd-4ef0-9876-abcdef123456`).
3. Open `wrangler.toml` and replace `REPLACE_WITH_YOUR_D1_DATABASE_ID` with your real `database_id`:

```toml
[[d1_databases]]
binding = "CMS_DB"
database_name = "aabtak24-cms"
database_id = "YOUR_ACTUAL_D1_DATABASE_ID"
```

> **Note:** No manual SQL migration is required. All D1 tables (`admin_config`, `editors`, `sessions`, `login_attempts`, `audit_logs`) are created automatically on the first request via `ensureSchema()`.

---

## Step 4: Set the 4 Encrypted Cloudflare Worker Secrets

First, generate two strong random secrets and **save both in your password manager**:

```bash
# 1. Server-side password pepper (64 hex chars).
# IMPORTANT: Save this securely and do NOT change it later, or existing password hashes will no longer match.
node -e "console.log('PASSWORD_PEPPER=' + require('crypto').randomBytes(32).toString('hex'))"

# 2. Main Admin Recovery Key (48 hex chars).
# Used on the login screen's "Forgot Main Admin Password" form if you ever lose your Admin password.
node -e "console.log('ADMIN_RECOVERY_KEY=' + require('crypto').randomBytes(24).toString('hex'))"
```

Now upload all 4 encrypted secrets to Cloudflare Workers (each command prompts securely for the secret value):

```bash
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put PASSWORD_PEPPER
npx wrangler secret put ADMIN_INITIAL_PASSWORD
npx wrangler secret put ADMIN_RECOVERY_KEY
```

| Secret Name | Minimum Rule | Purpose |
| :--- | :--- | :--- |
| `GITHUB_TOKEN` | Fine-grained PAT from Step 2 | Server-side GitHub API writes to `AdityaCODER1/auto-news-bot` (never leaves Cloudflare) |
| `PASSWORD_PEPPER` | ≥ 16 chars (use generated 64-hex string) | HMAC-SHA256 server pepper combined with salted PBKDF2-SHA256 |
| `ADMIN_INITIAL_PASSWORD` | ≥ 8 chars | Bootstraps your Main Admin password in D1 on your **very first** login |
| `ADMIN_RECOVERY_KEY` | ≥ 12 chars (use generated 48-hex string) | Server-verified key for the **Forgot Main Admin Password** recovery flow |

---

## Step 5: Deploy & Switch `editor.aabtak24.in` to Cloudflare Workers

1. In Cloudflare Dashboard → `aabtak24.in` → **DNS → Records**, **delete** the old temporary `editor` CNAME record pointing to `adityacoder1.github.io`.
   *(Cloudflare Workers Custom Domain will automatically create and manage the `editor.aabtak24.in` DNS record and HTTPS certificate.)*
2. Run the local security test suite and deploy:

```bash
npm test
npx wrangler deploy
```

3. In Cloudflare Dashboard → **Workers & Pages → `aabtak24-editor` → Settings → Domains & Routes**, confirm `editor.aabtak24.in` shows **Active** (typically 30–60 seconds).
4. Open `https://editor.aabtak24.in` in your browser and verify:
   - Leave **Username / Email** blank and log in using your `ADMIN_INITIAL_PASSWORD`.
   - Open DevTools → **Application**:
     - **Cookies**: `aabtak_session` is set with `HttpOnly`, `Secure`, and `SameSite=Strict`.
     - **Local Storage** & **Session Storage**: completely empty (zero secrets in browser storage).
   - Open **👥 संपादक एवं सुरक्षा (Editors)**:
     - Verify the **Server-Side Auth** card shows `Cloudflare Workers + Private D1`.
     - Verify the **Security Audit Log** records `login_success`.
     - *(Recommended)* Change your Main Admin password once inside this tab so your D1 record has a fresh password independent of `ADMIN_INITIAL_PASSWORD`.
     - Create your sub-editors (`own_only` or `all_articles`) with their email usernames and custom passwords.

---

## Step 6: Mandatory Post-Cutover Security Cleanup

Once `https://editor.aabtak24.in` is working smoothly on Cloudflare Workers:

1. **Disable GitHub Pages on `AdityaCODER1/aabtak24-admin`:**
   - GitHub → `AdityaCODER1/aabtak24-admin` → **Settings → Pages** → remove the custom domain `editor.aabtak24.in` and set **Build and deployment / Source** to **None** (or unpublish site).
2. **Revoke your old GitHub PAT:**
   - GitHub → **Settings → Developer settings → Personal access tokens** → revoke the old token that was previously embedded in the legacy static `index.html`.
3. **Strip legacy vault metadata from `auto-news-bot/site_config.json`:**
   - Click **Save** once on any site setting (e.g., Homepage/Header/Footer) in the new Admin portal—`PUT /api/config` automatically strips legacy `admin_lock` and `editors_vault` keys from `site_config.json`.
4. **Remove legacy root `index.html` and `CNAME` from `aabtak24-admin`:**
   - Once you no longer need the old GitHub Pages fallback, delete the root `index.html` and `CNAME` files from `AdityaCODER1/aabtak24-admin` (the live Worker serves from `./public/index.html`).
5. *(Optional)* **Enable Auto-Deploy on `git push` via GitHub Actions:**
   - Commit and push your updated `wrangler.toml` (with the real D1 `database_id`).
   - In Cloudflare Dashboard → **My Profile → API Tokens → Create Token** → use the **Edit Cloudflare Workers** template (include your account and `aabtak24.in` zone).
   - In GitHub → `AdityaCODER1/aabtak24-admin` → **Settings → Secrets and variables → Actions**, add:
     - `CLOUDFLARE_API_TOKEN`
     - `CLOUDFLARE_ACCOUNT_ID`
   - Future pushes to `main` touching `src/**`, `public/**`, `wrangler.toml`, or `package.json` will automatically run `npm test` and deploy via `.github/workflows/deploy-worker.yml`.
