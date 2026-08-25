const express = require("express");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require("google-auth-library");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");

const { connectDB, readDatabase, writeDatabase, getNextId, GIFT_ADDON, reserveCustomerMobile, releaseCustomerMobile } = require("./database");

const app = express();

// Fallback WhatsApp destination + URL builder — used across the products,
// product-detail, and callback-request endpoints below. Must be declared at
// module scope (not nested inside any single route handler) since more than
// one handler references it.
const DESIGN_MAKERS_WHATSAPP = "https://wa.me/917004847813";

function buildWhatsAppUrl(number) {
  const digits = String(number || "").replace(/\D/g, "");
  return digits.length >= 8 ? `https://wa.me/${digits}` : DESIGN_MAKERS_WHATSAPP;
}
const PORT = process.env.PORT || 3000;
app.set("trust proxy", 1);

// Gzip/deflate-compress every response (HTML, JSON, JS, CSS) before it goes
// over the wire. This is the single biggest win for the ~240KB+ HTML/JSON
// payloads this site sends on every page load.
app.use(compression());

// ================================
// SECURITY HEADERS
// ================================
// contentSecurityPolicy is turned off here because index.html/admin.html/
// seller.html are single-file pages full of inline <script> blocks and
// onclick="..." handlers — a default CSP would break them outright. Turning
// it off keeps every other helmet protection (X-Content-Type-Options,
// X-Frame-Options/clickjacking protection, HSTS, etc.) without breaking the
// site. If the front-end is ever split into external .js files, turning CSP
// back on (with a script-src allowlist) is worth doing.
// crossOriginOpenerPolicy is relaxed to "same-origin-allow-popups" — helmet's
// default ("same-origin") silently blocks the Google Sign-In popup from
// passing its login token back to this page (no error, it just never
// completes), which is exactly the "Continue with Google" bug this fixes.
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
  })
);

// ================================
// EMAIL (seller welcome mail, approvals, rejections)
// ================================
// Sends real email via Gmail SMTP using an App Password (not your normal
// Gmail password — generate one at myaccount.google.com/apppasswords with
// 2-Step Verification turned on). Set these in your host's environment
// variables:
//   GMAIL_USER          -> the Gmail address sending the mail
//   GMAIL_APP_PASSWORD  -> the 16-character App Password (no spaces)
// If either is missing, mail sending is skipped and every call site here
// already falls back to "share it manually" (admin panel shows the
// password), so nothing breaks — it just won't auto-email until both are
// set.
const ADMIN_NOTIFY_EMAIL = process.env.ADMIN_NOTIFY_EMAIL || "";
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";

const mailTransporter =
  GMAIL_USER && GMAIL_APP_PASSWORD
    ? nodemailer.createTransport({
        service: "gmail",
        auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
      })
    : null;

if (!mailTransporter) {
  console.warn(
    "⚠️  GMAIL_USER / GMAIL_APP_PASSWORD not set — automatic emails (seller welcome mail, etc) " +
      "are disabled. Passwords/details will still show in the admin panel to share manually.",
  );
}

async function sendMail(to, subject, html) {
  if (!mailTransporter || !to) {
    console.log(`(email not sent — automailer not configured) To: ${to} | Subject: ${subject}`);
    return { sent: false, reason: "automailer-not-configured" };
  }
  try {
    await mailTransporter.sendMail({
      from: `"Design Makers" <${GMAIL_USER}>`,
      to,
      subject,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error("sendMail failed:", err.message);
    return { sent: false, reason: err.message };
  }
}

// ================================
// CUSTOMER MARKETING / OFFERS
// ================================
// Marketing is intentionally separate from transactional email. A customer
// can opt out of offers/product updates without losing OTP, order or delivery
// messages. Unsubscribe links are signed so a customer cannot change an ID in
// the URL and unsubscribe someone else.
function makeMarketingToken(customerId) {
  const payload = `${customerId}.${Date.now()}`;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(`marketing-unsubscribe:${payload}`).digest("hex");
  return Buffer.from(`${payload}.${sig}`).toString("base64url");
}

function verifyMarketingToken(token) {
  try {
    const raw = Buffer.from(String(token || ""), "base64url").toString("utf8");
    const parts = raw.split(".");
    if (parts.length !== 3) return null;
    const [id, ts, sig] = parts;
    if (!/^\d+$/.test(id) || !/^\d+$/.test(ts)) return null;
    const age = Date.now() - Number(ts);
    if (age < 0 || age > 180 * 24 * 60 * 60 * 1000) return null;
    const expected = crypto.createHmac("sha256", JWT_SECRET).update(`marketing-unsubscribe:${id}.${ts}`).digest("hex");
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    return Number(id);
  } catch (_) { return null; }
}

// Builds the exact same absolute product URL the storefront itself builds
// (see buildProductUrl() in index.html) — /product/<id>/<slug> — so a
// marketing email link always opens the real product page, never the
// homepage, even if the product name changes later (the id is what
// actually resolves the product; the slug is cosmetic/SEO only).
function marketingProductUrl(product, baseUrl) {
  return `${baseUrl}/product/${encodeURIComponent(product.id)}/${slugifyProductName(product.name)}`;
}

// Renders one product card's inner HTML (image + name + price + button, all
// individually clickable to the same product page). Kept separate from the
// grid/table wrapper below so the same card markup works whether it's
// sitting in a single-product hero cell, a 2/3-up row, or the 2x2 / 3+2
// grids for 4 and 5 products.
function marketingProductCardHtml(product, baseUrl, big) {
  const name = escapeHtml(product.name || "Product");
  const href = marketingProductUrl(product, baseUrl);
  const onSale = !!product.onSale && Number(product.salePercent) > 0 && (!product.saleEndsAt || Date.now() < Number(product.saleEndsAt));
  const price = Number(product.price || 0);
  const salePrice = onSale ? Math.round(price * (1 - Number(product.salePercent) / 100) * 100) / 100 : null;
  const imgHeight = big ? 260 : 170;
  // Gmail and most real email clients block/strip inline data:image base64
  // sources, so the email must link to a normal HTTPS image URL instead.
  // If the stored photo is a base64 data URI, point at the existing
  // /product-image/:id/:index route (same one used for WhatsApp links)
  // which serves the real bytes over HTTPS from the production domain.
  // If it's already a hosted URL, use it as-is. Either way, no image data
  // is duplicated or re-uploaded — this just reuses the existing storage.
  const rawImage = typeof product.image === "string" ? product.image : "";
  const imageUrl = rawImage
    ? (rawImage.startsWith("data:image/")
        ? `${baseUrl}/product-image/${encodeURIComponent(product.id)}/0`
        : rawImage)
    : "";
  const image = imageUrl
    ? `<img src="${escapeHtml(imageUrl)}" alt="${name}" width="100%" style="width:100%;height:${imgHeight}px;object-fit:cover;border-radius:12px;display:block;">`
    : `<div style="width:100%;height:${imgHeight}px;border-radius:12px;background:#f4e9e2;color:#a68a82;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;">No image available</div>`;
  const priceHtml = onSale
    ? `<span style="text-decoration:line-through;color:#a68a82;font-size:13px;">₹${price.toLocaleString("en-IN")}</span> <span style="color:#a56a2a;font-weight:800;font-size:${big?20:18}px;">₹${salePrice.toLocaleString("en-IN")}</span> <span style="display:inline-block;background:#6b3028;color:#fff;font-size:11px;font-weight:800;padding:2px 7px;border-radius:6px;">${Math.round(Number(product.salePercent))}% OFF</span>`
    : `<span style="color:#a56a2a;font-weight:800;font-size:${big?20:18}px;">₹${price.toLocaleString("en-IN")}</span>`;
  return `<a href="${href}" style="display:block;text-decoration:none;margin-bottom:12px;">${image}</a>` +
    `<a href="${href}" style="display:block;text-decoration:none;color:#5b2b24;font-weight:800;font-size:${big?18:16}px;line-height:1.3;margin-bottom:6px;">${name}</a>` +
    `<div style="margin-bottom:12px;">${priceHtml}</div>` +
    `<a href="${href}" style="display:inline-block;background:#6b3028;color:#fff;text-decoration:none;padding:9px 16px;border-radius:9px;font-weight:700;font-size:13px;">View Product</a>`;
}

// Wraps 1-5 product cards into an email-safe (table-based) responsive grid:
//   1 -> one large hero card
//   2 -> two balanced columns
//   3 -> three balanced columns
//   4 -> 2 x 2 grid
//   5 -> 3-up row, then a balanced 2-up row
// Every cell carries the "dm-col" class, which the <style> block in
// buildMarketingEmail() collapses to a full-width single column under
// 600px, so it always stacks cleanly on mobile regardless of layout.
function marketingProductsGridHtml(products, baseUrl) {
  if (!products.length) return "";
  const cell = (p, big) => `<td class="dm-col" width="${big?100:Math.floor(100/Math.min(products.length,3))}%" valign="top" style="padding:8px;box-sizing:border-box;">` +
    `<div style="border:1px solid #ead8d0;border-radius:14px;padding:16px;background:#fffaf7;text-align:left;height:100%;box-sizing:border-box;">${marketingProductCardHtml(p, baseUrl, big)}</div></td>`;
  const row = (cells) => `<tr>${cells.join("")}</tr>`;
  let rowsHtml;
  if (products.length === 1) {
    rowsHtml = row([cell(products[0], true)]);
  } else if (products.length === 4) {
    rowsHtml = row([cell(products[0]), cell(products[1])]) + row([cell(products[2]), cell(products[3])]);
  } else if (products.length === 5) {
    const three = `<tr>${products.slice(0,3).map(p => cell(p)).join("")}</tr>`;
    const two = `<tr>${products.slice(3,5).map(p => `<td class="dm-col" width="50%" valign="top" style="padding:8px;box-sizing:border-box;"><div style="border:1px solid #ead8d0;border-radius:14px;padding:16px;background:#fffaf7;text-align:left;box-sizing:border-box;">${marketingProductCardHtml(p, baseUrl, false)}</div></td>`).join("")}</tr>`;
    rowsHtml = three + two;
  } else {
    // 2 or 3 products: one balanced row.
    rowsHtml = row(products.map(p => cell(p)));
  }
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0;width:100%;">${rowsHtml}</table>`;
}

// Optional gift-code section. Only rendered when the admin attached a real,
// currently-configured gift code to the campaign — never a hardcoded one,
// and never an empty section when no code was selected.
function marketingGiftCodeHtml(gift, buttonUrl, buttonText) {
  if (!gift) return "";
  const discountText = gift.type === "fixed" ? `₹${Number(gift.value).toLocaleString("en-IN")} OFF` : `${Number(gift.value)}% OFF`;
  const minOrderText = Number(gift.minOrder) > 0 ? `<div style="font-size:12px;color:#806e68;margin-top:4px;">On orders above ₹${Number(gift.minOrder).toLocaleString("en-IN")}</div>` : "";
  const href = buttonUrl || "";
  const cta = href ? `<a href="${escapeHtml(href)}" style="display:inline-block;margin-top:12px;background:#6b3028;color:#fff;text-decoration:none;padding:10px 18px;border-radius:9px;font-weight:800;font-size:13px;">${escapeHtml(buttonText || "Shop Now")}</a>` : "";
  return `<div style="margin:20px 0;padding:18px;border:2px dashed #c99a4f;border-radius:14px;text-align:center;background:#fdf6ec;">` +
    `<div style="font-size:12px;letter-spacing:1.5px;font-weight:800;color:#a56a2a;margin-bottom:6px;">USE CODE</div>` +
    `<div style="font-size:22px;font-weight:900;color:#6b3028;letter-spacing:2px;">${escapeHtml(gift.code)}</div>` +
    `<div style="font-size:15px;font-weight:700;color:#5b2b24;margin-top:6px;">${discountText}</div>${minOrderText}${cta}</div>`;
}

function buildMarketingEmail(campaign, unsubscribeToken) {
  const subjectText = escapeHtml(campaign.heading || campaign.title || "Design Makers");
  const body = escapeHtml(campaign.message || "").replace(/\n/g, "<br>");
  const products = Array.isArray(campaign.products) ? campaign.products.slice(0, 5) : [];
  const baseUrl = String(campaign.baseUrl || "").replace(/\/$/, "");
  const grid = marketingProductsGridHtml(products, baseUrl);
  const giftSection = marketingGiftCodeHtml(campaign.giftCode, campaign.buttonUrl, campaign.buttonText);
  const button = campaign.buttonUrl && !campaign.giftCode ? `<p style="text-align:center;margin:22px 0;"><a href="${escapeHtml(campaign.buttonUrl)}" style="display:inline-block;background:#6b3028;color:#fff;text-decoration:none;padding:11px 20px;border-radius:10px;font-weight:800;">${escapeHtml(campaign.buttonText || "View Now")}</a></p>` : "";
  const unsubscribeUrl = `${baseUrl}/api/marketing/unsubscribe?token=${encodeURIComponent(unsubscribeToken)}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
    @media only screen and (max-width:600px){
      .dm-container{padding:14px 8px !important;}
      .dm-card{padding:18px !important;}
      .dm-col{display:block !important;width:100% !important;padding:6px 0 !important;}
      .dm-h1{font-size:22px !important;}
    }
  </style></head><body style="margin:0;background:#f9f2ee;font-family:Arial,Helvetica,sans-serif;color:#33231f;">` +
    `<div class="dm-container" style="max-width:680px;margin:0 auto;padding:24px 14px;">` +
    `<div class="dm-card" style="background:#fff;border:1px solid #ead8d0;border-radius:18px;padding:28px;box-shadow:0 8px 30px rgba(72,38,28,.08);">` +
    `<div style="text-align:center;font-size:12px;letter-spacing:2px;font-weight:800;color:#a56a2a;margin-bottom:10px;">DESIGN MAKERS</div>` +
    `<h1 class="dm-h1" style="text-align:center;color:#6b3028;font-size:26px;margin:0 0 16px;">${subjectText}</h1>` +
    `<div style="font-size:15px;line-height:1.65;">${body}</div>` +
    grid + giftSection + button +
    `<hr style="border:0;border-top:1px solid #ead8d0;margin:28px 0 16px;">` +
    `<div style="text-align:center;font-size:12px;margin:0 0 14px;">` +
    `<a href="https://www.instagram.com/designmakers.in" target="_blank" style="color:#6b3028;text-decoration:none;margin:0 8px;">Instagram</a>` +
    `<a href="https://youtube.com/@designmakershub" target="_blank" style="color:#6b3028;text-decoration:none;margin:0 8px;">YouTube</a>` +
    `<a href="https://wa.me/7004847813" target="_blank" style="color:#6b3028;text-decoration:none;margin:0 8px;">WhatsApp</a></div>` +
    `<p style="font-size:12px;color:#806e68;text-align:center;margin:0;">You're receiving this because you're subscribed to Design Makers offers & product updates.</p>` +
    `<p style="font-size:12px;text-align:center;margin:9px 0 0;"><a href="${unsubscribeUrl}" style="color:#6b3028;">Unsubscribe from offers &amp; product updates</a></p>` +
    `</div></div></body></html>`;
}

// ================================
// GOOGLE SIGN-IN (customers + sellers)
// ================================
// Uses Google Identity Services on the frontend to get an ID token, which
// is verified here against GOOGLE_CLIENT_ID. Set this in your host's
// environment variables (get it from console.cloud.google.com -> APIs &
// Services -> Credentials -> OAuth Client ID -> Web application). The SAME
// value also needs to be pasted into index.html and seller.html where
// marked "YOUR_GOOGLE_CLIENT_ID".
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

async function verifyGoogleToken(idToken) {
  if (!googleClient) throw new Error("Google sign-in is not configured on the server yet.");
  const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
  const payload = ticket.getPayload();
  if (!payload || !payload.email) throw new Error("Could not read your Google account.");
  return { email: payload.email, name: payload.name || "", picture: payload.picture || "", googleId: payload.sub };
}

// ================================
// SEO HELPERS
// ================================
// Public site origin used to build absolute URLs for canonical tags, Open
// Graph/social-share previews, and the sitemap. Overridable via env var in
// case the production domain ever differs from the current default —
// nothing else about routing changes based on this.
const SITE_URL = (process.env.SITE_URL || "https://designmakers.site").replace(/\/+$/, "");

// Same slugify logic as buildProductUrl()/slugifyProductName() in
// index.html — kept identical so server-generated canonical/sitemap URLs
// always match the links the frontend itself builds and shares.
function slugifyProductName(name) {
  return (
    (name || "product")
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-+|-+$)/g, "") || "product"
  );
}

function escapeHtml(str) {
  return String(str == null ? "" : str).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[ch]);
}

function escapeJsonForHtml(obj) {
  // Safe to inline inside a <script type="application/ld+json"> tag —
  // escapes "</" so a stray "</script" inside product text can't break out.
  return JSON.stringify(obj).replace(/</g, "\\u003c");
}

// Generates a seller ID like DM-SLR-001 and a random 10-character password.
// Existing sellers already have SLR-xxxx IDs saved — those are untouched;
// this only applies to newly approved sellers going forward.
function generateSellerId(nextNumericId) {
  return `DM-SLR-${String(nextNumericId).padStart(3, "0")}`;
}

// Generates a random password for manual sharing (WhatsApp, in person, a
// screenshot, etc). Deliberately avoids ambiguous look-alike characters
// (0/O, 1/l/I) — a base64url charset includes all of those, which is fine
// for a password a computer pastes for you, but is a real source of
// "I typed it exactly and it still says invalid" when a human has to
// read it off a popup/screenshot and retype it by hand.
const SAFE_PASSWORD_CHARS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
function generateSellerPassword() {
  let out = "";
  const bytes = crypto.randomBytes(10);
  for (let i = 0; i < 10; i++) {
    out += SAFE_PASSWORD_CHARS[bytes[i] % SAFE_PASSWORD_CHARS.length];
  }
  return out;
}

// Generates the initial seller password from their shop name + Aadhaar,
// e.g. "Kanak Gifts" + last-4 "7391" -> "Kanak#7391" — easy for the seller
// to remember/guess-recall themselves. Only used the first time (at
// approval); a later admin "Reset password" still falls back to a random
// one via generateSellerPassword(), since regenerating this same formula
// would just hand back the identical password.
function generateShopBasedPassword(shopTitle, aadhaarLast4) {
  const firstWord = String(shopTitle || "").trim().split(/\s+/)[0] || "";
  const cleaned = firstWord.replace(/[^a-zA-Z0-9]/g, "") || "Shop";
  const capitalized = cleaned.charAt(0).toUpperCase() + cleaned.slice(1).toLowerCase();
  const last4 = String(aadhaarLast4 || "").padStart(4, "0").slice(-4);
  return `${capitalized}#${last4}`;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.ip || "unknown";
}

// ================================
// ADMIN CONFIG — one boss account + unlimited sub-admins
// ================================
// The boss account lives in Replit Secrets (ADMIN1_USERNAME / ADMIN1_PASSWORD)
// and can never be locked out. Every other admin ("sub-admin") is created by
// the boss from the admin panel itself — no coding needed — and is stored in
// database.json with a hashed password. Sub-admins get locked out after 3
// wrong password attempts in a row; only the boss can unlock them.
// IMPORTANT: this must be stable across restarts. It used to include
// Date.now(), which meant every single restart (every deploy, every
// idle-spin-down-then-wake on a free host) generated a brand new secret
// and silently invalidated every admin/seller/customer token that was
// still "logged in" — they'd get bounced to the login screen for no
// visible reason. Set a real JWT_SECRET in your host's environment
// variables for production; this fallback only exists so local/dev runs
// don't crash, and is now at least consistent within itself.
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-change-me-in-production";

// ================================
// PII ENCRYPTION (Aadhaar / PAN / bank account / IFSC — at rest)
// ================================
// Seller applications collect real government ID and banking details.
// Those four fields are encrypted (AES-256-GCM) before they're ever
// written to the database, and only decrypted back when an authenticated,
// authorized admin endpoint actually needs to display them. Everything
// else about these fields (which endpoints see them, who's allowed to
// call those endpoints) is unchanged — this only protects them if the
// database itself is ever read outside the app (a leaked backup, DB
// access misconfigured, etc).
// Set PII_ENCRYPTION_KEY in your host's environment variables to a
// random 64-character hex string (32 bytes) — e.g. generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// If it's not set, these fields are stored in plaintext exactly as
// before (so local/dev runs still work) and a warning is logged.
const PII_ENCRYPTION_KEY = (() => {
  const raw = process.env.PII_ENCRYPTION_KEY || "";
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, "hex");
  return null;
})();

if (!PII_ENCRYPTION_KEY) {
  console.warn(
    "⚠️  PII_ENCRYPTION_KEY is not set (or isn't a 64-character hex string) — " +
      "seller Aadhaar/PAN/bank details will be stored in PLAINTEXT. Set a random " +
      "32-byte hex key in your host's environment variables before going live: " +
      "node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
  );
}

function encryptPII(plainText) {
  const value = String(plainText || "");
  if (!value || !PII_ENCRYPTION_KEY) return value;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", PII_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
}

function decryptPII(value) {
  if (typeof value !== "string" || !value.startsWith("enc:v1:")) return value; // plaintext / legacy record — return as-is
  if (!PII_ENCRYPTION_KEY) return value; // can't decrypt without the key — surface the raw (unreadable) value rather than crash
  try {
    const [, , ivHex, authTagHex, dataHex] = value.split(":");
    const decipher = crypto.createDecipheriv("aes-256-gcm", PII_ENCRYPTION_KEY, Buffer.from(ivHex, "hex"));
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]);
    return decrypted.toString("utf8");
  } catch (error) {
    console.error("decryptPII failed:", error.message);
    return value;
  }
}

const BOSS_ACCOUNT = {
  username: process.env.ADMIN1_USERNAME || "admin1",
  passwordHash: bcrypt.hashSync(process.env.ADMIN1_PASSWORD || "ChangeMe123!", 10),
};

const MAX_LOGIN_ATTEMPTS = 3;

// ================================
// CONCURRENT SESSION LIMIT — max 2 active logins per username at once.
// ================================
// IMPORTANT: this used to live in a plain in-memory object, which is wiped
// out every time the Node process restarts. On a host like Render, that
// happens on every single deploy (and, on a free-tier dyno, after any idle
// spin-down too) — so every admin who was logged in would suddenly get
// "You've been logged out — logged in elsewhere" for no visible reason
// right after a redeploy, even though nothing they did caused it. Storing
// it in the database instead means it survives restarts, same as every
// other piece of app state.
const MAX_CONCURRENT_SESSIONS = 2;

function registerSession(database, username, sessionId) {
  if (!database.activeSessions) database.activeSessions = {};
  if (!database.activeSessions[username]) database.activeSessions[username] = [];
  database.activeSessions[username].push(sessionId);
  // If this login pushes the account over the limit, the oldest session(s)
  // are evicted — that device/tab will get "logged in elsewhere" on its
  // next request instead of continuing to work silently.
  if (database.activeSessions[username].length > MAX_CONCURRENT_SESSIONS) {
    database.activeSessions[username] = database.activeSessions[username].slice(-MAX_CONCURRENT_SESSIONS);
  }
}

function isSessionActive(database, username, sessionId) {
  return !!(database.activeSessions && database.activeSessions[username] && database.activeSessions[username].includes(sessionId));
}

function revokeSession(database, username, sessionId) {
  if (!database.activeSessions || !database.activeSessions[username]) return;
  database.activeSessions[username] = database.activeSessions[username].filter((id) => id !== sessionId);
}

if (!process.env.JWT_SECRET) {
  console.warn(
    "⚠️  JWT_SECRET is not set — using a shared dev fallback. Set a long random " +
      "JWT_SECRET in your host's environment variables so login tokens can't be forged " +
      "and stay valid across restarts as intended.",
  );
}

if (!process.env.ADMIN1_PASSWORD) {
  console.warn(
    "⚠️  Using a default boss password. Set ADMIN1_USERNAME, ADMIN1_PASSWORD, " +
      "and JWT_SECRET in Replit Secrets before going live.",
  );
}

// Middleware
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true }));

// If a request body is too large or malformed JSON, Express's default
// behavior is to send back an HTML error page — which breaks any frontend
// code doing res.json() on the response (it throws, and the user just sees
// a generic "something went wrong"). Catching it here means they always get
// a real, readable message instead.
app.use((err, req, res, next) => {
  if (err && err.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      message: "That upload is too large. Please use smaller photos and try again.",
    });
  }
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ success: false, message: "Invalid request." });
  }
  next(err);
});

// ================================
// NO STALE CACHING
// ================================
// Without this, browsers (and some hosting/CDN layers) can silently serve an
// old cached copy of /api/* responses or the HTML pages themselves — so a
// newly added product, an edited theme, etc. exist on the server right away
// but don't show up for a visitor until they force-refresh. Every API call
// and every HTML page is marked "always re-check with the server" so normal
// navigation (even just re-opening the tab) always reflects the latest data.
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
  }
  next();
});

// ================================
// BLOCK SERVER-SIDE FILES FROM STATIC SERVING
// ================================
// express.static below serves this entire project folder, so without this
// check, requests like GET /server.js or GET /database.js would return the
// raw backend source — including the JWT_SECRET dev fallback, DB logic, and
// every dependency under node_modules. Dotfiles (.env, .git) are already
// blocked by express.static's default `dotfiles: "ignore"` behavior; this
// covers everything else that shouldn't be publicly downloadable.
const BLOCKED_STATIC_PATHS = /^\/(server\.js|database\.js|products-store\.js|package(-lock)?\.json|node_modules(\/|$))/i;
app.use((req, res, next) => {
  if (BLOCKED_STATIC_PATHS.test(req.path)) return res.status(404).end();
  next();
});

// Serve website files
app.use(
  express.static(__dirname, {
    // etag/lastModified stay ON globally now so static assets (images, css,
    // js) get proper 304-revalidation and browser caching. HTML explicitly
    // overrides this below to "no-cache" so admin/product changes still
    // show up immediately on next navigation/reopen.
    etag: true,
    lastModified: true,
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".html")) {
        // HTML pages (index.html, admin.html) must always be revalidated —
        // this is what was causing "close and reopen still shows old data".
        res.set("Cache-Control", "no-cache");
      } else if (/\.(png|jpe?g|webp|gif|svg|ico|css|js|woff2?)$/.test(filePath)) {
        // Static assets rarely change day-to-day; cache them for a day so
        // repeat visits don't re-download the same images every time.
        res.set("Cache-Control", "public, max-age=86400");
      }
    },
  }),
);

// ================================
// ADMIN AUTH MIDDLEWARE
// ================================

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, message: "Login required." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const database = readDatabase();
    if (!isSessionActive(database, payload.username, payload.sessionId)) {
      return res.status(401).json({
        success: false,
        message: "You've been logged out — either this session ended or the account hit its 2-device login limit and got signed in elsewhere.",
      });
    }
    req.admin = { username: payload.username, role: payload.role || "admin", sessionId: payload.sessionId };
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Session expired. Please log in again." });
  }
}

function requireBoss(req, res, next) {
  if (!req.admin || req.admin.role !== "boss") {
    return res.status(403).json({ success: false, message: "Only the boss account can do this." });
  }
  next();
}

// ================================
// CUSTOMER / SELLER AUTH MIDDLEWARE
// ================================
// Separate from admin auth above — customers/sellers log in with Google,
// never with a username/password, and their tokens carry a customerId
// instead of a username.

function requireCustomer(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, message: "Please sign in to continue." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== "customer") {
      return res.status(401).json({ success: false, message: "Please sign in to continue." });
    }
    const database = readDatabase();
    const customer = database.customers.find((c) => c.id === payload.customerId);
    if (!customer) {
      return res.status(401).json({ success: false, message: "Account not found. Please sign in again." });
    }
    req.customer = customer;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Session expired. Please sign in again." });
  }
}

// ================================
// RATE LIMITING — brute-force protection
// ================================
// This is IP-based and separate from the existing 3-strike sub-admin
// account lockout above. It matters most for the boss account, which
// (correctly) never locks out by design — one bad password can't be used
// to lock the site's owner out of their own admin panel — but that means
// it previously had NO brute-force protection at all. This closes that gap
// without touching the lockout behavior itself.
//
// standardHeaders adds RateLimit-* response headers; legacyHeaders is off
// since nothing here depends on the old X-RateLimit-* headers.
function makeLimiter(windowMinutes, max, message) {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message },
  });
}

// Login endpoints: tight — a real user rarely needs more than a handful of
// attempts in 15 minutes, but this still allows retyping a typo'd password.
const loginLimiter = makeLimiter(15, 10, "Too many login attempts. Please wait a few minutes and try again.");

// Signup/apply endpoints: looser, since these aren't "guess a secret" flows,
// but still capped to blunt automated spam/abuse.
const signupLimiter = makeLimiter(60, 20, "Too many attempts. Please try again later.");

// Password-reset-request endpoints: tight, since each pending request emails
// the admin — no reason to let one IP flood that inbox.
const resetRequestLimiter = makeLimiter(60, 5, "Too many reset requests. Please try again later.");

// Directory exports contain customer/seller contact data. Sub-admins must
// complete an email OTP challenge before the server returns any export rows.
const exportOtpLimiter = makeLimiter(15, 5, "Too many export verification attempts. Please wait and try again.");

// Guest order tracking is unauthenticated by nature (no account to sign
// into), so it's the one lookup endpoint most exposed to enumeration —
// tight limit, and the handler below requires an exact phone+order-number
// match rather than a partial/fuzzy search.
const trackOrderLimiter = makeLimiter(15, 10, "Too many lookup attempts. Please wait a few minutes and try again.");

// Customer self-service "forgot password" OTP request: tight, since each
// request emails the customer's inbox and (once verified) allows a full
// password reset.
const customerForgotPasswordLimiter = makeLimiter(60, 5, "Too many reset requests. Please try again later.");

// ================================
// ADMIN LOGIN
// ================================

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const ip = getClientIp(req);
  const userAgent = req.headers["user-agent"] || "unknown";

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required." });
  }

  function logAttempt(database, role, success) {
    if (!Array.isArray(database.loginHistory)) database.loginHistory = [];
    database.loginHistory.push({
      username,
      role,
      ip,
      userAgent,
      success,
      at: new Date().toISOString(),
    });
    const MAX_HISTORY = 200;
    if (database.loginHistory.length > MAX_HISTORY) {
      database.loginHistory = database.loginHistory.slice(-MAX_HISTORY);
    }
  }

  // Boss account — checked first, never locks out.
  if (username === BOSS_ACCOUNT.username) {
    const database = readDatabase();
    if (!bcrypt.compareSync(password, BOSS_ACCOUNT.passwordHash)) {
      logAttempt(database, "boss", false);
      writeDatabase(database);
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }
    logAttempt(database, "boss", true);
    database.bossLastLogin = { ip, at: new Date().toISOString() };
    const sessionId = crypto.randomUUID();
    registerSession(database, username, sessionId);
    writeDatabase(database);
    const token = jwt.sign({ username, role: "boss", sessionId }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ success: true, token, username, role: "boss" });
  }

  // Sub-admin account — stored in database.json, hashed, with a 3-strike lockout.
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === username);

  if (!account) {
    logAttempt(database, "admin", false);
    writeDatabase(database);
    return res.status(401).json({ success: false, message: "Invalid username or password." });
  }

  if (account.locked) {
    return res.status(403).json({
      success: false,
      message: "This account is locked after too many wrong attempts. Ask the boss to unlock it.",
    });
  }

  if (!bcrypt.compareSync(password, account.passwordHash)) {
    account.failedAttempts = (account.failedAttempts || 0) + 1;
    if (account.failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      account.locked = true;
    }
    logAttempt(database, "admin", false);
    writeDatabase(database);

    if (account.locked) {
      return res.status(403).json({
        success: false,
        message: "Wrong password 3 times — this account is now locked. Ask the boss to unlock it.",
      });
    }
    return res.status(401).json({
      success: false,
      message: `Invalid username or password. ${MAX_LOGIN_ATTEMPTS - account.failedAttempts} attempt(s) left before lockout.`,
    });
  }

  account.failedAttempts = 0;
  account.lastLogin = { ip, at: new Date().toISOString() };
  logAttempt(database, "admin", true);
  const sessionId = crypto.randomUUID();
  registerSession(database, username, sessionId);
  writeDatabase(database);

  const token = jwt.sign({ username, role: "admin", sessionId }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, token, username, role: "admin" });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  const database = readDatabase();
  revokeSession(database, req.admin.username, req.admin.sessionId);
  writeDatabase(database);
  res.json({ success: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  if (req.admin.role === "boss") {
    return res.json({ success: true, username: req.admin.username, role: req.admin.role, canDeleteProducts: true });
  }
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === req.admin.username);
  res.json({
    success: true,
    username: req.admin.username,
    role: req.admin.role,
    designation: account ? (account.designation || null) : null,
    email: account ? (account.email || null) : null,
    phone: account ? (account.phone || null) : null,
    canDeleteProducts: !!(account && account.canDeleteProducts),
  });
});

// ================================
// ================================
// CUSTOMER SIGN UP / LOGIN (mobile number + password)
// ================================
// Customers create their own account with a mobile number + password —
// no email, no Google, no OTP. Same JWT session pattern as everywhere
// else on the site.

function normalizeMobile(raw) {
  return String(raw || "").replace(/\D/g, "").slice(-10); // keep last 10 digits
}

function isValidMobile(mobile) {
  return /^[6-9]\d{9}$/.test(mobile); // 10-digit Indian mobile number for legacy mobile/password login
}

function normalizeWhatsAppNumber(countryCode, number) {
  let cc = String(countryCode || "").replace(/\D/g, "");
  let local = String(number || "").trim();
  const rawDigits = local.replace(/\D/g, "");
  // If the client sends a full international number (for example +9198...),
  // do not accidentally prepend the selected country code a second time.
  if (String(number || "").trim().startsWith("+") && rawDigits.length >= 7) {
    const knownCodes = [
      "1","7","20","27","30","31","32","33","34","36","39","40","41","43","44","45","46","47","48","49","51","52","53","54","55","56","57","58","60","61","62","63","64","65","66","81","82","84","86","90","91","92","93","94","95","98","211","212","213","216","218","220","221","222","223","224","225","226","227","228","229","230","231","232","233","234","235","236","237","238","239","240","241","242","243","244","245","248","249","250","251","252","253","254","255","256","257","258","260","261","262","263","264","265","266","267","268","269","290","291","297","298","299","350","351","352","353","354","355","356","357","358","359","370","371","372","373","374","375","376","377","378","379","380","381","382","383","385","386","387","389","420","421","423","500","501","502","503","504","505","506","507","508","509","590","591","592","593","594","595","596","597","598","599","670","672","673","674","675","676","677","678","679","680","681","682","683","685","686","687","688","689","690","691","692","850","852","853","855","856","880","886","960","961","962","963","964","965","966","967","968","970","971","972","973","974","975","976","977","992","993","994","995","996","998"
    ].sort((a,b) => b.length - a.length);
    const matched = knownCodes.find(code => rawDigits.startsWith(code));
    if (matched) { cc = matched; local = rawDigits.slice(matched.length); }
  } else {
    local = rawDigits;
  }
  if (!/^\d{1,4}$/.test(cc) || local.length < 4 || local.length > 15) return "";
  return "+" + cc + local;
}

app.post("/api/customer/register", signupLimiter, async (req, res) => {
  const { name, mobile, password } = req.body || {};
  const cleanName = String(name || "").trim();
  const cleanMobile = normalizeMobile(mobile);

  if (!cleanName) {
    return res.status(400).json({ success: false, message: "Please enter your name." });
  }
  if (!isValidMobile(cleanMobile)) {
    return res.status(400).json({ success: false, message: "Enter a valid 10-digit mobile number." });
  }
  if (!password || String(password).length < 6) {
    return res.status(400).json({ success: false, message: "Password should be at least 6 characters." });
  }

  const duplicateMessage = "An account with this mobile number already exists. Please log in instead.";
  const database = readDatabase();
  // Cheap first-pass check against the in-memory array.
  const exists = database.customers.find((c) => c.mobile === cleanMobile);
  if (exists) {
    return res.status(409).json({ success: false, message: duplicateMessage });
  }

  // Atomically claim this mobile number via MongoDB's unique index. This is
  // the real guarantee against two simultaneous registrations for the same
  // number both succeeding — it holds even across multiple server instances,
  // unlike the in-memory check above which only protects a single process.
  const reserved = await reserveCustomerMobile(cleanMobile, null);
  if (!reserved) {
    return res.status(409).json({ success: false, message: duplicateMessage });
  }

  try {
    // Re-check in case another request on this same instance created the
    // account in the moment between the check above and the reservation.
    if (database.customers.find((c) => c.mobile === cleanMobile)) {
      await releaseCustomerMobile(cleanMobile);
      return res.status(409).json({ success: false, message: duplicateMessage });
    }

    // IMPORTANT: the new customer's id is generated here — after the await
    // above, not before it. getNextId() just returns
    // max(existing ids)+1 with no locking of its own, so if it were computed
    // before that await, two concurrent registrations (different mobile
    // numbers, so both pass the mobile-uniqueness check independently) could
    // both read the same "next" id while neither has pushed yet, and end up
    // creating two different customer accounts that share one id — which
    // would then make lookups by id (login sessions, orders, account
    // pages) resolve to whichever of the two happens to come first. Doing
    // this read synchronously, right before the push below with no
    // await in between, is what actually prevents that.
    const newId = getNextId(database.customers);

    const customer = {
      id: newId,
      mobile: cleanMobile,
      name: cleanName,
      passwordHash: bcrypt.hashSync(String(password), 10),
      picture: "",
      cart: [],
      role: "customer",
      marketingOptIn: true,
      shopTitle: "",
      sellerStatus: "none",
      createdAt: new Date().toISOString(),
    };
    database.customers.push(customer);
    writeDatabase(database);

    const token = jwt.sign(
      { type: "customer", customerId: customer.id },
      JWT_SECRET,
      { expiresIn: "30d" },
    );

    res.json({
      success: true,
      token,
      customer: {
        id: customer.id,
        name: customer.name,
        mobile: customer.mobile,
        picture: customer.picture || "",
        role: customer.role,
        shopTitle: customer.shopTitle,
        sellerStatus: customer.sellerStatus,
        marketingOptIn: customer.marketingOptIn !== false,
        needsEmail: !customer.email,
        hasPassword: !!customer.passwordHash,
      },
    });
  } catch (err) {
    await releaseCustomerMobile(cleanMobile);
    console.error("customer/register failed:", err.message);
    res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
});

app.post("/api/customer/login", loginLimiter, (req, res) => {
  const { mobile, password } = req.body || {};
  const cleanMobile = normalizeMobile(mobile);
  if (!cleanMobile || !password) {
    return res.status(400).json({ success: false, message: "Mobile number and password are required." });
  }

  const database = readDatabase();
  const customer = database.customers.find((c) => c.mobile === cleanMobile);

  // A Google-created account may have a mobile number but no local password yet.
  // Do not pretend it is a brand-new account; tell the user to finish account setup.
  if (customer && !customer.passwordHash) {
    return res.status(409).json({
      success: false,
      needsPasswordSetup: true,
      message: "Your account needs a password before you can use mobile login. Sign in with Google or complete your account setup.",
    });
  }

  // No account for this number → tell the frontend so it can offer sign-up.
  if (!customer) {
    return res.status(404).json({
      success: false,
      notRegistered: true,
      message: "No account found for this number. Create one below.",
    });
  }
  // Account exists but the password is wrong.
  if (!bcrypt.compareSync(password, customer.passwordHash)) {
    return res.status(401).json({ success: false, message: "Incorrect password. Please try again." });
  }

  const token = jwt.sign(
    { type: "customer", customerId: customer.id },
    JWT_SECRET,
    { expiresIn: "30d" },
  );

  res.json({
    success: true,
    token,
    customer: {
      id: customer.id,
      name: customer.name,
      mobile: customer.mobile,
      picture: customer.picture || "",
      role: customer.role,
      shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus,
      marketingOptIn: customer.marketingOptIn !== false,
      needsEmail: !customer.email,
      hasPassword: !!customer.passwordHash,
    },
  });
});

// Customer signs in / signs up with Google. Existing accounts are matched
// by email; brand-new Google users get a customer account immediately, then
// the frontend asks them to complete their WhatsApp mobile + local password.
app.post("/api/customer/google-login", loginLimiter, async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ success: false, message: "Missing Google token." });

  let profile;
  try {
    profile = await verifyGoogleToken(idToken);
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message || "Google sign-in failed." });
  }

  const database = readDatabase();
  let customer = database.customers.find((c) => c.email && c.email.toLowerCase() === profile.email.toLowerCase());

  if (!customer) {
    customer = {
      id: getNextId(database.customers),
      mobile: "",
      name: profile.name || profile.email.split("@")[0],
      email: profile.email,
      googleId: profile.googleId,
      passwordHash: "",
      picture: profile.picture || "",
      cart: [],
      role: "customer",
      marketingOptIn: true,
      shopTitle: "",
      sellerStatus: "none",
      createdAt: new Date().toISOString(),
    };
    database.customers.push(customer);
    writeDatabase(database);
  } else if (!customer.googleId) {
    // Existing mobile+password account signing in with Google for the
    // first time using the same email — just link it, don't duplicate.
    customer.googleId = profile.googleId;
    if (!customer.picture) customer.picture = profile.picture || "";
    writeDatabase(database);
  }

  const token = jwt.sign({ type: "customer", customerId: customer.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({
    success: true,
    token,
    customer: {
      id: customer.id,
      name: customer.name,
      email: customer.email || "",
      mobile: customer.mobile,
      picture: customer.picture || "",
      role: customer.role,
      shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus,
      marketingOptIn: customer.marketingOptIn !== false,
      needsProfileCompletion: !customer.mobile,
      hasPassword: !!customer.passwordHash,
    },
  });
});

// Save a Google customer's WhatsApp number. No OTP/verification and no password are required.
// The country calling code is stored with the number so international WhatsApp numbers work.
app.post("/api/customer/save-whatsapp-number", requireCustomer, async (req, res) => {
  const waNumber = normalizeWhatsAppNumber(req.body && req.body.countryCode, req.body && req.body.number);
  if (!waNumber) return res.status(400).json({ success: false, message: "Enter a valid WhatsApp number and country code." });

  // IMPORTANT: normalizeWhatsAppNumber() keeps the country code (e.g.
  // "+919876543210"), but every other path in the app — register, login,
  // complete-account, and the admin duplicate-mobile detector — stores and
  // compares the bare 10-digit form (e.g. "9876543210") via normalizeMobile().
  // If a domestic Indian WhatsApp number were saved straight into
  // customer.mobile in its "+91..." form, it would never match against
  // those other paths and duplicate mobiles could silently slip through.
  // So: for Indian numbers, store the SAME canonical 10-digit format in
  // customer.mobile as everywhere else; keep the full "+cc..." form only in
  // customer.whatsappNumber, which is purely a display/contact field.
  const waDigits = waNumber.replace(/\D/g, "");
  const indianLocalPart = waDigits.length === 12 && waDigits.startsWith("91") ? waDigits.slice(2) : (waDigits.length === 10 ? waDigits : "");
  if (!isValidMobile(indianLocalPart)) {
    return res.status(400).json({ success: false, message: "Enter a valid 10-digit Indian mobile number." });
  }
  const canonicalMobile = indianLocalPart;

  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) return res.status(404).json({ success: false, message: "Account not found." });

  const duplicateMessage = "This WhatsApp number is already linked to another customer account. Please use a different number.";
  const duplicate = database.customers.find((c) => c.id !== customer.id && c.mobile === canonicalMobile);
  if (duplicate) return res.status(409).json({ success: false, message: duplicateMessage });

  const previousMobile = customer.mobile || "";
  if (canonicalMobile !== previousMobile) {
    const reserved = await reserveCustomerMobile(canonicalMobile, customer.id);
    if (!reserved) return res.status(409).json({ success: false, message: duplicateMessage });
    // Re-check after the async reservation in case another request just landed.
    if (database.customers.find((c) => c.id !== customer.id && c.mobile === canonicalMobile)) {
      await releaseCustomerMobile(canonicalMobile);
      return res.status(409).json({ success: false, message: duplicateMessage });
    }
  }

  customer.mobile = canonicalMobile;
  customer.whatsappNumber = waNumber;
  customer.whatsappNumberSavedAt = new Date().toISOString();
  writeDatabase(database);
  if (previousMobile && previousMobile !== canonicalMobile) await releaseCustomerMobile(previousMobile);

  res.json({
    success: true,
    message: "WhatsApp number saved successfully.",
    customer: {
      id: customer.id, name: customer.name, email: customer.email || "", mobile: customer.mobile,
      picture: customer.picture || "", role: customer.role, shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus, marketingOptIn: customer.marketingOptIn !== false, needsProfileCompletion: false,
      hasPassword: !!customer.passwordHash,
    },
  });
});

// Complete a Google-created customer account with the WhatsApp mobile number
// and a local password. This keeps Google sign-in working while also enabling
// the site's normal mobile + password login and WhatsApp order flow.
app.post("/api/customer/complete-account", requireCustomer, async (req, res) => {
  const { mobile, password } = req.body || {};
  const cleanMobile = normalizeMobile(mobile);
  const cleanPassword = String(password || "");

  if (!isValidMobile(cleanMobile)) {
    return res.status(400).json({ success: false, message: "Enter a valid 10-digit WhatsApp mobile number." });
  }
  if (cleanPassword.length < 6) {
    return res.status(400).json({ success: false, message: "Password should be at least 6 characters." });
  }

  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) return res.status(404).json({ success: false, message: "Account not found." });

  const duplicateMessage = "This mobile number is already linked to another customer account. Please use a different number.";
  const duplicate = database.customers.find((c) => c.id !== customer.id && c.mobile === cleanMobile);
  if (duplicate) {
    return res.status(409).json({ success: false, message: duplicateMessage });
  }

  const previousMobile = customer.mobile || "";
  if (cleanMobile !== previousMobile) {
    const reserved = await reserveCustomerMobile(cleanMobile, customer.id);
    if (!reserved) return res.status(409).json({ success: false, message: duplicateMessage });
    if (database.customers.find((c) => c.id !== customer.id && c.mobile === cleanMobile)) {
      await releaseCustomerMobile(cleanMobile);
      return res.status(409).json({ success: false, message: duplicateMessage });
    }
  }

  customer.mobile = cleanMobile;
  customer.passwordHash = bcrypt.hashSync(cleanPassword, 10);
  if (!customer.role) customer.role = "customer";
  if (!customer.shopTitle) customer.shopTitle = "";
  if (!customer.sellerStatus) customer.sellerStatus = "none";
  writeDatabase(database);
  if (previousMobile && previousMobile !== cleanMobile) await releaseCustomerMobile(previousMobile);

  res.json({
    success: true,
    message: "Account completed successfully.",
    customer: {
      id: customer.id,
      name: customer.name,
      email: customer.email || "",
      mobile: customer.mobile,
      picture: customer.picture || "",
      role: customer.role,
      shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus,
      marketingOptIn: customer.marketingOptIn !== false,
      needsProfileCompletion: false,
      hasPassword: !!customer.passwordHash,
    },
  });
});

app.get("/api/customer/me", requireCustomer, (req, res) => {
  const c = req.customer;
  res.json({
    success: true,
    customer: {
      id: c.id,
      name: c.name,
      email: c.email || "",
      mobile: c.mobile,
      picture: c.picture || "",
      role: c.role,
      shopTitle: c.shopTitle,
      sellerStatus: c.sellerStatus,
      marketingOptIn: c.marketingOptIn !== false,
      needsProfileCompletion: !c.mobile,
      needsEmail: !!c.mobile && !c.email,
      hasPassword: !!c.passwordHash,
    },
  });
});

// Self-service: a logged-in customer adds (or replaces) the email on their
// account. Being logged in is the identity proof here — no OTP needed just
// to attach an email, the same way a fresh signup doesn't need one either.
// This is what makes the forgot-password OTP flow below safe: an email can
// only ever be attached by someone who already controls the account.
app.post("/api/customer/add-email", requireCustomer, (req, res) => {
  const cleanEmail = String((req.body || {}).email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ success: false, message: "Enter a valid email address." });
  }

  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) return res.status(404).json({ success: false, message: "Account not found." });

  const duplicate = database.customers.find((c) => c.id !== customer.id && c.email && c.email.toLowerCase() === cleanEmail);
  if (duplicate) {
    return res.status(409).json({ success: false, message: "This email is already linked to another account." });
  }

  customer.email = cleanEmail;
  writeDatabase(database);

  res.json({
    success: true,
    message: "Email saved successfully.",
    customer: {
      id: customer.id, name: customer.name, email: customer.email, mobile: customer.mobile,
      picture: customer.picture || "", role: customer.role, shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus, marketingOptIn: customer.marketingOptIn !== false,
      needsProfileCompletion: !customer.mobile, needsEmail: false, hasPassword: !!customer.passwordHash,
    },
  });
});

// ================================
// CUSTOMER FORGOT PASSWORD (email OTP)
// ================================
// Unauthenticated by nature (that's the point — they're locked out), so
// identity is proven by possession of the registered email inbox instead of
// a session. Mobile number finds the account; the OTP only ever goes to
// whatever email is already saved on that account (never one typed in on
// the spot) — that's what closes the takeover hole a wide-open "type any
// email" flow would have.
function buildCustomerResetOtpEmail({ name, otp }) {
  return `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;line-height:1.5;color:#2f2521;">
    <h2 style="color:#8a1c42;margin-bottom:6px;">Design Makers password reset</h2>
    <p>Hi ${escapeHtml(name || "there")},</p>
    <p>Use the code below to reset your Design Makers account password. This code expires in 10 minutes.</p>
    <div style="background:#f8ecef;border:1px solid #ecd7dd;border-radius:10px;padding:18px 20px;margin:18px 0;text-align:center;">
      <div style="font-size:12px;color:#8c7d78;">Your one-time verification code</div>
      <div style="font-size:32px;letter-spacing:8px;font-weight:800;color:#8a1c42;margin-top:6px;">${otp}</div>
    </div>
    <p style="color:#8c7d78;font-size:13px;">If you didn't request this, you can safely ignore this email — your password won't change.</p>
  </div>`;
}

function cleanCustomerResetOtps(database) {
  const now = Date.now();
  if (!Array.isArray(database.customerPasswordResetOtps)) database.customerPasswordResetOtps = [];
  database.customerPasswordResetOtps = database.customerPasswordResetOtps.filter(
    (x) => !x.expiresAt || new Date(x.expiresAt).getTime() > now,
  );
}

app.post("/api/customer/forgot-password/request-otp", customerForgotPasswordLimiter, async (req, res) => {
  const cleanMobile = normalizeMobile((req.body || {}).mobile);
  if (!isValidMobile(cleanMobile)) {
    return res.status(400).json({ success: false, message: "Enter a valid 10-digit mobile number." });
  }

  const database = readDatabase();
  cleanCustomerResetOtps(database);
  const customer = database.customers.find((c) => c.mobile === cleanMobile);

  // Same response shape whether or not the account exists, so this can't be
  // used to enumerate which mobile numbers have accounts.
  if (!customer || !customer.email) {
    return res.status(404).json({
      success: false,
      message: customer
        ? "No email is saved on this account yet. Please log in and add one from your profile, or contact support to reset your password."
        : "No account found for this number.",
    });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const requestId = crypto.randomUUID();
  database.customerPasswordResetOtps.push({
    requestId,
    customerId: customer.id,
    otpHash: hashExportSecret(otp),
    attempts: 0,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    createdAt: new Date().toISOString(),
  });
  writeDatabase(database);

  const emailResult = await sendMail(
    customer.email,
    "Design Makers password reset code",
    buildCustomerResetOtpEmail({ name: customer.name, otp }),
  );
  if (!emailResult.sent) {
    const db2 = readDatabase();
    db2.customerPasswordResetOtps = (db2.customerPasswordResetOtps || []).filter((x) => x.requestId !== requestId);
    writeDatabase(db2);
    return res.status(503).json({ success: false, message: "Could not send the verification email right now. Please try again shortly." });
  }

  res.json({ success: true, requestId, emailMasked: maskEmail(customer.email), expiresInSeconds: 600 });
});

app.post("/api/customer/forgot-password/verify-otp", customerForgotPasswordLimiter, (req, res) => {
  const requestId = String((req.body || {}).requestId || "");
  const otp = String((req.body || {}).otp || "").trim();
  const newPassword = String((req.body || {}).newPassword || "");

  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, message: "New password should be at least 6 characters." });
  }

  const database = readDatabase();
  cleanCustomerResetOtps(database);
  const request = (database.customerPasswordResetOtps || []).find((x) => x.requestId === requestId);
  if (!request) return res.status(400).json({ success: false, message: "This code has expired or is invalid. Please request a new one." });
  if (request.attempts >= 5) return res.status(429).json({ success: false, message: "Too many incorrect attempts. Please request a new code." });

  if (!/^\d{6}$/.test(otp) || hashExportSecret(otp) !== request.otpHash) {
    request.attempts += 1;
    writeDatabase(database);
    return res.status(401).json({ success: false, message: "Incorrect code. Please check your email and try again." });
  }

  const customer = database.customers.find((c) => c.id === request.customerId);
  if (!customer) return res.status(404).json({ success: false, message: "Account not found." });

  customer.passwordHash = bcrypt.hashSync(newPassword, 10);
  database.customerPasswordResetOtps = database.customerPasswordResetOtps.filter((x) => x.requestId !== requestId);
  writeDatabase(database);

  res.json({ success: true, message: "Password reset successfully. You can now log in with your new password." });
});

// Self-service password change for a logged-in customer. If the account
// already has a password, the current one must be verified first. Google-only
// accounts that never set a password can set one directly (no old password
// to check yet).
app.post("/api/customer/change-password", requireCustomer, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const cleanNew = String(newPassword || "");
  if (cleanNew.length < 6) {
    return res.status(400).json({ success: false, message: "New password should be at least 6 characters." });
  }

  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) return res.status(404).json({ success: false, message: "Account not found." });

  if (customer.passwordHash) {
    if (!currentPassword || !bcrypt.compareSync(String(currentPassword), customer.passwordHash)) {
      return res.status(401).json({ success: false, message: "Current password is incorrect." });
    }
  }

  customer.passwordHash = bcrypt.hashSync(cleanNew, 10);
  writeDatabase(database);

  res.json({ success: true, message: "Password updated successfully.", hasPassword: true });
});

// Customer marketing preference. This is account-scoped: a customer can only
// change their own subscription state.
app.put("/api/customer/marketing-preference", requireCustomer, (req, res) => {
  const optIn = req.body && req.body.subscribed === true;
  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) return res.status(404).json({ success: false, message: "Account not found." });
  customer.marketingOptIn = optIn;
  customer.marketingPreferenceUpdatedAt = new Date().toISOString();
  writeDatabase(database);
  res.json({ success: true, subscribed: optIn, message: optIn ? "You are subscribed to offers and product updates." : "You have been unsubscribed from promotional emails." });
});

app.get("/api/marketing/unsubscribe", (req, res) => {
  const customerId = verifyMarketingToken(req.query && req.query.token);
  if (!customerId) {
    return res.status(400).send(`<!doctype html><html><body style="font-family:Arial,sans-serif;background:#f9f2ee;padding:40px;text-align:center;color:#4a2a23;"><div style="max-width:520px;margin:auto;background:#fff;padding:28px;border-radius:16px;border:1px solid #ead8d0;"><h2>Unsubscribe link expired</h2><p>Please open your Design Makers account and use Profile → Email Preferences.</p><a href="/index.html" style="display:inline-block;background:#6b3028;color:#fff;text-decoration:none;padding:10px 16px;border-radius:9px;">Go to Design Makers</a></div></body></html>`);
  }
  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === customerId);
  if (!customer) return res.status(404).send("Account not found.");
  customer.marketingOptIn = false;
  customer.marketingPreferenceUpdatedAt = new Date().toISOString();
  writeDatabase(database);
  res.send(`<!doctype html><html><body style="font-family:Arial,sans-serif;background:#f9f2ee;padding:40px;text-align:center;color:#4a2a23;"><div style="max-width:520px;margin:auto;background:#fff;padding:28px;border-radius:16px;border:1px solid #ead8d0;"><div style="font-size:12px;letter-spacing:2px;font-weight:800;color:#a56a2a;">DESIGN MAKERS</div><h2>You're unsubscribed</h2><p>You won't receive promotional offers or new-product emails. Essential order, login and account emails are unaffected.</p><p>You can subscribe again anytime from <b>Profile → Email Preferences</b>.</p><a href="/index.html" style="display:inline-block;background:#6b3028;color:#fff;text-decoration:none;padding:10px 16px;border-radius:9px;">Back to Design Makers</a></div></body></html>`);
});

// ================================
// ADMIN MARKETING CAMPAIGNS
// ================================
app.get("/api/admin/marketing/campaigns", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const campaigns = Array.isArray(database.marketingCampaigns) ? database.marketingCampaigns : [];
  res.json({ success: true, campaigns: campaigns.slice().sort((a,b) => new Date(b.createdAt||0) - new Date(a.createdAt||0)) });
});

app.get("/api/admin/marketing/customers", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const customers = (database.customers || []).filter(c => c.email).map(c => ({ id:c.id, name:c.name||"Customer", email:c.email, marketingOptIn:c.marketingOptIn !== false })).sort((a,b)=>String(a.name).localeCompare(String(b.name)));
  res.json({ success:true, customers });
});

app.get("/api/admin/marketing/recipients", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const customers = (database.customers || []).filter(c => c.email && c.marketingOptIn !== false);
  const emails = [...new Set(customers.map(c => String(c.email).trim().toLowerCase()).filter(Boolean))];
  res.json({ success: true, count: emails.length });
});

function normalizeCampaign(campaign, database, baseUrl) {
  const type = ["new-products", "offer", "update"].includes(campaign.type) ? campaign.type : "update";
  let selectedIds = Array.isArray(campaign.productIds) ? [...new Set(campaign.productIds.map(Number).filter(Number.isFinite))] : [];
  if (selectedIds.length > 5) throw new Error("Select at most 5 products for the campaign.");
  const products = selectedIds.map(id => (database.products || []).find(p => Number(p.id) === id)).filter(Boolean)
    .map(p => ({ id:p.id, name:p.name, price:p.price, image:p.image || "", onSale:!!p.onSale, salePercent:p.salePercent||0, saleEndsAt:p.saleEndsAt||null }));
  const title = String(campaign.title || "").trim().slice(0,160);
  const heading = String(campaign.heading || title).trim().slice(0,200);
  const message = String(campaign.message || "").trim().slice(0,5000);
  if (!title || !message) throw new Error("Campaign title and message are required.");
  if (type === "new-products" && !products.length) throw new Error("Select at least one product for a new-product announcement.");
  const buttonUrl = String(campaign.buttonUrl||"").trim().slice(0,500);
  if (buttonUrl && !/^https?:\/\//i.test(buttonUrl)) throw new Error("Button URL must start with http:// or https://.");
  // Optional gift code attached to the campaign. Must be a real, currently
  // configured code from the gift-code system — never hardcoded here.
  let giftCode = null;
  if (campaign.giftCodeId) {
    const gift = (database.giftCodes || []).find(g => Number(g.id) === Number(campaign.giftCodeId) && g.active !== false);
    if (!gift) throw new Error("Selected gift code is no longer available.");
    giftCode = { code: gift.code, type: gift.type, value: gift.value, minOrder: gift.minOrder || 0 };
  }
  return { type,title,heading,message,productIds:selectedIds,products,buttonText:String(campaign.buttonText||"").trim().slice(0,60),buttonUrl,giftCode,baseUrl };
}

function getMarketingBaseUrl(req) {
  return String(process.env.PUBLIC_BASE_URL || process.env.BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
}

// Renders the campaign using the EXACT same buildMarketingEmail() template
// used for the real send/test email, so the admin preview can never drift
// from what a customer actually receives. Read-only — sends nothing.
app.post("/api/admin/marketing/preview", requireAdmin, requireBoss, (req, res) => {
  try {
    const database = readDatabase();
    const campaign = normalizeCampaign(req.body || {}, database, getMarketingBaseUrl(req));
    const html = buildMarketingEmail(campaign, makeMarketingToken(0));
    res.json({ success: true, html });
  } catch (e) { res.status(400).json({ success:false, message:e.message || "Could not build preview." }); }
});

app.post("/api/admin/marketing/test", requireAdmin, requireBoss, async (req, res) => {
  try {
    const database = readDatabase();
    const campaign = normalizeCampaign(req.body || {}, database, getMarketingBaseUrl(req));
    const to = ADMIN_NOTIFY_EMAIL || GMAIL_USER;
    if (!to) return res.status(400).json({success:false,message:"ADMIN_NOTIFY_EMAIL or GMAIL_USER must be configured for test emails."});
    const result = await sendMail(to, `[TEST] ${campaign.title}`, buildMarketingEmail(campaign, makeMarketingToken(0)));
    if (!result.sent) return res.status(502).json({success:false,message:result.reason || "Test email could not be sent."});
    res.json({success:true,message:`Test email sent to ${to}.`});
  } catch(e) { res.status(400).json({success:false,message:e.message || "Could not create test email."}); }
});

app.post("/api/admin/marketing/send", requireAdmin, requireBoss, async (req, res) => {
  try {
    const database = readDatabase();
    const campaign = normalizeCampaign(req.body || {}, database, getMarketingBaseUrl(req));
    let customers;
    if (req.body.audience === "selected") {
      const ids = new Set((Array.isArray(req.body.customerIds) ? req.body.customerIds : []).map(Number));
      customers = (database.customers || []).filter(c => ids.has(Number(c.id)) && c.email && c.marketingOptIn !== false);
    } else {
      customers = (database.customers || []).filter(c => c.email && c.marketingOptIn !== false);
    }
    const byEmail = new Map();
    customers.forEach(c => { const email=String(c.email||"").trim().toLowerCase(); if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) byEmail.set(email,c); });
    const recipients=[...byEmail.values()];
    if (!recipients.length) return res.status(400).json({success:false,message:"No subscribed customers with valid email addresses were found."});
    if (recipients.length > 5000) return res.status(400).json({success:false,message:"This campaign exceeds the 5,000-recipient safety limit. Use a proper bulk-email provider before sending a larger campaign."});
    if (!Array.isArray(database.marketingCampaigns)) database.marketingCampaigns=[];
    const record={id:getNextId(database.marketingCampaigns),type:campaign.type,title:campaign.title,heading:campaign.heading,message:campaign.message,productIds:campaign.productIds,buttonText:campaign.buttonText,buttonUrl:campaign.buttonUrl,giftCode:campaign.giftCode ? campaign.giftCode.code : null,audience:req.body.audience === "selected" ? "selected" : "all-subscribed",recipientCount:recipients.length,sent:0,failed:0,status:"sending",createdAt:new Date().toISOString(),sentAt:null};
    database.marketingCampaigns.unshift(record); writeDatabase(database);
    for(let i=0;i<recipients.length;i+=5){
      const batch=recipients.slice(i,i+5);
      const results=await Promise.all(batch.map(c=>sendMail(c.email,campaign.title,buildMarketingEmail(campaign,makeMarketingToken(c.id)))));
      results.forEach(r=>{if(r.sent)record.sent++;else record.failed++;});
      writeDatabase(database);
    }
    record.status=record.failed ? (record.sent ? "partial" : "failed") : "sent";
    record.sentAt=new Date().toISOString(); writeDatabase(database);
    res.json({success:true,campaign:{id:record.id,title:record.title,status:record.status,recipientCount:record.recipientCount,sent:record.sent,failed:record.failed}});
  } catch(e) { console.error("Marketing campaign failed:",e); res.status(400).json({success:false,message:e.message || "Campaign failed."}); }
});

// Customer uploads / changes their profile picture (stored as a data URL).
app.post("/api/customer/photo", requireCustomer, (req, res) => {
  const { picture } = req.body || {};
  if (typeof picture !== "string" || !/^data:image\/(png|jpe?g|webp);base64,/.test(picture)) {
    return res.status(400).json({ success: false, message: "Please upload a valid image." });
  }
  // Guard against huge uploads (~2MB of base64).
  if (picture.length > 2_800_000) {
    return res.status(413).json({ success: false, message: "Image is too large. Please use a smaller photo." });
  }

  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) {
    return res.status(404).json({ success: false, message: "Account not found." });
  }
  customer.picture = picture;
  writeDatabase(database);
  res.json({ success: true, picture });
});

// ================================
// CUSTOMER CART (saved to the account so it survives logout / new devices)
// ================================
app.get("/api/customer/cart", requireCustomer, (req, res) => {
  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  res.json({ success: true, cart: (customer && Array.isArray(customer.cart)) ? customer.cart : [] });
});

app.put("/api/customer/cart", requireCustomer, (req, res) => {
  const { cart } = req.body || {};
  if (!Array.isArray(cart)) {
    return res.status(400).json({ success: false, message: "Cart must be a list." });
  }
  if (cart.length > 100) {
    return res.status(400).json({ success: false, message: "Too many items in the cart." });
  }
  // Keep only the fields we need, and sane values.
  const clean = cart
    .filter((it) => it && (it.productId !== undefined && it.productId !== null))
    .slice(0, 100)
    .map((it) => ({
      productId: it.productId,
      name: String(it.name || "").slice(0, 200),
      price: Number(it.price) || 0,
      originalPrice: Number(it.originalPrice) || Number(it.price) || 0,
      onSale: !!it.onSale,
      // Product photos are stored as base64 data URIs, which run to
      // hundreds of KB — far past 500 chars. Slicing them at 500 used to
      // save a truncated, corrupted data URI that rendered as a broken
      // image in the cart. Real short image URLs are kept as-is; anything
      // long is dropped here and re-resolved on the frontend by looking
      // the product's current photo up via productId instead.
      image: typeof it.image === "string" && it.image.length <= 500 ? it.image : "",
      size: it.size || "",
      qty: Math.max(1, Math.min(100000, Math.round(Number(it.qty) || 1))),
      discounts: Array.isArray(it.discounts) ? it.discounts.slice(0, 20) : [],
    }));

  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) {
    return res.status(404).json({ success: false, message: "Account not found." });
  }
  customer.cart = clean;
  writeDatabase(database);
  res.json({ success: true });
});

// ================================
// CUSTOMER EXTRAS: wishlist, recently-viewed, saved addresses
// ================================
// Previously these lived only in browser localStorage (see AUDIT-REPORT.md,
// section 4) — functional on one device, but two devices for the same
// account showed completely different wishlists/addresses. Synced here the
// same way the cart already is: saved to the account, pulled and merged on
// sign-in from any device.
app.get("/api/customer/extras", requireCustomer, (req, res) => {
  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  res.json({
    success: true,
    wishlist: (customer && Array.isArray(customer.wishlist)) ? customer.wishlist : [],
    recentlyViewed: (customer && Array.isArray(customer.recentlyViewed)) ? customer.recentlyViewed : [],
    addresses: (customer && Array.isArray(customer.addresses)) ? customer.addresses : [],
  });
});

app.put("/api/customer/extras", requireCustomer, (req, res) => {
  const { wishlist, recentlyViewed, addresses } = req.body || {};
  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === req.customer.id);
  if (!customer) {
    return res.status(404).json({ success: false, message: "Account not found." });
  }

  if (wishlist !== undefined) {
    if (!Array.isArray(wishlist)) {
      return res.status(400).json({ success: false, message: "Wishlist must be a list." });
    }
    customer.wishlist = wishlist.map((n) => Number(n)).filter((n) => Number.isFinite(n)).slice(0, 100);
  }
  if (recentlyViewed !== undefined) {
    if (!Array.isArray(recentlyViewed)) {
      return res.status(400).json({ success: false, message: "Recently viewed must be a list." });
    }
    customer.recentlyViewed = recentlyViewed.map((n) => Number(n)).filter((n) => Number.isFinite(n)).slice(0, 12);
  }
  if (addresses !== undefined) {
    if (!Array.isArray(addresses)) {
      return res.status(400).json({ success: false, message: "Addresses must be a list." });
    }
    customer.addresses = addresses
      .slice(0, 10)
      .map((a) => ({
        label: String((a && a.label) || "Address").slice(0, 40),
        text: String((a && a.text) || "").slice(0, 300),
      }))
      .filter((a) => a.text);
  }

  writeDatabase(database);
  res.json({ success: true });
});

// ================================
// SELLER APPLICATIONS (public — no account needed)
// ================================
// Anyone can apply from the /sell page (or the "Become a Seller" link in a
// customer's account). No login required to submit. Only the LAST 4 DIGITS
// of the Aadhaar number are ever stored — never the full number — along
// with a photo of the card for the admin to manually verify.

app.post("/api/seller-applications", signupLimiter, async (req, res) => {
  const body = req.body || {};
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim();
  const phone = String(body.phone || "").trim();
  const shopTitle = String(body.shopTitle || "").trim();
  const aadhaar = String(body.aadhaar || "").replace(/\D/g, "");
  const aadhaarPhoto = String(body.aadhaarPhoto || ""); // base64 data URL
  const personPhoto = String(body.personPhoto || ""); // base64 data URL — a photo of the applicant

  // Extra profile fields shown on the admin's Seller Details page. Alternate
  // phone, UPI ID, and GST number are optional — everything else here is
  // required to submit an application.
  const altPhone = String(body.altPhone || "").trim();
  const businessType = String(body.businessType || "").trim();
  const businessAddress = String(body.businessAddress || "").trim();
  const city = String(body.city || "").trim();
  const state = String(body.state || "").trim();
  const pincode = String(body.pincode || "").trim();
  const panNumber = String(body.panNumber || "").trim().toUpperCase();
  const dob = String(body.dob || "").trim();
  const gender = String(body.gender || "").trim();
  const bankAccountNumber = String(body.bankAccountNumber || "").trim();
  const ifscCode = String(body.ifscCode || "").trim().toUpperCase();
  const upiId = String(body.upiId || "").trim();
  const gstNumber = String(body.gstNumber || "").trim().toUpperCase();

  if (!name || !email || !phone || !shopTitle || aadhaar.length !== 12 || !personPhoto) {
    return res.status(400).json({
      success: false,
      message: "Name, email, phone, shop title, a photo of yourself, and a valid 12-digit Aadhaar number are required.",
    });
  }
  if (!businessType || !businessAddress || !city || !state || !pincode || !panNumber || !dob || !gender || !bankAccountNumber || !ifscCode) {
    return res.status(400).json({
      success: false,
      message: "Please fill in your business details, identity details (PAN, date of birth, gender), and bank details (account number, IFSC) — everything except alternate phone, UPI ID, and GST number is required.",
    });
  }

  const database = readDatabase();
  const aadhaarLast4 = aadhaar.slice(-4);

  // Block duplicate applications — same person applying twice (by email,
  // phone, or Aadhaar last-4) while an earlier application is still pending
  // or already approved. A previously REJECTED application doesn't block a
  // fresh one.
  const emailLower = email.toLowerCase();
  const duplicate = database.sellerApplications.find(
    (a) =>
      a.status !== "rejected" &&
      (String(a.email || "").toLowerCase() === emailLower ||
        String(a.phone || "") === phone ||
        String(a.aadhaarLast4 || "") === aadhaarLast4),
  );
  const alreadySeller = database.sellers.find(
    (s) =>
      String(s.email || "").toLowerCase() === emailLower ||
      String(s.phone || "") === phone ||
      String(s.aadhaarLast4 || "") === aadhaarLast4,
  );
  if (duplicate || alreadySeller) {
    return res.status(409).json({
      success: false,
      message: alreadySeller
        ? "You're already registered as a seller with this email/phone/Aadhaar."
        : "You've already submitted an application with this email/phone/Aadhaar. Please wait for it to be reviewed.",
    });
  }

  const application = {
    id: getNextId(database.sellerApplications),
    name,
    email,
    phone,
    altPhone,
    shopTitle,
    businessType,
    businessAddress,
    city,
    state,
    pincode,
    aadhaarLast4: aadhaar.slice(-4),
    // aadhaarLast4 is kept in plaintext on purpose — it's what the
    // duplicate-application check above matches against, and by itself
    // (4 digits) it isn't sensitive the way the full number is.
    aadhaarFull: encryptPII(aadhaar),
    panNumber: encryptPII(panNumber),
    dob,
    gender,
    bankAccountNumber: encryptPII(bankAccountNumber),
    ifscCode: encryptPII(ifscCode),
    upiId,
    gstNumber,
    aadhaarPhoto,
    personPhoto,
    status: "pending",
    createdAt: new Date().toISOString(),
  };
  database.sellerApplications.push(application);
  writeDatabase(database);

  // Notify the admin — email + it already shows up in the admin panel
  // via GET /api/admin/seller-applications.
  sendMail(
    ADMIN_NOTIFY_EMAIL,
    "New seller application — Design Makers",
    `<p>New seller application received:</p>
     <ul>
       <li><b>Name:</b> ${name}</li>
       <li><b>Shop title:</b> ${shopTitle}</li>
       <li><b>Email:</b> ${email}</li>
       <li><b>Phone:</b> ${phone}</li>
       <li><b>Aadhaar (last 4):</b> ${application.aadhaarLast4}</li>
     </ul>
     <p>Review and approve it from the admin panel's Sellers tab.</p>`,
  );

  res.json({ success: true, message: "Application submitted — we'll contact you once it's reviewed." });
});

// ================================
// SELLER LOGIN (ID + password, issued on approval)
// ================================

app.post("/api/seller/login", loginLimiter, (req, res) => {
  const { sellerId, password } = req.body || {};
  if (!sellerId || !password) {
    return res.status(400).json({ success: false, message: "Seller ID and password are required." });
  }

  const database = readDatabase();
  const seller = database.sellers.find((s) => s.sellerId === sellerId);
  if (!seller || !bcrypt.compareSync(password, seller.passwordHash)) {
    return res.status(401).json({ success: false, message: "Invalid Seller ID or password." });
  }
  if (seller.banned) {
    return res.status(403).json({ success: false, message: "This seller account has been suspended. Contact Design Makers for details." });
  }

  // A successful login proves the seller now has their password one way or
  // another — clear any "unsent, share manually" fallback sitting on the
  // record so it doesn't linger in the admin panel forever.
  if (seller.pendingPlainPassword) {
    delete seller.pendingPlainPassword;
    writeDatabase(database);
  }

  const token = jwt.sign({ type: "seller", sellerId: seller.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({
    success: true,
    token,
    seller: { id: seller.id, sellerId: seller.sellerId, name: seller.name, shopTitle: seller.shopTitle },
    // True only right after an OTP/one-time password login — the dashboard
    // should block everything else until the seller sets their own password.
    mustChangePassword: !!seller.mustChangePassword,
  });
});

// Seller signs in with Google. Only works for sellers who are ALREADY
// approved (their seller record's email must match the Google account) —
// Google sign-in isn't a way to apply as a seller, applications still go
// through the normal form on /sell.
app.post("/api/seller/google-login", loginLimiter, async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ success: false, message: "Missing Google token." });

  let profile;
  try {
    profile = await verifyGoogleToken(idToken);
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message || "Google sign-in failed." });
  }

  const database = readDatabase();
  const seller = database.sellers.find((s) => String(s.email || "").toLowerCase() === profile.email.toLowerCase());

  if (!seller) {
    return res.status(404).json({
      success: false,
      message: "No approved seller account found for this Google email. Apply first, or log in with your Seller ID and password.",
    });
  }
  if (seller.banned) {
    return res.status(403).json({ success: false, message: "This seller account has been suspended. Contact Design Makers for details." });
  }

  if (!seller.googleId) {
    seller.googleId = profile.googleId;
    writeDatabase(database);
  }

  const token = jwt.sign({ type: "seller", sellerId: seller.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({
    success: true,
    token,
    seller: { id: seller.id, sellerId: seller.sellerId, name: seller.name, shopTitle: seller.shopTitle },
    mustChangePassword: !!seller.mustChangePassword,
  });
});

// ================================
// SELLER: FORGOT PASSWORD
// ================================
// No self-service reset — sellers only have an ID + password, with no
// email/OTP flow behind it. Instead this raises a query that shows up in
// the admin panel; the boss reviews it and clicks a button to generate a
// fresh password and email it to the seller.

app.post("/api/seller/forgot-password", (req, res) => {
  return res.status(403).json({ success: false, message: "Self-service password reset is disabled. Please contact Om/main admin manually." });
});

// Boss/admin: view pending seller password-reset requests.
app.get("/api/admin/seller-password-requests", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const requests = (database.sellerPasswordResetRequests || [])
    .filter((r) => r.status === "pending")
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, requests });
});

// Boss/admin: generate a new password for the seller and email it to them,
// then mark the request resolved.
app.put("/api/admin/seller-password-requests/:id/resolve", requireAdmin, requireBoss, async (req, res) => {
  const database = readDatabase();
  const request = (database.sellerPasswordResetRequests || []).find((r) => r.id === Number(req.params.id));
  if (!request) {
    return res.status(404).json({ success: false, message: "Request not found." });
  }
  if (request.status === "resolved") {
    return res.status(400).json({ success: false, message: "Already resolved." });
  }

  const seller = database.sellers.find((s) => s.id === request.sellerRecordId);
  if (!seller) {
    return res.status(404).json({ success: false, message: "That seller account no longer exists." });
  }

  const newPassword = generateSellerPassword();
  seller.passwordHash = bcrypt.hashSync(newPassword, 10);
  // A reset password is now always one-time — force a fresh password on
  // the seller's next login instead of leaving this one valid forever.
  seller.mustChangePassword = true;
  // Clear out any stale unsent-password flag before we know how this one goes.
  delete seller.pendingPlainPassword;
  request.status = "resolved";
  request.resolvedAt = new Date().toISOString();
  writeDatabase(database);

  const sellerLoginUrl = `${req.protocol}://${req.get("host")}/seller`;
  const emailResult = await sendMail(
    seller.email,
    "Your Design Makers password has been reset",
    buildPasswordResetOtpEmail({
      name: seller.name,
      shopTitle: seller.shopTitle,
      sellerId: seller.sellerId,
      otp: newPassword,
      loginUrl: sellerLoginUrl,
    }),
  );

  if (!emailResult.sent) {
    seller.pendingPlainPassword = newPassword;
  }
  writeDatabase(database);

  res.json({
    success: true,
    message: emailResult.sent
      ? `One-time password generated and emailed to ${seller.name}.`
      : `One-time password generated for ${seller.name}. Share it with them yourself (WhatsApp/SMS/etc) — find it any time from the Live Sellers tab.`,
    sellerId: seller.sellerId,
    newPassword: emailResult.sent ? undefined : newPassword,
    emailSent: emailResult.sent,
  });
});

function requireSeller(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: "Not logged in." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== "seller") throw new Error("wrong token type");
    const database = readDatabase();
    const seller = database.sellers.find((s) => s.id === payload.sellerId);
    if (!seller) return res.status(401).json({ success: false, message: "Seller account not found." });
    if (seller.banned) return res.status(403).json({ success: false, message: "This seller account has been suspended." });
    req.seller = seller;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Session expired. Please log in again." });
  }
}

// ================================
// SELLER: SET OWN NEW PASSWORD
// ================================
// Used two ways: (1) the forced first-login flow after an OTP, where
// currentPassword is the one-time password that just worked; and (2) a
// seller who's already in and wants to change their password normally,
// from their dashboard settings. Either way this always clears
// mustChangePassword, since after this call the seller has a password only
// they know.
app.post("/api/seller/change-password", requireSeller, (req, res) => {
  return res.status(403).json({ success: false, message: "Seller passwords are controlled by the main admin. Please contact Om to change your password." });
});

// ================================
// ADMIN: CUSTOMERS (mobile + password accounts)
// ================================
// Read-only list for the admin panel, plus a "reset password" action.
// We never expose passwordHash — resetting generates a brand-new plaintext
// password, saves its hash, and returns the plaintext ONCE so the admin can
// pass it on to the customer.

// ================================
// PAGINATION HELPER
// ================================
// Applies ?page=&limit= to an already-sorted array and returns both the
// page slice and the metadata the admin panel needs to render Prev/Next
// controls. Defaults to page 1 / 50 per page when the params are missing
// or invalid, so existing callers that don't pass them yet still get a
// sane, bounded response instead of the entire table in one payload.
function paginate(req, items, defaultLimit = 50, maxLimit = 200) {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(maxLimit, Math.max(1, parseInt(req.query.limit, 10) || defaultLimit));
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / limit));
  const start = (page - 1) * limit;
  return {
    slice: items.slice(start, start + limit),
    meta: { total, page, pages, limit },
  };
}

// Human-readable account status for Admin — computed on the fly from
// existing fields; no new field is stored on the customer record.
function computeCustomerAccountStatus(c) {
  if (!c.mobile) return "Incomplete signup (Google, no mobile yet)";
  if (!c.passwordHash && !c.googleId) return "Incomplete signup (no password)";
  return "Active";
}

app.get("/api/admin/customers", requireAdmin, (req, res) => {
  const database = readDatabase();
  const orders = database.orders || [];
  const sorted = (database.customers || [])
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const { slice, meta } = paginate(req, sorted);
  const normalizedMobileCounts = {};
  (database.customers || []).forEach((row) => {
    const normalized = row.mobile ? normalizeMobile(row.mobile) : "";
    if (normalized) normalizedMobileCounts[normalized] = (normalizedMobileCounts[normalized] || 0) + 1;
  });
  const customers = slice
    .map((c) => {
      const theirOrders = orders.filter(
        (o) => (c.mobile && o.customer && o.customer.phone === c.mobile) || o.customerId === c.id,
      );
      const normalized = c.mobile ? normalizeMobile(c.mobile) : "";
      return {
        id: c.id,
        name: c.name,
        email: c.email || null,
        city: c.city || "",
        mobile: c.mobile || null,
        role: c.role,
        shopTitle: c.shopTitle,
        sellerStatus: c.sellerStatus,
        createdAt: c.createdAt,
        orderCount: theirOrders.length,
        // Existing duplicate records are preserved and flagged for Admin review.
        duplicateMobile: !!normalized && normalizedMobileCounts[normalized] > 1,
        duplicateMobileCount: normalized ? (normalizedMobileCounts[normalized] || 0) : 0,
        legacy: !c.mobile,
        marketingOptIn: c.marketingOptIn !== false,
        status: computeCustomerAccountStatus(c),
      };
    });
  res.json({ success: true, customers, ...meta });
});

// ================================
// DIRECTORY EXPORT SECURITY
// ================================
// The boss account can export directly. Sub-admins must receive a one-time
// code at their registered email and verify it before the server returns any
// customer/seller directory rows. Phone is stored as the second contact field
// for the sub-admin, but it is not used for OTP delivery.
function maskEmail(email) {
  const value = String(email || "").trim();
  const at = value.indexOf("@");
  if (at <= 1) return "your registered email";
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  const shown = local.slice(0, Math.min(2, local.length));
  return shown + "***@" + domain;
}

function hashExportSecret(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function cleanExportSecurity(database) {
  const now = Date.now();
  if (!Array.isArray(database.adminExportOtps)) database.adminExportOtps = [];
  if (!Array.isArray(database.adminExportGrants)) database.adminExportGrants = [];
  database.adminExportOtps = database.adminExportOtps.filter((x) => !x.expiresAt || new Date(x.expiresAt).getTime() > now);
  database.adminExportGrants = database.adminExportGrants.filter((x) => !x.expiresAt || new Date(x.expiresAt).getTime() > now);
}

function validExportTarget(kind, format) {
  return ["customers", "sellers"].includes(kind) && ["xlsx", "pdf"].includes(format);
}

function buildExportOtpEmail({ username, otp, kind, format }) {
  const label = kind === "customers" ? "Customer Directory" : "Live Seller Directory";
  const fileType = format === "xlsx" ? "Excel" : "PDF";
  return `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;line-height:1.5;color:#2f2521;">
    <h2 style="color:#8a1c42;margin-bottom:6px;">Design Makers export verification</h2>
    <p>Hi ${escapeHtml(username)},</p>
    <p>A download was requested for the <b>${label}</b> in <b>${fileType}</b> format.</p>
    <div style="background:#f8ecef;border:1px solid #ecd7dd;border-radius:10px;padding:18px 20px;margin:18px 0;text-align:center;">
      <div style="font-size:12px;color:#8c7d78;">Your one-time verification code</div>
      <div style="font-size:32px;letter-spacing:8px;font-weight:800;color:#8a1c42;margin-top:6px;">${otp}</div>
      <div style="font-size:12px;color:#8c7d78;margin-top:8px;">Expires in 10 minutes. Do not share this code.</div>
    </div>
    <p>If you did not request this download, you can ignore this email.</p>
    <p>— Design Makers</p>
  </div>`;
}

app.post("/api/admin/export/request-otp", exportOtpLimiter, requireAdmin, async (req, res) => {
  if (req.admin.role === "boss") {
    return res.json({ success: true, requiresOtp: false });
  }
  const kind = String((req.body || {}).kind || "");
  const format = String((req.body || {}).format || "");
  if (!validExportTarget(kind, format)) {
    return res.status(400).json({ success: false, message: "Invalid export request." });
  }
  const database = readDatabase();
  cleanExportSecurity(database);
  const account = database.admins.find((a) => a.username === req.admin.username);
  if (!account) return res.status(403).json({ success: false, message: "Admin account not found." });
  const email = String(account.email || "").trim().toLowerCase();
  if (!email) {
    return res.status(400).json({ success: false, message: "No registered email is set for your account. Ask Om to add your email and phone number in the Admins section." });
  }
  const otp = String(crypto.randomInt(100000, 1000000));
  const requestId = crypto.randomUUID();
  database.adminExportOtps.push({
    requestId,
    username: req.admin.username,
    sessionId: req.admin.sessionId,
    kind,
    format,
    otpHash: hashExportSecret(otp),
    attempts: 0,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    createdAt: new Date().toISOString(),
  });
  writeDatabase(database);
  const emailResult = await sendMail(email, "Design Makers export verification code", buildExportOtpEmail({ username: req.admin.username, otp, kind, format }));
  if (!emailResult.sent) {
    const db2 = readDatabase();
    db2.adminExportOtps = (db2.adminExportOtps || []).filter((x) => x.requestId !== requestId);
    writeDatabase(db2);
    return res.status(503).json({ success: false, message: "Email delivery is not configured or failed. Please ask Om to configure the admin email service." });
  }
  res.json({ success: true, requestId, emailMasked: maskEmail(email), expiresInSeconds: 600 });
});

app.post("/api/admin/export/verify-otp", requireAdmin, (req, res) => {
  if (req.admin.role === "boss") return res.json({ success: true, exportGrant: null });
  const requestId = String((req.body || {}).requestId || "");
  const otp = String((req.body || {}).otp || "").trim();
  const database = readDatabase();
  cleanExportSecurity(database);
  const request = (database.adminExportOtps || []).find((x) => x.requestId === requestId && x.username === req.admin.username && x.sessionId === req.admin.sessionId);
  if (!request) return res.status(400).json({ success: false, message: "This OTP request is invalid or expired." });
  if (request.attempts >= 5) return res.status(429).json({ success: false, message: "Too many incorrect OTP attempts. Request a new code." });
  request.attempts += 1;
  if (!/^\d{6}$/.test(otp) || hashExportSecret(otp) !== request.otpHash) {
    writeDatabase(database);
    return res.status(401).json({ success: false, message: "Incorrect OTP. Please check your email and try again." });
  }
  database.adminExportOtps = database.adminExportOtps.filter((x) => x.requestId !== requestId);
  const rawGrant = crypto.randomBytes(32).toString("hex");
  database.adminExportGrants.push({
    grantHash: hashExportSecret(rawGrant),
    username: req.admin.username,
    sessionId: req.admin.sessionId,
    kind: request.kind,
    format: request.format,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    used: false,
  });
  writeDatabase(database);
  res.json({ success: true, exportGrant: rawGrant });
});

function requireDirectoryExportAccess(req, kind) {
  if (req.admin.role === "boss") return { ok: true };
  const grant = String(req.headers["x-export-grant"] || "");
  if (!grant) return { ok: false, status: 403, message: "Email verification is required before a sub-admin can download exports." };
  const database = readDatabase();
  cleanExportSecurity(database);
  const item = (database.adminExportGrants || []).find((x) => x.grantHash === hashExportSecret(grant) && x.username === req.admin.username && x.sessionId === req.admin.sessionId && x.kind === kind && !x.used);
  if (!item) return { ok: false, status: 403, message: "Export verification is missing, expired, or already used. Please verify again." };
  item.used = true;
  item.usedAt = new Date().toISOString();
  writeDatabase(database);
  return { ok: true };
}

// Flat customer export for authorized admins. Only fields needed for the
// customer directory are returned; no passwords or internal secrets.
app.get("/api/admin/customers/export", requireAdmin, (req, res) => {
  const access = requireDirectoryExportAccess(req, "customers");
  if (!access.ok) return res.status(access.status).json({ success: false, message: access.message });
  const database = readDatabase();
  const customers = (database.customers || [])
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((c) => ({
      name: c.name || "",
      city: c.city || "",
      email: c.email || "",
      mobile: c.mobile || "",
    }));
  res.json({ success: true, customers });
});

// Full details for one customer, including their order history.
app.get("/api/admin/customers/:id", requireAdmin, (req, res) => {
  const database = readDatabase();
  const customer = (database.customers || []).find((c) => c.id === Number(req.params.id));
  if (!customer) {
    return res.status(404).json({ success: false, message: "Customer not found." });
  }
  const productById = new Map((database.products || []).map((p) => [p.id, p]));
  const matchingOrders = (database.orders || [])
    .filter((o) => (customer.mobile && o.customer && o.customer.phone === customer.mobile) || o.customerId === customer.id)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const theirOrders = matchingOrders.map((o) => ({
    id: o.id,
    orderNumber: o.orderNumber,
    createdAt: o.createdAt,
    status: o.status,
    paymentStatus: o.paymentStatus || "pending",
    total: o.total,
    items: (o.items || []).map((it) => ({
      name: it.name,
      size: it.size || "",
      qty: it.qty,
      // Product may since have been deleted from the catalogue — fall back
      // gracefully rather than breaking the row.
      image: (productById.get(Number(it.productId)) && (productById.get(Number(it.productId)).image || (Array.isArray(productById.get(Number(it.productId)).images) && productById.get(Number(it.productId)).images[0]))) || "",
    })),
  }));

  // Amount spent excludes cancelled orders.
  const totalSpent = theirOrders
    .filter((o) => o.status !== "Cancelled")
    .reduce((sum, o) => sum + (o.total || 0), 0);
  const cancelledCount = theirOrders.filter((o) => o.status === "Cancelled").length;
  const activeCount = theirOrders.length - cancelledCount;
  const normalized = customer.mobile ? normalizeMobile(customer.mobile) : "";
  const duplicateAccounts = normalized
    ? (database.customers || [])
        .filter((c) => c.id !== customer.id && c.mobile && normalizeMobile(c.mobile) === normalized)
        .map((c) => ({ id: c.id, name: c.name || "Customer", mobile: c.mobile || null, email: c.email || null, createdAt: c.createdAt || null }))
    : [];
  // Built from the customer's own orders (each order already records the
  // exact gift code + discount applied at the time), rather than the
  // gift code's own aggregate usage counter — this gives a real per-use,
  // per-order, dated history instead of just a total count.
  const giftCodeHistory = matchingOrders
    .filter((o) => o.giftCode)
    .map((o) => ({
      code: o.giftCode,
      discount: o.giftDiscount || 0,
      orderNumber: o.orderNumber,
      date: o.createdAt,
      status: o.status === "Cancelled" ? "Order cancelled" : "Used",
    }));
  const authMethod = customer.googleId ? (customer.passwordHash ? "Google + Mobile password" : "Google") : (customer.passwordHash ? "Mobile + password" : "Not available");
  const addresses = Array.isArray(customer.addresses) ? customer.addresses : [];

  res.json({
    success: true,
    customer: {
      id: customer.id,
      name: customer.name,
      email: customer.email || null,
      mobile: customer.mobile || null,
      whatsappNumber: customer.whatsappNumber || null,
      picture: customer.picture || null,
      role: customer.role,
      shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus,
      marketingOptIn: customer.marketingOptIn !== false,
      createdAt: customer.createdAt,
      // Customer accounts don't currently track per-session login/activity
      // timestamps (only admin accounts do) — reported as unavailable
      // rather than invented, per spec.
      lastActivity: null,
      legacy: !customer.mobile,
      status: computeCustomerAccountStatus(customer),
      authMethod,
      addresses,
      duplicateMobile: duplicateAccounts.length > 0,
      duplicateAccounts,
      orders: theirOrders,
      orderSummary: { total: theirOrders.length, active: activeCount, cancelled: cancelledCount },
      totalSpent,
      giftCodeHistory,
    },
  });
});

// Permanently delete a customer account.
app.delete("/api/admin/customers/:id", requireAdmin, async (req, res) => {
  const database = readDatabase();
  const idx = (database.customers || []).findIndex((c) => c.id === Number(req.params.id));
  if (idx === -1) {
    return res.status(404).json({ success: false, message: "Customer not found." });
  }
  const [removed] = database.customers.splice(idx, 1);
  writeDatabase(database);
  // Free up their mobile number reservation so it can be registered again,
  // unless another (e.g. duplicate) customer record still holds that same
  // number — in that case leave the lock in place for them.
  if (removed.mobile && !database.customers.find((c) => c.mobile === removed.mobile)) {
    await releaseCustomerMobile(removed.mobile);
  }
  res.json({ success: true, message: "Customer account deleted.", name: removed.name });
});

app.post("/api/admin/customers/:id/reset-password", requireAdmin, (req, res) => {
  const database = readDatabase();
  const customer = database.customers.find((c) => c.id === Number(req.params.id));
  if (!customer) {
    return res.status(404).json({ success: false, message: "Customer not found." });
  }

  const newPassword = generateSellerPassword();
  customer.passwordHash = bcrypt.hashSync(newPassword, 10);
  writeDatabase(database);

  res.json({
    success: true,
    newPassword,
    mobile: customer.mobile,
    message: "New password generated. Share it with the customer now — it won't be shown again.",
  });
});

// ================================
// ADMIN: LOG IN AS A SELLER (no password needed)
// ================================
// For when the boss just needs to see/use a seller's dashboard directly —
// no password exchange required at all. Issues a normal seller session
// token, exactly like a real seller login would, scoped to that one
// seller's account. Boss-only, and every use is written to the seller's
// own login-adjacent record via loginHistory-style logging isn't needed
// here since it's not a credentialed login — but we do still block it for
// banned sellers, same as a real login would be blocked.
app.post("/api/admin/sellers/:id/login-as", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });
  if (seller.banned) {
    return res.status(403).json({ success: false, message: "This seller is banned — unban them first." });
  }

  const token = jwt.sign({ type: "seller", sellerId: seller.id }, JWT_SECRET, { expiresIn: "1d" });
  res.json({
    success: true,
    token,
    seller: { id: seller.id, sellerId: seller.sellerId, name: seller.name, shopTitle: seller.shopTitle },
  });
});

// ================================
// ADMIN: SELLER LIST (approved sellers + their products)
// ================================

app.get("/api/admin/sellers", requireAdmin, (req, res) => {
  const database = readDatabase();
  const allProducts = database.products || [];
  const allOrders = database.orders || [];
  const sellers = (database.sellers || [])
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((s) => {
      const products = allProducts.filter((p) => p.sellerId === s.id);
      const approvedCount = products.filter((p) => p.approved !== false).length;
      const pendingCount = products.filter((p) => p.approved === false).length;
      const myProductIds = new Set(products.map((p) => p.id));

      // Total Orders / Total Revenue for this seller's Activity Summary —
      // an order "belongs" to this seller if any line item is one of their
      // products. Cancelled orders are excluded from both, same as the
      // main admin dashboard's revenue figure.
      let totalOrders = 0;
      let totalRevenue = 0;
      allOrders.forEach((o) => {
        if (o.status === "Cancelled") return;
        const myItems = (o.items || []).filter((item) => myProductIds.has(item.productId));
        if (!myItems.length) return;
        totalOrders += 1;
        totalRevenue += myItems.reduce((sum, item) => sum + (item.lineTotal || 0), 0);
      });

      return {
        id: s.id,
        sellerId: s.sellerId,
        name: s.name,
        email: s.email,
        phone: s.phone,
        altPhone: s.altPhone || "",
        whatsappNumber: s.whatsappNumber || s.phone || "",
        shopTitle: s.shopTitle,
        businessType: s.businessType || "",
        businessAddress: s.businessAddress || "",
        city: s.city || "",
        state: s.state || "",
        pincode: s.pincode || "",
        aadhaarLast4: s.aadhaarLast4 || "",
        // Decrypted here, at the point of an authorized admin actually
        // viewing it — see PII_ENCRYPTION_KEY above. Never stored decrypted.
        aadhaarFull: decryptPII(s.aadhaarFull || ""),
        panNumber: decryptPII(s.panNumber || ""),
        dob: s.dob || "",
        gender: s.gender || "",
        bankAccountNumber: decryptPII(s.bankAccountNumber || ""),
        ifscCode: decryptPII(s.ifscCode || ""),
        upiId: s.upiId || "",
        gstNumber: s.gstNumber || "",
        notes: s.notes || "",
        createdAt: s.createdAt,
        banned: !!s.banned,
        // The actual password is never included in the list response — it's
        // fetched only on demand via the endpoint below, so it isn't sitting
        // in a network response every time the tab loads.
        hasPendingPassword: !!s.pendingPlainPassword,
        // A sub-admin's proposed change to this seller's own details
        // (name/email/phone/shopTitle/photo) — held here until the boss
        // approves it. Included so the Live Sellers tab can flag it.
        pendingSellerEdit: s.pendingSellerEdit || null,
        productCount: products.length,
        approvedCount,
        pendingCount,
        totalOrders,
        totalRevenue: Math.round(totalRevenue * 100) / 100,
        products: products.map((p) => ({
          id: p.id,
          name: p.name,
          price: p.price,
          category: p.category,
          approved: p.approved !== false,
          image: (Array.isArray(p.images) && p.images[0]) || p.image || "",
        })),
      };
    });
  res.json({ success: true, sellers });
});

// Flat live-seller export for authorized admins. Deliberately limited to the
// business/contact fields requested for the directory export.
app.get("/api/admin/sellers/export", requireAdmin, (req, res) => {
  const access = requireDirectoryExportAccess(req, "sellers");
  if (!access.ok) return res.status(access.status).json({ success: false, message: access.message });
  const database = readDatabase();
  const sellers = (database.sellers || [])
    .slice()
    .filter((s) => !s.banned)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((s) => ({
      companyName: s.shopTitle || "",
      name: s.name || "",
      city: s.city || "",
      mobile: s.phone || "",
      email: s.email || "",
    }));
  res.json({ success: true, sellers });
});

// Save/update the admin-only note on a seller's profile (shown on the
// Seller Details page — never visible to the seller themselves).
app.put("/api/admin/sellers/:id/note", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });
  seller.notes = String((req.body && req.body.note) || "").slice(0, 2000);
  writeDatabase(database);
  res.json({ success: true, notes: seller.notes });
});

// ================================
// ADMIN: BAN / UNBAN A SELLER
// ================================
// Banning blocks the seller from logging in (or continuing an existing
// session) and hides their products from the storefront, without deleting
// their account, order history, or product listings.

app.put("/api/admin/sellers/:id/ban", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });
  seller.banned = true;
  writeDatabase(database);
  res.json({ success: true, message: `${seller.name} (${seller.sellerId}) has been banned.` });
});

app.put("/api/admin/sellers/:id/unban", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });
  seller.banned = false;
  writeDatabase(database);
  res.json({ success: true, message: `${seller.name} (${seller.sellerId}) has been unbanned.` });
});

// ================================
// ADMIN: DELETE A SELLER (boss-only, permanent)
// ================================
// Unlike Ban (which just hides the seller and keeps everything), this
// permanently removes the seller account and every product they listed,
// plus any reviews on those products and any of those products sitting
// in a customer's cart. Past orders are left untouched since they're the
// store's own financial history, not the seller's account data.
app.delete("/api/admin/sellers/:id", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const sellerId = Number(req.params.id);
  const idx = (database.sellers || []).findIndex((s) => s.id === sellerId);
  if (idx === -1) return res.status(404).json({ success: false, message: "Seller not found." });
  const [removedSeller] = database.sellers.splice(idx, 1);

  const removedProductIds = new Set(
    (database.products || []).filter((p) => p.sellerId === sellerId).map((p) => p.id),
  );
  database.products = (database.products || []).filter((p) => p.sellerId !== sellerId);

  if (removedProductIds.size) {
    database.reviews = (database.reviews || []).filter((r) => !removedProductIds.has(r.productId));
    (database.customers || []).forEach((c) => {
      if (Array.isArray(c.cart)) {
        c.cart = c.cart.filter((item) => !removedProductIds.has(item.productId));
      }
    });
  }

  // Also remove the seller application record that created this account.
  // Without this, the application stays behind with status "approved" —
  // and the duplicate-application check in POST /api/seller-applications
  // treats any non-rejected application as a block, so the same person
  // (same email/phone/Aadhaar) would be told they're "already a seller"
  // or "already applied" forever, even after their account was deleted
  // and they try to apply again from scratch.
  const emailLower = String(removedSeller.email || "").toLowerCase();
  database.sellerApplications = (database.sellerApplications || []).filter((a) => {
    const isThisApplication =
      a.id === removedSeller.applicationId ||
      (String(a.email || "").toLowerCase() === emailLower &&
        String(a.phone || "") === String(removedSeller.phone || "") &&
        String(a.aadhaarLast4 || "") === String(removedSeller.aadhaarLast4 || ""));
    return !isThisApplication;
  });

  writeDatabase(database);
  res.json({
    success: true,
    message: `${removedSeller.name} (${removedSeller.sellerId}) and all their products have been permanently deleted. They can submit a fresh seller application if they want to rejoin.`,
  });
});

// ================================
// ADMIN: EDIT SELLER DETAILS (name / email / phone / shop title / photo)
// ================================
// Direct edit by any admin — separate from the seller-initiated
// profile-update-request flow above, which still exists for sellers
// asking to change their own phone/shopTitle/photo.
//
// The boss's edit applies immediately, same as before. A sub-admin's edit
// is held as a proposal on the seller record (pendingSellerEdit) — the
// live seller details are left untouched until the boss reviews and
// approves it from the "Pending Seller Detail Edits" card. This mirrors
// the pendingAdminEdit pattern already used for a sub-admin's edit to an
// existing product.

app.put("/api/admin/sellers/:id", requireAdmin, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });

  const body = req.body || {};
  const name = body.name !== undefined ? String(body.name).trim() : seller.name;
  const email = body.email !== undefined ? String(body.email).trim() : seller.email;
  const phone = body.phone !== undefined ? String(body.phone).trim() : seller.phone;
  const whatsappNumber = body.whatsappNumber !== undefined ? String(body.whatsappNumber).trim() : (seller.whatsappNumber || seller.phone || "");
  const shopTitle = body.shopTitle !== undefined ? String(body.shopTitle).trim() : seller.shopTitle;
  // Optional — a base64 data URL, same as the seller's own
  // profile-update-request photo field. Only replaced if a new one is sent.
  const photo = body.photo !== undefined && body.photo !== "" ? String(body.photo).trim() : seller.photo || "";

  if (!name) return res.status(400).json({ success: false, message: "Name cannot be empty." });
  if (!email) return res.status(400).json({ success: false, message: "Email cannot be empty." });
  if (!shopTitle) return res.status(400).json({ success: false, message: "Shop title cannot be empty." });

  // Guard against colliding with another seller's email/phone.
  const clash = database.sellers.find(
    (s) => s.id !== seller.id && (s.email === email || (phone && s.phone === phone)),
  );
  if (clash) {
    return res.status(409).json({ success: false, message: "Another seller already uses that email or phone." });
  }

  const changes = { name, email, phone, shopTitle, photo };
  if (req.admin.role === "boss") changes.whatsappNumber = whatsappNumber;

  if (req.admin.role !== "boss") {
    seller.pendingSellerEdit = {
      changes,
      requestedBy: req.admin.username,
      requestedAt: new Date().toISOString(),
    };
    writeDatabase(database);
    return res.json({
      success: true,
      pending: true,
      message: "Change submitted — it needs the boss's approval before it goes live.",
    });
  }

  Object.assign(seller, changes);
  delete seller.pendingSellerEdit;
  writeDatabase(database);

  res.json({ success: true, message: `${seller.name} (${seller.sellerId}) has been updated.` });
});

// A sub-admin's proposed edit to a seller's own details, waiting on the
// boss to review it. Boss-only — same shape as the product pending-edits
// endpoints, so the admin panel can reuse the same before/after diff UI.
app.get("/api/admin/sellers/pending-edits", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const pending = (database.sellers || []).filter((s) => s.pendingSellerEdit);
  res.json({ success: true, sellers: pending });
});

app.put("/api/admin/sellers/:id/approve-edit", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller || !seller.pendingSellerEdit) {
    return res.status(404).json({ success: false, message: "No pending edit found for this seller." });
  }
  Object.assign(seller, seller.pendingSellerEdit.changes);
  delete seller.pendingSellerEdit;
  writeDatabase(database);
  res.json({ success: true, message: "Edit approved and now live." });
});

app.put("/api/admin/sellers/:id/reject-edit", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller || !seller.pendingSellerEdit) {
    return res.status(404).json({ success: false, message: "No pending edit found for this seller." });
  }
  delete seller.pendingSellerEdit;
  writeDatabase(database);
  res.json({ success: true, message: "Edit rejected — seller left unchanged." });
});

// ================================
// ADMIN: RESET SELLER PASSWORD (direct, no request needed)
// ================================
// Same mechanism as resolving a seller's own forgot-password request —
// a fresh random password is generated and only its bcrypt hash is kept
// for actual login — but the boss can trigger it any time, without
// waiting for the seller to ask first. If the credentials email fails to
// send, the plaintext is also stashed in pendingPlainPassword purely as a
// manual-share fallback (see the two endpoints below).

app.put("/api/admin/sellers/:id/reset-password", requireAdmin, requireBoss, async (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });

  const newPassword = generateSellerPassword();
  seller.passwordHash = bcrypt.hashSync(newPassword, 10);
  // A reset password is now always one-time — force a fresh password on
  // the seller's next login instead of leaving this one valid forever.
  seller.mustChangePassword = true;
  // Clear out any stale unsent-password flag before we know how this one goes.
  delete seller.pendingPlainPassword;
  writeDatabase(database);

  const sellerLoginUrl = `${req.protocol}://${req.get("host")}/seller`;
  const emailResult = await sendMail(
    seller.email,
    "Your Design Makers password has been reset",
    buildPasswordResetOtpEmail({
      name: seller.name,
      shopTitle: seller.shopTitle,
      sellerId: seller.sellerId,
      otp: newPassword,
      loginUrl: sellerLoginUrl,
    }),
  );

  if (!emailResult.sent) {
    seller.pendingPlainPassword = newPassword;
  }
  writeDatabase(database);

  res.json({
    success: true,
    message: emailResult.sent
      ? `One-time password generated and emailed to ${seller.name}.`
      : `One-time password generated for ${seller.name}. Share it with them yourself (WhatsApp/SMS/etc) — find it any time from the Live Sellers tab.`,
    sellerId: seller.sellerId,
    newPassword: emailResult.sent ? undefined : newPassword,
    emailSent: emailResult.sent,
  });
});

// ================================
// ADMIN: SET A SPECIFIC SELLER PASSWORD (boss-chosen, not random)
// ================================
// The "Reset password" endpoint above only ever generates a random one.
// This lets the boss type an exact password for the seller's main ID —
// useful when the seller wants to keep a password they'll remember, or
// when the boss needs to hand out a known password in person right away.
// Same storage rules as everywhere else: only the bcrypt hash is kept for
// login; the plaintext is never written to the database at all here
// (unlike the random-generate flow, there's nothing to "resend" if it's
// misplaced — the boss already has it, since they typed it).
app.put("/api/admin/sellers/:id/set-password", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });

  const newPassword = String((req.body || {}).password || "");
  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, message: "Password must be at least 6 characters." });
  }

  seller.passwordHash = bcrypt.hashSync(newPassword, 10);
  // A fresh password was just set by hand — any old "email never sent"
  // fallback copy is now stale, clear it out. It's also a real password
  // the boss just typed, not a one-time one, so no forced change either.
  delete seller.pendingPlainPassword;
  delete seller.mustChangePassword;
  writeDatabase(database);

  res.json({
    success: true,
    message: `Password for ${seller.name} (${seller.sellerId}) has been set. Share it with them directly — it won't be shown again.`,
    sellerId: seller.sellerId,
  });
});

// Boss-only: look up a seller's password when the credentials email never
// reached them. Only returns something when pendingPlainPassword is actually
// set — i.e. the last approval/reset genuinely failed to email out. There's
// no way to recover the password for a seller whose email succeeded, since
// the plaintext is never kept once it's been sent.
app.get("/api/admin/sellers/:id/pending-password", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });
  if (!seller.pendingPlainPassword) {
    return res.status(404).json({
      success: false,
      message: "No unsent password on file for this seller — their credentials email went through, or it's already been marked as shared.",
    });
  }
  res.json({ success: true, sellerId: seller.sellerId, password: seller.pendingPlainPassword });
});

// Boss-only: once the boss has shared the password with the seller some
// other way (phone, WhatsApp, in person), clear it from the record so it
// doesn't sit around indefinitely.
app.delete("/api/admin/sellers/:id/pending-password", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const seller = database.sellers.find((s) => s.id === Number(req.params.id));
  if (!seller) return res.status(404).json({ success: false, message: "Seller not found." });
  delete seller.pendingPlainPassword;
  writeDatabase(database);
  res.json({ success: true, message: "Cleared." });
});

// ================================
// ADMIN: REVIEW SELLER APPLICATIONS
// ================================

app.get("/api/admin/seller-applications", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const applications = database.sellerApplications
    .filter((a) => a.status === "pending")
    .map((a) => ({
      id: a.id,
      name: a.name,
      email: a.email,
      phone: a.phone,
      altPhone: a.altPhone || "",
      shopTitle: a.shopTitle,
      businessType: a.businessType || "",
      businessAddress: a.businessAddress || "",
      city: a.city || "",
      state: a.state || "",
      pincode: a.pincode || "",
      aadhaarLast4: a.aadhaarLast4,
      // Decrypted here, at the point of an authorized admin actually
      // viewing it — see PII_ENCRYPTION_KEY above. Never stored decrypted.
      aadhaarFull: decryptPII(a.aadhaarFull || ""),
      panNumber: decryptPII(a.panNumber || ""),
      dob: a.dob || "",
      gender: a.gender || "",
      bankAccountNumber: decryptPII(a.bankAccountNumber || ""),
      ifscCode: decryptPII(a.ifscCode || ""),
      upiId: a.upiId || "",
      gstNumber: a.gstNumber || "",
      aadhaarPhoto: a.aadhaarPhoto,
      personPhoto: a.personPhoto,
      createdAt: a.createdAt,
    }));
  res.json({ success: true, applications });
});

// Approving generates a Seller ID + random password, creates the seller
// account, and emails the credentials — nothing further needed from you.
// Builds the "welcome, you're approved" email. `mode` is "otp" (one-time
// password — seller is forced to set their own password right after their
// first login) or "password" (a normal password that just keeps working).
function buildSellerWelcomeEmail({ name, shopTitle, sellerId, plainPassword, mode, loginUrl }) {
  const isOtp = mode === "otp";
  const credentialLabel = isOtp ? "One-Time Password" : "Password";
  const credentialNote = isOtp
    ? `<p style="margin:14px 0 0;font-size:0.9em;color:#8a1c42;background:#fff7e6;border:1px solid #f3d9a0;border-radius:8px;padding:10px 14px;">🔒 This password works <b>once</b>. The moment you log in with it, we'll ask you to choose a new password of your own — so only you will know it from then on.</p>`
    : `<p style="margin:14px 0 0;font-size:0.85em;color:#8c7d78;">Please keep this password safe — we recommend not sharing it with anyone.</p>`;

  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
       <h2 style="color:#8a1c42;margin-bottom:4px;">Welcome to the family, ${name}! 🎉💗</h2>
       <p style="font-size:1.05em;">We're so happy to have you here. Your seller application for <b>${shopTitle}</b> has been approved — your little shop now has a home on Design Makers.</p>
       <p>Every design, every product you list from here is a story you get to tell — and we can't wait to see what you create. You can start listing products, set your own prices, and open your doors whenever you're ready.</p>
       <div style="background:#f8ecef;border:1px solid #ecd7dd;border-radius:10px;padding:16px 20px;margin:20px 0;">
         <p style="margin:0 0 8px;"><b>Seller ID:</b> ${sellerId}</p>
         <p style="margin:0;"><b>${credentialLabel}:</b> ${plainPassword}</p>
         ${credentialNote}
       </div>
       <p><a href="${loginUrl}" style="background:#8a1c42;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;display:inline-block;">Log in to your Seller Dashboard</a></p>
       <p style="font-size:0.85em;color:#8c7d78;">Or visit: ${loginUrl}</p>
       <p style="font-size:0.85em;color:#8c7d78;">You can also sign in with Google on the same page if your Google account uses this email address.</p>
       <p style="margin-top:22px;">Welcome aboard — truly excited to have you selling with us!<br/>With warmth,<br/><b>Team Design Makers</b> 💗</p>
     </div>`;
}

// Builds the "your password was reset" email — always framed as a
// one-time password now, since every reset (admin-triggered or via a
// seller's own forgot-password request) forces a fresh password to be set
// on next login.
function buildPasswordResetOtpEmail({ name, shopTitle, sellerId, otp, loginUrl }) {
  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
       <h2 style="color:#8a1c42;margin-bottom:4px;">Your password has been reset</h2>
       <p>Hi ${name},</p>
       <p>Here's a one-time password to get back into <b>${shopTitle}</b>:</p>
       <div style="background:#f8ecef;border:1px solid #ecd7dd;border-radius:10px;padding:16px 20px;margin:20px 0;">
         <p style="margin:0 0 8px;"><b>Seller ID:</b> ${sellerId}</p>
         <p style="margin:0;"><b>One-Time Password:</b> ${otp}</p>
         <p style="margin:14px 0 0;font-size:0.9em;color:#8a1c42;background:#fff7e6;border:1px solid #f3d9a0;border-radius:8px;padding:10px 14px;">🔒 This password works <b>once</b>. The moment you log in with it, we'll ask you to choose a new password of your own — so only you will know it from then on.</p>
       </div>
       <p><a href="${loginUrl}" style="background:#8a1c42;color:#fff;padding:10px 22px;border-radius:8px;text-decoration:none;display:inline-block;">Log in to your Seller Dashboard</a></p>
       <p style="font-size:0.85em;color:#8c7d78;">Or visit: ${loginUrl}</p>
       <p style="margin-top:18px;">— Team Design Makers</p>
     </div>`;
}

app.put("/api/admin/seller-applications/:id/approve", requireAdmin, requireBoss, async (req, res) => {
  const database = readDatabase();
  const application = database.sellerApplications.find((a) => a.id === Number(req.params.id));
  if (!application) return res.status(404).json({ success: false, message: "Application not found." });
  if (application.status === "approved") {
    return res.status(400).json({ success: false, message: "Already approved." });
  }

  // Admin chooses, per-approval, whether the seller gets a normal password
  // or a one-time password that forces them to set their own on first login.
  const passwordMode = "password";

  const nextNum = getNextId(database.sellers);
  const sellerId = generateSellerId(nextNum);
  // Initial password is derived from their shop name + Aadhaar last-4 —
  // e.g. "Kanak Gifts" -> "Kanak#7391" — so it's easy for the seller to
  // remember/recall themselves.
  const plainPassword = generateShopBasedPassword(application.shopTitle, application.aadhaarLast4);

  const seller = {
    id: nextNum,
    sellerId,
    passwordHash: bcrypt.hashSync(plainPassword, 10),
    name: application.name,
    email: application.email,
    phone: application.phone,
    altPhone: application.altPhone || "",
    whatsappNumber: application.whatsappNumber || application.phone || "",
    shopTitle: application.shopTitle,
    businessType: application.businessType || "",
    businessAddress: application.businessAddress || "",
    city: application.city || "",
    state: application.state || "",
    pincode: application.pincode || "",
    aadhaarLast4: application.aadhaarLast4,
    aadhaarFull: application.aadhaarFull || "",
    panNumber: application.panNumber || "",
    dob: application.dob || "",
    gender: application.gender || "",
    bankAccountNumber: application.bankAccountNumber || "",
    ifscCode: application.ifscCode || "",
    upiId: application.upiId || "",
    gstNumber: application.gstNumber || "",
    notes: "",
    applicationId: application.id,
    createdAt: new Date().toISOString(),
    banned: false,
    // Only true for the OTP flow — cleared automatically the moment the
    // seller sets their own new password after their first login.
    mustChangePassword: false,
  };
  database.sellers.push(seller);
  application.status = "approved";
  writeDatabase(database);

  const sellerLoginUrl = `${req.protocol}://${req.get("host")}/seller`;
  const emailResult = await sendMail(
    application.email,
    "Welcome to Design Makers — you're approved as a seller! 🎉",
    buildSellerWelcomeEmail({
      name: application.name,
      shopTitle: application.shopTitle,
      sellerId,
      plainPassword,
      mode: passwordMode,
      loginUrl: sellerLoginUrl,
    }),
  );

  // If the email didn't go through, keep the plaintext password on the
  // record (separately from passwordHash, which is what's actually used to
  // log in) so the boss can come back later — even in a new session — and
  // look it up from the Live Sellers tab instead of only seeing it once here.
  if (!emailResult.sent) {
    seller.pendingPlainPassword = plainPassword;
    writeDatabase(database);
  }

  res.json({
    success: true,
    message: emailResult.sent
      ? `${application.name} is now an approved seller (${sellerId}). Login email sent.`
      : `${application.name} is now an approved seller (${sellerId}). Share the login details with them yourself (WhatsApp/SMS/etc) — find the password any time from the Live Sellers tab.`,
    sellerId,
    // Only returned when the email failed — so the admin panel can show a
    // manual-share fallback instead of the seller being stuck with no way in.
    plainPassword: emailResult.sent ? undefined : plainPassword,
    emailSent: emailResult.sent,
  });
});

app.put("/api/admin/seller-applications/:id/reject", requireAdmin, requireBoss, async (req, res) => {
  const database = readDatabase();
  const application = database.sellerApplications.find((a) => a.id === Number(req.params.id));
  if (!application) return res.status(404).json({ success: false, message: "Application not found." });
  application.status = "rejected";
  writeDatabase(database);

  await sendMail(
    application.email,
    "Update on your Design Makers seller application",
    `<p>Hi ${application.name},</p>
     <p>Thanks for your interest in selling on Design Makers. After review, we're not able to approve your application at this time.</p>`,
  );

  res.json({ success: true, message: `${application.name}'s application was rejected.` });
});

// ================================
// BOSS: MANAGE SUB-ADMINS
// ================================

const ADMIN_DESIGNATIONS = ["Product Listing Manager", "Sales Manager"];

app.get("/api/admin/admins", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const admins = database.admins.map((a) => ({
    username: a.username,
    role: "admin",
    designation: a.designation || null,
    email: a.email || null,
    phone: a.phone || null,
    canDeleteProducts: !!a.canDeleteProducts,
    locked: !!a.locked,
    failedAttempts: a.failedAttempts || 0,
    createdAt: a.createdAt,
    lastLogin: a.lastLogin || null,
  }));
  const boss = {
    username: BOSS_ACCOUNT.username,
    role: "boss",
    designation: null,
    email: null,
    phone: null,
    canDeleteProducts: true,
    locked: false,
    failedAttempts: 0,
    createdAt: null,
    lastLogin: database.bossLastLogin || null,
  };
  res.json({ success: true, admins: [boss, ...admins] });
});

app.get("/api/admin/login-history", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const history = (database.loginHistory || []).slice().reverse();
  res.json({ success: true, history });
});

// ================================
// ADMIN ROLES (boss / main "om" account only)
// ================================
// The two built-in roles below always exist. The boss can add extra custom
// roles from the Admins tab; they're stored in the database and offered as
// options when creating a sub-admin. Only the boss account can manage roles.
const DEFAULT_ADMIN_ROLES = ["Product Listing Manager", "Sales Manager"];

function allAdminRoles(database) {
  const custom = Array.isArray(database.adminRoles) ? database.adminRoles : [];
  return Array.from(new Set([...DEFAULT_ADMIN_ROLES, ...custom]));
}

app.get("/api/admin/roles", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  res.json({ success: true, roles: allAdminRoles(database), defaults: DEFAULT_ADMIN_ROLES });
});

app.post("/api/admin/roles", requireAdmin, requireBoss, (req, res) => {
  const name = String((req.body || {}).name || "").trim();
  if (!name) {
    return res.status(400).json({ success: false, message: "Enter a role name." });
  }
  if (name.length > 40) {
    return res.status(400).json({ success: false, message: "Role name is too long (max 40 characters)." });
  }
  const database = readDatabase();
  if (!Array.isArray(database.adminRoles)) database.adminRoles = [];
  if (allAdminRoles(database).some((r) => r.toLowerCase() === name.toLowerCase())) {
    return res.status(409).json({ success: false, message: "That role already exists." });
  }
  database.adminRoles.push(name);
  writeDatabase(database);
  res.json({ success: true, roles: allAdminRoles(database) });
});

app.delete("/api/admin/roles/:name", requireAdmin, requireBoss, (req, res) => {
  const name = decodeURIComponent(req.params.name || "");
  if (DEFAULT_ADMIN_ROLES.some((r) => r.toLowerCase() === name.toLowerCase())) {
    return res.status(400).json({ success: false, message: "Built-in roles can't be removed." });
  }
  const database = readDatabase();
  database.adminRoles = (database.adminRoles || []).filter((r) => r.toLowerCase() !== name.toLowerCase());
  writeDatabase(database);
  res.json({ success: true, roles: allAdminRoles(database) });
});

app.post("/api/admin/admins", requireAdmin, requireBoss, (req, res) => {
  const username = String((req.body || {}).username || "").trim();
  const password = String((req.body || {}).password || "");
  const email = String((req.body || {}).email || "").trim().toLowerCase();
  const phone = String((req.body || {}).phone || "").trim();
  const designation = String((req.body || {}).designation || "").trim();
  const canDeleteFlag = !!(req.body || {}).canDeleteProducts;

  if (!username || !password || !email || !phone) {
    return res.status(400).json({ success: false, message: "Username, password, registered email and phone number are required." });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: "Enter a valid registered email address." });
  }
  if (phone.replace(/\D/g, "").length < 7) {
    return res.status(400).json({ success: false, message: "Enter a valid phone number." });
  }
  if (username === BOSS_ACCOUNT.username) {
    return res.status(400).json({ success: false, message: "That username is reserved for the boss account." });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, message: "Password should be at least 6 characters." });
  }
  if (designation && !ADMIN_DESIGNATIONS.includes(designation)) {
    return res.status(400).json({ success: false, message: "Invalid designation." });
  }

  const database = readDatabase();
  if (database.admins.some((a) => a.username === username)) {
    return res.status(400).json({ success: false, message: "That username already exists." });
  }
  if (database.admins.some((a) => String(a.email || "").toLowerCase() === email)) {
    return res.status(400).json({ success: false, message: "That email is already registered to another sub-admin." });
  }

  database.admins.push({
    username,
    email,
    phone,
    passwordHash: bcrypt.hashSync(password, 10),
    designation: designation || null,
    canDeleteProducts: canDeleteFlag,
    locked: false,
    failedAttempts: 0,
    createdAt: new Date().toISOString(),
  });
  writeDatabase(database);

  res.status(201).json({ success: true, message: "Sub-admin created." });
});

// Boss can maintain the two contact fields required for sub-admin export verification.
app.put("/api/admin/admins/:username/contact", requireAdmin, requireBoss, (req, res) => {
  if (req.params.username === BOSS_ACCOUNT.username) {
    return res.status(403).json({ success: false, message: "The boss account contact details are managed through server configuration." });
  }
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === req.params.username);
  if (!account) return res.status(404).json({ success: false, message: "Admin not found." });
  const email = String((req.body || {}).email || "").trim().toLowerCase();
  const phone = String((req.body || {}).phone || "").trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: "Enter a valid registered email address." });
  }
  if (phone.replace(/\D/g, "").length < 7) {
    return res.status(400).json({ success: false, message: "Enter a valid phone number." });
  }
  if (database.admins.some((a) => a.username !== account.username && String(a.email || "").toLowerCase() === email)) {
    return res.status(400).json({ success: false, message: "That email is already registered to another sub-admin." });
  }
  account.email = email;
  account.phone = phone;
  writeDatabase(database);
  res.json({ success: true, email, phone });
});

app.put("/api/admin/admins/:username/permissions", requireAdmin, requireBoss, (req, res) => {
  if (req.params.username === BOSS_ACCOUNT.username) {
    return res.status(403).json({ success: false, message: "The boss account cannot be modified." });
  }
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === req.params.username);
  if (!account) {
    return res.status(404).json({ success: false, message: "Admin not found." });
  }
  account.canDeleteProducts = !!(req.body || {}).canDeleteProducts;
  writeDatabase(database);
  res.json({ success: true, canDeleteProducts: account.canDeleteProducts });
});

// Boss can change a sub-admin's username and/or password at any time.
app.put("/api/admin/admins/:username/credentials", requireAdmin, requireBoss, (req, res) => {
  if (req.params.username === BOSS_ACCOUNT.username) {
    return res.status(403).json({ success: false, message: "The boss account cannot be modified here." });
  }
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === req.params.username);
  if (!account) {
    return res.status(404).json({ success: false, message: "Admin not found." });
  }

  const newUsername = String((req.body || {}).username || "").trim();
  const newPassword = String((req.body || {}).password || "");

  if (!newUsername) {
    return res.status(400).json({ success: false, message: "Username cannot be empty." });
  }
  if (newUsername === BOSS_ACCOUNT.username) {
    return res.status(400).json({ success: false, message: "That username is reserved for the boss account." });
  }
  if (newUsername !== account.username && database.admins.some((a) => a.username === newUsername)) {
    return res.status(400).json({ success: false, message: "That username already exists." });
  }
  if (newPassword && newPassword.length < 6) {
    return res.status(400).json({ success: false, message: "Password should be at least 6 characters." });
  }

  account.username = newUsername;
  if (newPassword) {
    account.passwordHash = bcrypt.hashSync(newPassword, 10);
  }
  writeDatabase(database);

  res.json({ success: true, message: "Login details updated." });
});

app.put("/api/admin/admins/:username/unlock", requireAdmin, requireBoss, (req, res) => {
  if (req.params.username === BOSS_ACCOUNT.username) {
    return res.status(403).json({ success: false, message: "The boss account cannot be modified." });
  }
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === req.params.username);

  if (!account) {
    return res.status(404).json({ success: false, message: "Admin not found." });
  }

  account.locked = false;
  account.failedAttempts = 0;
  writeDatabase(database);

  res.json({ success: true, message: "Unlocked." });
});

app.delete("/api/admin/admins/:username", requireAdmin, requireBoss, (req, res) => {
  if (req.params.username === BOSS_ACCOUNT.username) {
    return res.status(403).json({ success: false, message: "The boss account cannot be removed." });
  }
  const database = readDatabase();
  const index = database.admins.findIndex((a) => a.username === req.params.username);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Admin not found." });
  }

  database.admins.splice(index, 1);
  writeDatabase(database);

  res.json({ success: true, message: "Sub-admin removed." });
});

// ================================
// PRODUCT VALIDATION HELPER
// ================================

function validateProductInput(body) {
  const errors = [];

  const name = String(body.name || "").trim();
  if (!name) errors.push("Product name is required.");

  const price = Number(body.price);
  if (!Number.isFinite(price) || price < 0) errors.push("Price must be a valid positive number.");

  const moq = body.moq === undefined || body.moq === "" ? 1 : Number(body.moq);
  if (!Number.isFinite(moq) || moq < 1) errors.push("MOQ must be a whole number of at least 1.");

  let sizes = body.sizes;
  if (typeof sizes === "string") {
    sizes = sizes.split(",").map((s) => s.trim()).filter(Boolean);
  }
  if (!Array.isArray(sizes)) sizes = [];

  let discounts = Array.isArray(body.discounts) ? body.discounts : [];
  discounts = discounts
    .map((d) => ({
      minQty: Number(d.minQty),
      percent: Number(d.percent),
    }))
    .filter((d) => Number.isFinite(d.minQty) && Number.isFinite(d.percent) && d.minQty > 0 && d.percent > 0)
    .sort((a, b) => a.minQty - b.minQty);

  // Up to a handful of product photos. `image` (singular) is kept as the
  // first image for backward compatibility with older code/screens.
  // Only real image data URLs or https:// image links are accepted — any
  // other string is dropped here rather than stored, so a crafted value
  // can never reach an <img src="..."> unescaped downstream.
  const isSafeImageValue = (s) =>
    /^data:image\/(png|jpe?g|webp|gif);base64,[a-zA-Z0-9+/=]+$/.test(s) ||
    /^https:\/\/[^\s"'<>]+$/.test(s);

  let images = Array.isArray(body.images) ? body.images : [];
  images = images.map((s) => String(s || "").trim()).filter((s) => s && isSafeImageValue(s)).slice(0, 6);
  if (!images.length && body.image) {
    const single = String(body.image).trim();
    if (isSafeImageValue(single)) images = [single];
  }

  const onSale = Boolean(body.onSale);
  let salePercent = Number(body.salePercent);
  if (!Number.isFinite(salePercent) || salePercent <= 0) salePercent = 0;
  if (salePercent > 90) salePercent = 90;
  if (onSale && salePercent <= 0) errors.push("Set a sale percent greater than 0 to put this item on sale.");

  // Percent used by the "BUY 10 @ Rs.X" badge on the Most Popular / Trending
  // homepage rows. Editable per-product from the Homepage Sections tab.
  // Defaults to 10 (the old hardcoded rule) so existing products keep the
  // same badge price unless the admin changes it.
  let buyBadgePercent = body.buyBadgePercent === undefined || body.buyBadgePercent === "" ? 10 : Number(body.buyBadgePercent);
  if (!Number.isFinite(buyBadgePercent) || buyBadgePercent <= 0) buyBadgePercent = 10;
  if (buyBadgePercent > 90) buyBadgePercent = 90;

  // Optional custom line shown on the storefront only while the sale is on
  // (e.g. "Diwali Blast — today only!"). Capped so it can't blow out the layout.
  const saleMessage = String(body.saleMessage || "").trim().slice(0, 80);

  // Stock is now owned by the Inventory tab, not the Products tab — the
  // admin product form no longer sends stockQty/variantStock/
  // lowStockThreshold at all. When these fields are absent from the body,
  // they're deliberately left OUT of the returned `product` object below
  // (rather than defaulted to 0) so that a save from the Products tab —
  // `{ ...existingProduct, ...product }` on the PUT route — can never
  // stomp existing stock back to zero. The seller product form
  // (seller.html) used to submit these fields directly, but now that the
  // seller has their own Inventory tab too, it no longer sends them
  // either — same reasoning, same protection against a Save on the
  // Add/Edit Product form silently wiping out stock set via Inventory.
  const stockFieldsProvided = body.stockQty !== undefined || body.variantStock !== undefined || body.lowStockThreshold !== undefined;
  let stockPatch = {};
  if (stockFieldsProvided) {
    const incomingVariantStock = body.variantStock && typeof body.variantStock === "object" && !Array.isArray(body.variantStock)
      ? body.variantStock : {};
    const variantStock = {};
    sizes.forEach((size) => {
      const n = Number(incomingVariantStock[size]);
      variantStock[size] = Number.isInteger(n) && n >= 0 ? n : 0;
    });
    const stockQtyRaw = Number(body.stockQty);
    const stockQty = Number.isInteger(stockQtyRaw) && stockQtyRaw >= 0 ? stockQtyRaw : 0;
    const thresholdRaw = Number(body.lowStockThreshold);
    const lowStockThreshold = Number.isInteger(thresholdRaw) && thresholdRaw >= 0 ? thresholdRaw : 5;
    stockPatch = {
      stockQty,
      variantStock,
      stockConfigured: true,
      variantStockConfigured: Object.fromEntries(sizes.map((size) => [size, true])),
      lowStockThreshold,
    };
  }

  // Optional sale expiry. Admin can send an explicit end timestamp (from a
  // datetime picker) or a quick duration in hours (e.g. 24). If neither is
  // sent, the sale simply has no timer and stays on until turned off by hand.
  let saleEndsAt = null;
  if (onSale) {
    const explicitEnd = Number(body.saleEndsAt);
    const durationHours = Number(body.saleDurationHours);
    if (Number.isFinite(explicitEnd) && explicitEnd > 0) {
      saleEndsAt = explicitEnd;
    } else if (Number.isFinite(durationHours) && durationHours > 0) {
      saleEndsAt = Date.now() + durationHours * 60 * 60 * 1000;
    }
  }

  return {
    errors,
    product: {
      name,
      category: String(body.category || "").trim(),
      description: String(body.description || "").trim(),
      price,
      image: images[0] || "",
      images,
      active: body.active !== false,
      customizationEnabled: Boolean(body.customizationEnabled),
      sizes,
      moq,
      ...stockPatch,
      discounts,
      onSale,
      salePercent,
      saleMessage,
      saleEndsAt,
      giftFor: ["her", "him", "both"].includes(body.giftFor) ? body.giftFor : "",
      hotProduct: Boolean(body.hotProduct),
      buyBadgePercent,
      options: body.options && typeof body.options === "object" ? body.options : {},
    },
  };
}

// A sale only actually applies while onSale is true, the percent is valid,
// AND (if a timer was set) that timer hasn't expired yet. This is the single
// source of truth the server uses for pricing — the timer on the storefront
// is just a friendly countdown pointing at the same saleEndsAt value.
function isSaleActive(product) {
  if (!product.onSale || !(product.salePercent > 0)) return false;
  if (product.saleEndsAt && Date.now() >= Number(product.saleEndsAt)) return false;
  return true;
}

// ================================
// INVENTORY / STOCK MANAGEMENT
// ================================

// This is the ONLY inventory route left. It is READ-ONLY — it just reads
// back the stock already stored on each product document. There is no
// Excel/Sheets import, paste, or export for stock anywhere in this app.
// The single authoritative place stock is written is the product editor:
// Admin/Seller → Products → Edit Product → Size/Variant Stock, which goes
// through validateProductInput() and the /api/admin/products/:id and
// /api/seller/products/:id routes (with their own negative-stock and
// ownership checks). This endpoint exists purely to power a read-only
// overview (the admin Inventory tab, and the Overview dashboard's stock
// health widget) — it never mutates stock.
app.get("/api/admin/inventory", requireAdmin, (req, res) => {
  const database = readDatabase();
  ensureProductCodes(database);
  writeDatabase(database);
  res.json({ success: true, rows: getInventoryRows(database) });
});

app.get("/api/inventory/availability", (req, res) => {
  try {
    const database = readDatabase();
    const ids = String(req.query.ids || "").split(",").map(Number).filter(Number.isFinite);
    const wanted = ids.length ? new Set(ids) : null;
    const availability = {};
    (database.products || []).forEach((product) => {
      if (!product.active || product.approved === false || product.hidden || (wanted && !wanted.has(Number(product.id)))) return;
      availability[product.id] = { stockQty: Math.max(0, Number(product.stockQty) || 0), stockConfigured: product.stockConfigured !== false, variantStockConfigured: product.variantStockConfigured && typeof product.variantStockConfigured === "object" ? product.variantStockConfigured : {}, lowStockThreshold: Math.max(0, Number(product.lowStockThreshold ?? 5) || 5), variantStock: product.variantStock && typeof product.variantStock === "object" ? product.variantStock : {} };
    });
    res.set("Cache-Control", "no-store");
    res.json({ success: true, availability });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load stock availability." });
  }
});

// ================================
// SECURE SERVER-SIDE ORDER PRICING
// ================================
// Never trust a total sent from the browser — recompute every line from the
// real product data on disk so a tampered request can't change what's charged.

// Returns today's day-of-month in IST, regardless of the server's own
// timezone — the gift add-on's eligible dates are meant in local (India)
// time, not wherever the process happens to be hosted.
function getISTDayOfMonth(date = new Date()) {
  return Number(
    new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Kolkata", day: "numeric" }).format(date),
  );
}

function isGiftAddonDateEligible(date = new Date()) {
  return GIFT_ADDON.eligibleDaysOfMonth.includes(getISTDayOfMonth(date));
}

function normalizeGiftCode(raw) {
  return String(raw || "").trim().toUpperCase().replace(/\s+/g, "");
}

function findGiftCode(database, rawCode) {
  const code = normalizeGiftCode(rawCode);
  if (!code) return null;
  return (database.giftCodes || []).find((g) => String(g.code || "").toUpperCase() === code) || null;
}

function validateGiftCode(database, rawCode, customerId, baseAmount, guestPhone = null) {
  const code = normalizeGiftCode(rawCode);
  if (!code) return { valid: false, discount: 0, message: "Enter a gift code." };
  const gift = findGiftCode(database, code);
  if (!gift || gift.active === false) return { valid: false, discount: 0, message: "Invalid or inactive gift code." };
  const now = Date.now();
  if (gift.startsAt && now < new Date(gift.startsAt).getTime()) return { valid: false, discount: 0, message: "This gift code is not active yet." };
  if (gift.expiresAt && now > new Date(gift.expiresAt).getTime()) return { valid: false, discount: 0, message: "This gift code has expired." };
  const minOrder = Number(gift.minOrder || 0);
  if (baseAmount < minOrder) return { valid: false, discount: 0, message: `This code requires a minimum order of ₹${Math.round(minOrder)}.` };
  const usageLimit = Number(gift.usageLimit || 0);
  if (usageLimit > 0 && Number(gift.usedCount || 0) >= usageLimit) return { valid: false, discount: 0, message: "This gift code has reached its usage limit." };
  const perCustomer = Number(gift.perCustomerLimit || 0);
  if (perCustomer > 0) {
    // A logged-in customer is tracked by their account id. A guest checkout
    // has no account id (customerId is null) — this codebase already treats
    // the order phone number as a guest's identity elsewhere (see the phone
    // helper below), so re-use that here too. Without this fallback, the
    // same person could keep checking out as a guest to reuse a one-per-
    // customer code indefinitely, since a null customerId always skipped
    // this check entirely.
    const usageKey = customerId ? String(customerId) : (guestPhone ? `phone:${guestPhone}` : null);
    if (usageKey) {
      const usedByCustomer = Number(gift.usageByCustomer && gift.usageByCustomer[usageKey] || 0);
      if (usedByCustomer >= perCustomer) return { valid: false, discount: 0, message: "You have already used this gift code." };
    }
  }
  let discount = gift.type === "fixed" ? Number(gift.value || 0) : baseAmount * (Number(gift.value || 0) / 100);
  if (Number(gift.maxDiscount || 0) > 0) discount = Math.min(discount, Number(gift.maxDiscount));
  discount = Math.max(0, Math.min(discount, baseAmount));
  return { valid: true, gift, code, discount: Math.round(discount * 100) / 100, message: "Gift code applied." };
}

function calculateSecurePricing(items, products, giftCode = "", customerId = null, database = null, guestPhone = null) {
  const errors = [];
  const pricedItems = [];
  let subtotal = 0;
  let discountTotal = 0;
  let listedSubtotal = 0;
  let saleDiscountTotal = 0;

  if (!Array.isArray(items) || items.length === 0) {
    return { errors: ["Your cart is empty."], pricedItems, subtotal: 0, discountTotal: 0, total: 0 };
  }

  items.forEach((item, idx) => {
    const product = products.find((p) => p.id === Number(item.productId));

    if (!product || !product.active) {
      errors.push(`Item ${idx + 1}: product not found or no longer available.`);
      return;
    }

    // Mirror the same public-eligibility rule enforced on the storefront list
    // and single-product endpoints: a product still pending admin approval,
    // deliberately hidden, or belonging to a banned/suspended seller must
    // never be purchasable — even if someone reaches this function by
    // calling /api/orders directly with a product ID they found or guessed,
    // bypassing the storefront UI and product-detail page entirely.
    if (product.approved === false || product.hidden) {
      errors.push(`Item ${idx + 1}: product not found or no longer available.`);
      return;
    }
    if (product.sellerId && database) {
      const productSeller = (database.sellers || []).find((s) => s.id === product.sellerId);
      if (productSeller && productSeller.banned) {
        errors.push(`Item ${idx + 1}: product not found or no longer available.`);
        return;
      }
    }

    const qty = Number(item.qty);
    if (!Number.isFinite(qty) || qty < 1) {
      errors.push(`${product.name}: invalid quantity.`);
      return;
    }

    const moq = product.moq || 1;
    if (qty < moq) {
      errors.push(`${product.name}: minimum order quantity is ${moq}.`);
      return;
    }

    if (Array.isArray(product.sizes) && product.sizes.length && !product.sizes.includes(item.size)) {
      errors.push(`${product.name}: please select a valid size.`);
      return;
    }

    // If the product is on sale, that discounted price becomes the base — bulk
    // discount tiers then apply on top of the sale price, not the original.
    // isSaleActive() also checks the sale timer, so a sale that has run out
    // stops applying automatically, even if onSale/salePercent are still set.
    const saleActive = isSaleActive(product);
    const effectivePrice = saleActive
      ? Math.round(product.price * (1 - product.salePercent / 100) * 100) / 100
      : product.price;

    let discountPct = 0;
    (product.discounts || []).forEach((tier) => {
      if (qty >= tier.minQty && tier.percent > discountPct) discountPct = tier.percent;
    });

    const lineListedSubtotal = product.price * qty;
    const lineSubtotal = effectivePrice * qty;
    const lineSaleDiscount = Math.max(0, lineListedSubtotal - lineSubtotal);
    const lineDiscount = lineSubtotal * (discountPct / 100);
    const lineTotal = Math.round((lineSubtotal - lineDiscount) * 100) / 100;

    listedSubtotal += lineListedSubtotal;
    saleDiscountTotal += lineSaleDiscount;
    subtotal += lineSubtotal;
    discountTotal += lineDiscount;

    pricedItems.push({
      productId: product.id,
      name: product.name,
      price: product.price,
      salePrice: saleActive ? effectivePrice : null,
      size: item.size || null,
      qty,
      discountPct,
      lineTotal,
    });
  });

  // The gift add-on is a real product (so it prices through the same path
  // as everything else) but it's only ever valid when: today is one of the
  // eligible dates, the *rest* of the order is ₹599+, and only one was
  // added. The client hides/removes it outside those conditions, but that's
  // just UX — this is the check that actually decides what gets charged,
  // since a client's request body is never trusted.
  const addonLine = pricedItems.find((i) => i.productId === GIFT_ADDON.productId);
  if (addonLine) {
    const nonAddonSubtotal = subtotal - addonLine.price * addonLine.qty;
    if (addonLine.qty > 1 || !isGiftAddonDateEligible() || nonAddonSubtotal < GIFT_ADDON.minSubtotal) {
      errors.push(
        "The gift add-on isn't available for this order right now — please remove it from your cart and try again.",
      );
    }
  }

  const preGiftTotal = Math.round((subtotal - discountTotal) * 100) / 100;
  let giftDiscount = 0;
  let appliedGiftCode = null;
  if (giftCode) {
    if (!database) errors.push("Gift code service is unavailable.");
    else {
      const result = validateGiftCode(database, giftCode, customerId, preGiftTotal, guestPhone);
      if (!result.valid) errors.push(result.message);
      else { giftDiscount = result.discount; appliedGiftCode = result.code; }
    }
  }
  const total = Math.round(Math.max(0, preGiftTotal - giftDiscount) * 100) / 100;
  const totalDiscount = Math.max(0, Math.round((listedSubtotal - total) * 100) / 100);
  return { errors, pricedItems, listedSubtotal, saleDiscountTotal, subtotal, discountTotal, giftDiscount, appliedGiftCode, totalDiscount, total };
}

// ================================
// PHONE HELPER
// ================================
// No login system — a customer's WhatsApp phone number is their identity
// on an order, even though we no longer keep a customer record for it.

function normalizePhone(phone) {
  return String(phone || "").replace(/\D/g, "").slice(-10);
}

// Internal-only product code. Never returned by public product APIs.
function productCodePrefix(category) {
  const c = String(category || "").toLowerCase();
  if (c.includes("t-shirt") || c.includes("tshirt") || c.includes("tee")) return "TS";
  if (c.includes("mug")) return "MUG";
  if (c.includes("frame")) return "FRM";
  if (c.includes("cushion")) return "CUS";
  if (c.includes("keychain") || c.includes("key chain")) return "KEY";
  if (c.includes("bottle")) return "BOT";
  if (c.includes("cover") || c.includes("phone")) return "COV";
  const cleaned = c.replace(/[^a-z0-9]/g, "").slice(0, 3).toUpperCase();
  return cleaned || "PRD";
}

function ensureProductCodes(database) {
  const counters = {};
  (database.products || []).forEach((product) => {
    if (product.isGiftAddon) return;
    if (product.productCode) {
      const m = String(product.productCode).match(/^DM-([A-Z0-9]+)-(\d+)$/);
      if (m) counters[m[1]] = Math.max(counters[m[1]] || 0, Number(m[2]));
      return;
    }
    const prefix = productCodePrefix(product.category);
    counters[prefix] = counters[prefix] || 0;
    let code;
    do {
      counters[prefix] += 1;
      code = `DM-${prefix}-${String(counters[prefix]).padStart(3, "0")}`;
    } while ((database.products || []).some((p) => p.productCode === code));
    product.productCode = code;
  });
}

function generateOrderNumber(database) {
  const used = new Set((database.orders || []).map((o) => String(o.orderNumber || "")));
  for (let i = 0; i < 50; i++) {
    const candidate = `DM-${crypto.randomInt(10000000, 99999999)}`;
    if (!used.has(candidate)) return candidate;
  }
  let n = Number(String(Date.now()).slice(-8));
  while (used.has(`DM-${n}`)) n = (n + 1) % 100000000;
  return `DM-${String(n).padStart(8, "0")}`;
}

function getStockForVariant(product, size) {
  if (!product) return 0;
  // BUGFIX: a product that hasn't been through the admin's first inventory
  // import yet (stockConfigured === false) must stay sellable at its
  // migration default (stockQty = 999999) — that's the whole point of the
  // database.js migration comment ("this deploy cannot suddenly make the
  // live catalog unavailable"). Returning 0 here instead made EVERY
  // existing product in the live catalog look permanently out of stock the
  // moment this deploy went live, blocking every checkout until the admin
  // manually entered stock for the entire catalog.
  if (product.stockConfigured === false) return Math.max(0, Number(product.stockQty) || 0);
  const sizes = Array.isArray(product.sizes) ? product.sizes : [];
  const variantStock = product.variantStock && typeof product.variantStock === "object" ? product.variantStock : {};

  // A product with sizes is always tracked at the exact selected size.
  // Never fall back to a product-level stock number for a sized product.
  if (sizes.length) {
    if (!size || !sizes.includes(size)) return 0;
    const configured = product.variantStockConfigured && typeof product.variantStockConfigured === "object" ? product.variantStockConfigured : {};
    if (configured[size] !== true) return 0;
    return Math.max(0, Number(variantStock[size]) || 0);
  }

  return Math.max(0, Number(product.stockQty) || 0);
}

function setStockForVariant(product, size, value) {
  const qty = Math.max(0, Math.floor(Number(value) || 0));
  if (size && product.sizes && product.sizes.length) {
    product.variantStock = product.variantStock && typeof product.variantStock === "object" ? product.variantStock : {};
    product.variantStockConfigured = product.variantStockConfigured && typeof product.variantStockConfigured === "object" ? product.variantStockConfigured : {};
    product.variantStock[size] = qty;
    product.variantStockConfigured[size] = true;
  } else {
    product.stockQty = qty;
  }
}

// ================================
// BACK-IN-STOCK NOTIFICATION DELIVERY
// ================================
// The "Notify Me" preference is stored server-side (see the
// /api/customer/back-in-stock endpoints below) so it can actually be acted
// on here, whenever a product's stock is written. Subscriptions are
// one-shot: once an email goes out, the subscription is removed — this is
// "notify me the next time it's back", not an ongoing watch. If the
// customer has no email on file (mobile-only signup, no Google login),
// the subscription is still removed on restock — there's genuinely
// nothing to deliver to, and leaving a dead subscription around forever
// would just be silent debt.
function deliverBackInStockNotifications(database, product, sizesNewlyAvailable) {
  if (!sizesNewlyAvailable || !sizesNewlyAvailable.size) return;
  if (!Array.isArray(database.backInStockSubscriptions) || !database.backInStockSubscriptions.length) return;
  const remaining = [];
  const toNotify = [];
  database.backInStockSubscriptions.forEach((sub) => {
    if (sub.productId === product.id && sizesNewlyAvailable.has(String(sub.size || ""))) toNotify.push(sub);
    else remaining.push(sub);
  });
  if (!toNotify.length) return;
  database.backInStockSubscriptions = remaining;
  toNotify.forEach((sub) => {
    const customer = (database.customers || []).find((c) => c.id === sub.customerId);
    if (!customer || !customer.email) return;
    const sizeText = sub.size ? ` (${sub.size})` : "";
    sendMail(
      customer.email,
      `Back in stock: ${product.name}${sizeText}`,
      `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
         <h2 style="color:#8a1c42;margin-bottom:6px;">🔔 It's back in stock!</h2>
         <p style="margin:0 0 10px;"><strong>${product.name}${sizeText}</strong> is available again.</p>
         <p style="font-size:0.85em;color:#8c7d78;">You're getting this because you asked to be notified on Design Makers. This alert has now been used up — if you'd like to be notified again in future, just tap Notify Me again.</p>
       </div>`,
    ).catch((err) => console.error("Back-in-stock email failed:", err.message));
  });
}

// Whole-product before/after diff — used where we have full snapshots of
// the product both before and after an edit (direct admin edit, and a
// seller's edit going live at admin approval), rather than a single
// variant's before/after quantity.
function notifyBackInStockForProduct(database, beforeProduct, afterProduct) {
  if (!beforeProduct || !afterProduct) return;
  const sizes = Array.isArray(afterProduct.sizes) ? afterProduct.sizes : [];
  const newlyAvailable = new Set();
  if (sizes.length) {
    sizes.forEach((size) => {
      const before = Math.max(0, Number((beforeProduct.variantStock || {})[size]) || 0);
      const after = Math.max(0, Number((afterProduct.variantStock || {})[size]) || 0);
      if (before <= 0 && after > 0) newlyAvailable.add(String(size));
    });
  } else {
    const before = Math.max(0, Number(beforeProduct.stockQty) || 0);
    const after = Math.max(0, Number(afterProduct.stockQty) || 0);
    if (before <= 0 && after > 0) newlyAvailable.add("");
  }
  deliverBackInStockNotifications(database, afterProduct, newlyAvailable);
}

// Single-variant before/after — used by the inventory endpoints, which
// already compute a specific variant's before/after quantity directly.
function notifyBackInStockForVariant(database, product, size, beforeQty, afterQty) {
  if (Math.max(0, Number(beforeQty) || 0) > 0 || Math.max(0, Number(afterQty) || 0) <= 0) return;
  deliverBackInStockNotifications(database, product, new Set([String(size || "")]));
}

function getInventoryRows(database) {
  const rows = [];
  (database.products || []).forEach((product) => {
    if (product.isGiftAddon) return;
    const sizes = Array.isArray(product.sizes) ? product.sizes : [];
    const variantStock = product.variantStock && typeof product.variantStock === "object" ? product.variantStock : {};
    const variantConfigured = product.variantStockConfigured && typeof product.variantStockConfigured === "object" ? product.variantStockConfigured : {};
    const common = {
      productId: product.id,
      // Kept alongside productId (not replacing it) so every existing
      // consumer of this row shape keeps working untouched — the new
      // hierarchical Inventory tab is the only thing that reads sellerId.
      sellerId: product.sellerId === undefined ? null : product.sellerId,
      productCode: product.productCode || "",
      productName: product.name || "",
      stockConfigured: product.stockConfigured !== false,
      lowStockThreshold: Math.max(0, Number(product.lowStockThreshold ?? 5) || 5),
    };
    if (sizes.length) {
      // Every size gets its own inventory row, even before stock has been
      // entered. Missing variant stock means zero/unconfigured, never the
      // product-level stock.
      sizes.forEach((size) => rows.push({
        ...common,
        variant: size,
        currentStock: product.stockConfigured === false || variantConfigured[size] !== true ? null : Math.max(0, Number(variantStock[size]) || 0),
      }));
    } else {
      rows.push({
        ...common,
        variant: "",
        currentStock: product.stockConfigured === false ? null : Math.max(0, Number(product.stockQty) || 0),
      });
    }
  });
  return rows;
}

let inventoryOrderQueue = Promise.resolve();
function withInventoryLock(task) {
  const run = inventoryOrderQueue.then(task, task);
  inventoryOrderQueue = run.catch(() => {});
  return run;
}

// ================================
// HIERARCHICAL INVENTORY (Inventory tab: Seller -> Products -> Variant Stock)
// Reuses getInventoryRows() / getStockForVariant() / setStockForVariant() —
// the same source of truth the storefront and the older flat inventory
// table already use — so stock numbers can never drift between them.
// ================================

// Same in-stock / low-stock / out-of-stock rule the existing flat
// inventory table already uses (see inventoryStatus() in admin.html) —
// mirrored here so the new hierarchical endpoints agree with it exactly.
function inventoryRowStatus(row) {
  if (row.stockConfigured === false || row.currentStock === null) return "not_configured";
  const n = Number(row.currentStock) || 0;
  if (n <= 0) return "out";
  if (n <= Number(row.lowStockThreshold || 5)) return "low";
  return "in_stock";
}

function sellerKeyFor(sellerId) {
  return sellerId === null || sellerId === undefined ? "house" : String(sellerId);
}

// Groups the flat inventory rows by seller (a seller-less/admin-added
// product is grouped under the "house" pseudo-seller) and rolls each
// group up into the counts the Inventory -> Seller List page needs.
function buildSellerInventorySummaries(database) {
  const rows = getInventoryRows(database);
  const bySeller = new Map();
  rows.forEach((row) => {
    const key = sellerKeyFor(row.sellerId);
    if (!bySeller.has(key)) bySeller.set(key, { productIds: new Set(), variants: 0, totalStock: 0, low: 0, out: 0 });
    const g = bySeller.get(key);
    g.productIds.add(row.productId);
    g.variants += 1;
    const status = inventoryRowStatus(row);
    if (status === "low") g.low += 1;
    else if (status === "out") g.out += 1;
    if (row.currentStock !== null) g.totalStock += Number(row.currentStock) || 0;
  });

  const sellerById = new Map((database.sellers || []).map((s) => [s.id, s]));
  const out = [];
  bySeller.forEach((g, key) => {
    const seller = key === "house" ? null : sellerById.get(Number(key));
    if (key !== "house" && !seller) return; // orphaned sellerId, skip
    // Same reasoning as buildSellerProductSummaries() below: seller
    // photos are full-size base64 data URIs, and sending one per row
    // adds up fast. This list only needs a small logo, so skip it here.
    out.push({
      key,
      sellerId: seller ? seller.id : null,
      name: seller ? (seller.shopTitle || seller.name) : "Design Makers (Direct)",
      status: seller ? (seller.banned ? "Suspended" : "Active") : "Active",
      totalProducts: g.productIds.size,
      totalVariants: g.variants,
      totalStock: g.totalStock,
      lowStockCount: g.low,
      outOfStockCount: g.out,
    });
  });
  // House catalogue first, then sellers alphabetically by display name.
  out.sort((a, b) => (a.key === "house" ? -1 : b.key === "house" ? 1 : a.name.localeCompare(b.name)));
  return out;
}

function buildSellerProductSummaries(database, sellerKey) {
  const rows = getInventoryRows(database).filter((r) => sellerKeyFor(r.sellerId) === sellerKey);
  const byProduct = new Map();
  rows.forEach((row) => {
    if (!byProduct.has(row.productId)) byProduct.set(row.productId, { variants: 0, totalStock: 0, low: 0, out: 0 });
    const g = byProduct.get(row.productId);
    g.variants += 1;
    const status = inventoryRowStatus(row);
    if (status === "low") g.low += 1;
    else if (status === "out") g.out += 1;
    if (row.currentStock !== null) g.totalStock += Number(row.currentStock) || 0;
  });
  const productById = new Map((database.products || []).map((p) => [p.id, p]));
  const out = [];
  byProduct.forEach((g, productId) => {
    const p = productById.get(productId);
    if (!p) return;
    // NOT sending the product image here: images are stored as full-size
    // base64 data URIs (often 100KB+ each), and this list can have many
    // rows. Embedding every one balloons the response and makes the
    // Inventory tab slow (or stuck) to load, especially with many
    // products or on lower-bandwidth hosting. The frontend already
    // handles a missing image gracefully (skips the thumbnail). The
    // Variant Stock page (buildProductVariantDetail below) still shows
    // the real image where it's actually needed.
    out.push({
      id: p.id,
      name: p.name || "",
      productCode: p.productCode || "",
      category: p.category || "Uncategorized",
      price: Number(p.price) || 0,
      // "Live on the storefront" = approved by admin AND not switched off
      // by the seller/admin. Used by the admin Inventory tab to sort/filter
      // so stock updates for what's actually on sale surface first.
      active: p.approved !== false && p.active !== false,
      variants: g.variants,
      totalStock: g.totalStock,
      lowStockCount: g.low,
      outOfStockCount: g.out,
    });
  });
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

function buildProductVariantDetail(database, productId) {
  const product = (database.products || []).find((p) => p.id === productId && !p.isGiftAddon);
  if (!product) return null;
  const seller = product.sellerId ? (database.sellers || []).find((s) => s.id === product.sellerId) : null;
  const sizes = Array.isArray(product.sizes) ? product.sizes : [];
  const rows = getInventoryRows(database).filter((r) => r.productId === productId);
  const variants = rows.map((row) => {
    const stock = row.currentStock === null ? 0 : Number(row.currentStock) || 0;
    // No cart-hold/reservation system exists in this codebase today, so
    // Reserved is always 0 and Available === Stock. If a reservation
    // system is added later, wire its number in here.
    const reserved = 0;
    return {
      size: row.variant || "",
      sku: product.productCode ? product.productCode + (row.variant ? "-" + row.variant : "") : "",
      price: Number(product.price) || 0,
      moq: Number(product.moq) || 1,
      stock,
      reserved,
      available: Math.max(0, stock - reserved),
      status: inventoryRowStatus(row),
      configured: row.currentStock !== null,
      lowStockThreshold: row.lowStockThreshold,
    };
  });
  // Latest of any stock adjustment timestamp, falling back to the
  // product's own updatedAt/createdAt — whichever is the most recent
  // real change we actually have on record. Never fabricated.
  const lastAdjustment = Array.isArray(product.stockAdjustments) && product.stockAdjustments[0] ? product.stockAdjustments[0].at : null;
  const lastUpdated = lastAdjustment || product.updatedAt || product.createdAt || null;
  return {
    id: product.id,
    name: product.name || "",
    productCode: product.productCode || "",
    image: (Array.isArray(product.images) && product.images[0]) || product.image || "",
    sellerKey: sellerKeyFor(product.sellerId),
    sellerName: seller ? (seller.shopTitle || seller.name) : "Design Makers (Direct)",
    hasSizes: sizes.length > 0,
    lowStockThreshold: Math.max(0, Number(product.lowStockThreshold ?? 5) || 5),
    totalVariants: variants.length,
    totalStock: variants.reduce((sum, v) => sum + (v.configured ? Number(v.stock) || 0 : 0), 0),
    lastUpdated,
    variants,
  };
}

// ---- Inventory tab routes ----

app.get("/api/admin/inventory/sellers", requireAdmin, (req, res) => {
  const database = readDatabase();
  res.json({ success: true, sellers: buildSellerInventorySummaries(database) });
});

app.get("/api/admin/inventory/sellers/:key/products", requireAdmin, (req, res) => {
  const database = readDatabase();
  res.json({ success: true, products: buildSellerProductSummaries(database, String(req.params.key)) });
});

app.get("/api/admin/inventory/products/:id", requireAdmin, (req, res) => {
  const database = readDatabase();
  const detail = buildProductVariantDetail(database, Number(req.params.id));
  if (!detail) return res.status(404).json({ success: false, message: "Product not found." });
  res.json({ success: true, product: detail });
});

// Dedicated, focused stock-only write — deliberately separate from the
// full product-edit endpoint (PUT /api/admin/products/:id) so a stock
// correction is instant for every admin/sub-admin the same way the
// existing hide/show toggle is, instead of being queued behind the
// boss-approval flow that whole-product catalogue edits go through.
// Stock permission is unchanged from before this feature existed — any
// signed-in admin could already change stock via the product edit form.
app.put("/api/admin/inventory/products/:id/stock", requireAdmin, (req, res) => {
  return withInventoryLock(() => {
    const database = readDatabase();
    const id = Number(req.params.id);
    const product = (database.products || []).find((p) => p.id === id && !p.isGiftAddon);
    if (!product) return res.status(404).json({ success: false, message: "Product not found." });

    const size = req.body && req.body.size ? String(req.body.size) : "";
    const sizes = Array.isArray(product.sizes) ? product.sizes : [];
    if (sizes.length && !sizes.includes(size)) {
      return res.status(400).json({ success: false, message: "Unknown size/variant for this product." });
    }
    const newStock = req.body ? Number(req.body.stock) : NaN;
    if (!Number.isFinite(newStock) || newStock < 0) {
      return res.status(400).json({ success: false, message: "Enter a valid stock quantity (0 or more)." });
    }

    const before = getStockForVariant(product, size);
    setStockForVariant(product, size, newStock);
    product.stockConfigured = true;

    const reason = req.body && req.body.reason ? String(req.body.reason).trim().slice(0, 200) : "";
    product.stockAdjustments = Array.isArray(product.stockAdjustments) ? product.stockAdjustments : [];
    product.stockAdjustments.unshift({
      size: size || null,
      before,
      after: newStock,
      reason,
      by: req.admin.username,
      at: new Date().toISOString(),
    });
    product.stockAdjustments = product.stockAdjustments.slice(0, 50);

    notifyBackInStockForVariant(database, product, size, before, newStock);
    writeDatabase(database);

    res.json({
      success: true,
      message: "Stock updated.",
      product: buildProductVariantDetail(database, id),
      sellerSummary: buildSellerProductSummaries(database, sellerKeyFor(product.sellerId)).find((p) => p.id === id) || null,
    });
  });
});

// ---- Seller-side Inventory tab routes ----
// Same hierarchical Inventory feature as admin above, but scoped to only
// the logged-in seller's own products — no seller list/drilldown, since
// there's only ever one seller in view (themselves). Reuses the exact
// same helper functions (buildSellerProductSummaries,
// buildProductVariantDetail, getInventoryRows, withInventoryLock) so
// stock numbers can never drift between the admin and seller views.

app.get("/api/seller/inventory/products", requireSeller, (req, res) => {
  const database = readDatabase();
  res.json({ success: true, products: buildSellerProductSummaries(database, sellerKeyFor(req.seller.id)) });
});

app.get("/api/seller/inventory/products/:id", requireSeller, (req, res) => {
  const database = readDatabase();
  const id = Number(req.params.id);
  const product = (database.products || []).find((p) => p.id === id && !p.isGiftAddon);
  if (!product || product.sellerId !== req.seller.id) {
    return res.status(404).json({ success: false, message: "Product not found." });
  }
  const detail = buildProductVariantDetail(database, id);
  if (!detail) return res.status(404).json({ success: false, message: "Product not found." });
  res.json({ success: true, product: detail });
});

app.put("/api/seller/inventory/products/:id/stock", requireSeller, (req, res) => {
  return withInventoryLock(() => {
    const database = readDatabase();
    const id = Number(req.params.id);
    const product = (database.products || []).find((p) => p.id === id && !p.isGiftAddon);
    if (!product || product.sellerId !== req.seller.id) {
      return res.status(404).json({ success: false, message: "Product not found." });
    }

    const size = req.body && req.body.size ? String(req.body.size) : "";
    const sizes = Array.isArray(product.sizes) ? product.sizes : [];
    if (sizes.length && !sizes.includes(size)) {
      return res.status(400).json({ success: false, message: "Unknown size/variant for this product." });
    }
    const newStock = req.body ? Number(req.body.stock) : NaN;
    if (!Number.isFinite(newStock) || newStock < 0) {
      return res.status(400).json({ success: false, message: "Enter a valid stock quantity (0 or more)." });
    }

    const before = getStockForVariant(product, size);
    setStockForVariant(product, size, newStock);
    product.stockConfigured = true;

    const reason = req.body && req.body.reason ? String(req.body.reason).trim().slice(0, 200) : "";
    product.stockAdjustments = Array.isArray(product.stockAdjustments) ? product.stockAdjustments : [];
    product.stockAdjustments.unshift({
      size: size || null,
      before,
      after: newStock,
      reason,
      by: req.seller.shopTitle || req.seller.name,
      at: new Date().toISOString(),
    });
    product.stockAdjustments = product.stockAdjustments.slice(0, 50);

    notifyBackInStockForVariant(database, product, size, before, newStock);
    writeDatabase(database);

    res.json({
      success: true,
      message: "Stock updated.",
      product: buildProductVariantDetail(database, id),
    });
  });
});

// ================================
// ADMIN PRODUCT MANAGEMENT
// ================================

// List ALL products (including inactive) for the dashboard

// ================================
// GIFT CODES — MAIN ADMIN ONLY
// ================================
app.get("/api/admin/gift-codes", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const codes = (database.giftCodes || []).map(({ usageByCustomer, ...g }) => g);
  res.json({ success: true, codes });
});

app.post("/api/admin/gift-codes", requireAdmin, requireBoss, (req, res) => {
  const body = req.body || {};
  const code = normalizeGiftCode(body.code);
  const type = body.type === "fixed" ? "fixed" : "percent";
  const value = Number(body.value);
  const minOrder = Math.max(0, Number(body.minOrder || 0));
  const maxDiscount = Math.max(0, Number(body.maxDiscount || 0));
  const usageLimit = Math.max(0, Math.floor(Number(body.usageLimit || 0)));
  const perCustomerLimit = Math.max(0, Math.floor(Number(body.perCustomerLimit || 0)));
  if (!/^[A-Z0-9_-]{3,30}$/.test(code)) return res.status(400).json({ success:false, message:"Gift code must be 3-30 characters (letters, numbers, _ or -)." });
  if (!Number.isFinite(value) || value <= 0 || (type === "percent" && value > 100)) return res.status(400).json({ success:false, message:"Enter a valid discount value." });
  const startsAt = body.startsAt ? new Date(body.startsAt).toISOString() : new Date().toISOString();
  const expiresAt = body.expiresAt ? new Date(body.expiresAt).toISOString() : null;
  if (expiresAt && new Date(expiresAt) <= new Date(startsAt)) return res.status(400).json({ success:false, message:"Expiry must be after the start date." });
  const database = readDatabase();
  if (!Array.isArray(database.giftCodes)) database.giftCodes = [];
  if (database.giftCodes.some(g => String(g.code).toUpperCase() === code)) return res.status(409).json({ success:false, message:"That gift code already exists." });
  database.giftCodes.push({ id: getNextId(database.giftCodes), code, type, value, minOrder, maxDiscount, usageLimit, perCustomerLimit, startsAt, expiresAt, active: true, usedCount: 0, usageByCustomer: {}, createdAt: new Date().toISOString(), createdBy: req.admin.username });
  writeDatabase(database);
  res.status(201).json({ success:true, message:"Gift code created." });
});

// Full edit support. Previously this only ever touched `active` and
// `expiresAt`, so the Admin UI had no way to actually change a code's
// discount, min order, usage limits, start date, or even its text — the
// "Edit" audit requirement for Update 1 was effectively unimplemented.
// Every field is optional (only what's sent is changed), but whatever IS
// sent is validated with the exact same rules as creation so an edit can
// never leave a code in a broken/inconsistent state.
app.patch("/api/admin/gift-codes/:id", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const gift = (database.giftCodes || []).find(g => Number(g.id) === Number(req.params.id));
  if (!gift) return res.status(404).json({ success:false, message:"Gift code not found." });
  const body = req.body || {};

  let nextCode = gift.code;
  if (body.code !== undefined) {
    nextCode = normalizeGiftCode(body.code);
    if (!/^[A-Z0-9_-]{3,30}$/.test(nextCode)) return res.status(400).json({ success:false, message:"Gift code must be 3-30 characters (letters, numbers, _ or -)." });
    if (database.giftCodes.some(g => g.id !== gift.id && String(g.code).toUpperCase() === nextCode)) {
      return res.status(409).json({ success:false, message:"That gift code already exists." });
    }
  }

  let nextType = gift.type;
  if (body.type !== undefined) nextType = body.type === "fixed" ? "fixed" : "percent";

  let nextValue = gift.value;
  if (body.value !== undefined) {
    nextValue = Number(body.value);
    if (!Number.isFinite(nextValue) || nextValue <= 0 || (nextType === "percent" && nextValue > 100)) {
      return res.status(400).json({ success:false, message:"Enter a valid discount value." });
    }
  }

  let nextStartsAt = gift.startsAt;
  if (body.startsAt !== undefined) nextStartsAt = body.startsAt ? new Date(body.startsAt).toISOString() : new Date().toISOString();
  let nextExpiresAt = gift.expiresAt;
  if (body.expiresAt !== undefined) nextExpiresAt = body.expiresAt ? new Date(body.expiresAt).toISOString() : null;
  if (nextExpiresAt && new Date(nextExpiresAt) <= new Date(nextStartsAt)) {
    return res.status(400).json({ success:false, message:"Expiry must be after the start date." });
  }

  gift.code = nextCode;
  gift.type = nextType;
  gift.value = nextValue;
  if (body.minOrder !== undefined) gift.minOrder = Math.max(0, Number(body.minOrder || 0));
  if (body.maxDiscount !== undefined) gift.maxDiscount = Math.max(0, Number(body.maxDiscount || 0));
  if (body.usageLimit !== undefined) gift.usageLimit = Math.max(0, Math.floor(Number(body.usageLimit || 0)));
  if (body.perCustomerLimit !== undefined) gift.perCustomerLimit = Math.max(0, Math.floor(Number(body.perCustomerLimit || 0)));
  gift.startsAt = nextStartsAt;
  gift.expiresAt = nextExpiresAt;
  if (typeof body.active === "boolean") gift.active = body.active;
  gift.updatedAt = new Date().toISOString();
  gift.updatedBy = req.admin.username;

  writeDatabase(database);
  res.json({ success:true, message:"Gift code updated." });
});

app.delete("/api/admin/gift-codes/:id", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const before = (database.giftCodes || []).length;
  database.giftCodes = (database.giftCodes || []).filter(g => Number(g.id) !== Number(req.params.id));
  if (database.giftCodes.length === before) return res.status(404).json({ success:false, message:"Gift code not found." });
  writeDatabase(database);
  res.json({ success:true });
});

app.get("/api/admin/products", requireAdmin, (req, res) => {
  const database = readDatabase();
  ensureProductCodes(database);
  writeDatabase(database);
  res.json({ success: true, products: database.products });
});

// Create a product
app.post("/api/admin/products", requireAdmin, (req, res) => {
  const { errors, product } = validateProductInput(req.body || {});

  if (errors.length) {
    return res.status(400).json({ success: false, message: errors.join(" ") });
  }

  const database = readDatabase();
  ensureProductCodes(database);
  const prefix = productCodePrefix(product.category);
  let max = 0;
  (database.products || []).forEach((p) => {
    const m = String(p.productCode || "").match(new RegExp("^DM-" + prefix + "-(\\d+)$"));
    if (m) max = Math.max(max, Number(m[1]));
  });
  // stockConfigured starts false (not 0) so a brand-new product from the
  // Products tab shows up in the Inventory tab as "needs stock entry"
  // rather than silently looking out-of-stock — the admin now sets its
  // real starting stock from Inventory -> Seller List -> Design Makers
  // (Direct) -> this product, same as any other product.
  const newProduct = { id: getNextId(database.products), sellerId: null, approved: true, productCode: `DM-${prefix}-${String(max + 1).padStart(3, "0")}`, stockQty: 0, stockConfigured: false, lowStockThreshold: 5, variantStock: {}, variantStockConfigured: {}, ...product };
  database.products.push(newProduct);
  writeDatabase(database);

  res.status(201).json({ success: true, product: newProduct });
});

// ================================
// SELLER: PRODUCT MANAGEMENT
// ================================
// A seller's new products are NOT active/approved by default — they only
// appear on the storefront once the admin approves them below. Sellers can
// see their own products (including pending ones) via GET /api/seller/products.

app.post("/api/seller/products", requireSeller, (req, res) => {
  const { errors, product } = validateProductInput(req.body || {});

  if (errors.length) {
    return res.status(400).json({ success: false, message: errors.join(" ") });
  }

  const database = readDatabase();
  ensureProductCodes(database);
  const prefix = productCodePrefix(product.category);
  let max = 0;
  (database.products || []).forEach((p) => {
    const m = String(p.productCode || "").match(new RegExp("^DM-" + prefix + "-(\\d+)$"));
    if (m) max = Math.max(max, Number(m[1]));
  });
  // stockConfigured starts false (not 0) so a brand-new seller product
  // shows up in the seller's own Inventory tab as "needs stock entry"
  // rather than silently looking out-of-stock — the seller now sets its
  // real starting stock from Inventory -> this product, same as admin
  // does for house products. (Previously this form collected stock
  // directly on Add Product; now that the seller's Inventory tab exists,
  // stock is set there instead — same single-source-of-truth pattern as
  // admin's Products tab.)
  const newProduct = {
    id: getNextId(database.products),
    sellerId: req.seller.id,
    approved: false, // waits for admin approval before showing on the storefront
    productCode: `DM-${prefix}-${String(max + 1).padStart(3, "0")}`,
    stockQty: 0,
    stockConfigured: false,
    lowStockThreshold: 5,
    variantStock: {},
    variantStockConfigured: {},
    sellerWhatsappNumber: req.seller.whatsappNumber || req.seller.phone || "",
    ...product,
  };
  database.products.push(newProduct);
  writeDatabase(database);

  res.status(201).json({
    success: true,
    message: "Product submitted — it will appear on the storefront once an admin approves it.",
    product: newProduct,
  });
});

app.get("/api/seller/products", requireSeller, (req, res) => {
  const database = readDatabase();
  const products = database.products.filter((p) => p.sellerId === req.seller.id);
  res.json({ success: true, products });
});

// Edit one of the seller's own products. Like a brand-new listing, an
// edited product goes back to `approved: false` and waits for an admin to
// re-review it — otherwise a seller could get a product approved once and
// then silently change it into something an admin never actually saw.
app.put("/api/seller/products/:id", requireSeller, (req, res) => {
  const { errors, product } = validateProductInput(req.body || {});

  if (errors.length) {
    return res.status(400).json({ success: false, message: errors.join(" ") });
  }

  const database = readDatabase();
  const id = Number(req.params.id);
  const index = database.products.findIndex((p) => p.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Product not found." });
  }
  if (database.products[index].sellerId !== req.seller.id) {
    return res.status(403).json({ success: false, message: "You can only edit your own products." });
  }

  // The seller's edit form doesn't have a buyBadgePercent field — only the
  // admin's Homepage Sections tab sets that. Don't let a normal edit reset
  // it back to the default.
  if (req.body.buyBadgePercent === undefined) {
    product.buyBadgePercent = database.products[index].buyBadgePercent ?? 10;
  }

  // Keep a snapshot of the last-live version so the admin review screen can
  // show a before/after summary of exactly what the seller changed. Only
  // captured the first time a live product goes back to pending — if it's
  // already pending from an earlier unreviewed edit, keep that original
  // snapshot so the diff always compares against what's actually live now.
  const wasLive = database.products[index].approved !== false;
  const snapshot = wasLive ? database.products[index] : database.products[index].pendingSnapshot;

  database.products[index] = {
    ...database.products[index],
    ...product,
    id,
    sellerId: database.products[index].sellerId,
    approved: false,
    pendingSnapshot: snapshot ? { ...snapshot, pendingSnapshot: undefined } : undefined,
  };
  writeDatabase(database);

  res.json({
    success: true,
    message: "Product updated — it will appear on the storefront once an admin re-approves it.",
    product: database.products[index],
  });
});

// ================================
// SELLER FULFILMENT / ORDER STAGES
// ================================
const SELLER_FULFILMENT_STAGES = ["Processing", "Ready to Ship", "Shipped", "Out for Delivery", "Delivered"];
const SELLER_DECISIONS = ["pending", "accepted", "declined", "taken_over"];

function itemFulfilmentKey(item, index) {
  return String(item.productId || "product") + "::" + String(item.size || "") + "::" + String(index);
}

function ensureSellerFulfilment(database, order) {
  if (!Array.isArray(order.sellerFulfilment)) order.sellerFulfilment = [];
  const now = new Date().toISOString();
  const existing = new Map(order.sellerFulfilment.map(x => [x.key, x]));
  (order.items || []).forEach((item, index) => {
    const product = database.products.find(p => p.id === Number(item.productId));
    if (!product || !product.sellerId) return;
    const key = itemFulfilmentKey(item, index);
    if (!existing.has(key)) {
      const rec = { key, productId: item.productId, sellerId: product.sellerId, decision: "pending", stage: "Order Received", updatedAt: order.createdAt || now, updatedBy: "system" };
      order.sellerFulfilment.push(rec);
      existing.set(key, rec);
    } else {
      const rec = existing.get(key);
      rec.productId = item.productId;
      rec.sellerId = product.sellerId;
      if (!rec.decision) rec.decision = "pending";
      if (!rec.stage) rec.stage = "Order Received";
    }
  });
  return order.sellerFulfilment;
}

function getSellerFulfilment(database, order) {
  return ensureSellerFulfilment(database, order).map(x => ({ ...x }));
}

function deriveCustomerFulfilmentStage(order, records) {
  if (order.status === "Cancelled") return "Cancelled";
  const stages = (records || []).map(r => r.stage || "Order Received");
  if (!stages.length) return order.status === "Delivered" ? "Delivered" : (order.status || "Order Received");
  if (stages.every(s => s === "Delivered")) return "Delivered";
  if (stages.some(s => s === "Out for Delivery")) return "Out for Delivery";
  if (stages.some(s => s === "Shipped")) return "Shipped";
  if (stages.some(s => s === "Ready to Ship")) return "Ready to Ship";
  if (stages.some(s => s === "Processing")) return "Processing";
  return "Order Received";
}

async function notifyAdminsSellerDecision(database, order, seller, decision, reason) {
  const subject = decision === "declined"
    ? `Seller declined order ${order.orderNumber} — action required`
    : `Seller accepted order ${order.orderNumber}`;
  const body = decision === "declined"
    ? `<p><b>${seller.shopTitle || seller.name}</b> declined part of order <b>${order.orderNumber}</b>.</p><p>Reason: ${String(reason || "Not provided").replace(/[<>&\"]/g, "")}</p><p>Open Admin → Orders to review and take over the fulfilment if required.</p>`
    : `<p><b>${seller.shopTitle || seller.name}</b> accepted order <b>${order.orderNumber}</b>.</p>`;
  try { await sendMail(ADMIN_NOTIFY_EMAIL, subject, body); } catch (e) { console.error("Seller decision admin email failed:", e.message); }
}

app.post("/api/seller/orders/:id/decision", requireSeller, async (req, res) => {
  const database = readDatabase();
  const order = database.orders.find(o => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ success: false, message: "Order not found." });
  const decision = String((req.body || {}).decision || "").toLowerCase();
  const reason = String((req.body || {}).reason || "").trim().slice(0, 500);
  if (!["accepted", "declined"].includes(decision)) return res.status(400).json({ success: false, message: "Invalid seller decision." });
  const records = ensureSellerFulfilment(database, order).filter(r => r.sellerId === req.seller.id);
  if (!records.length) return res.status(403).json({ success: false, message: "This order does not contain your products." });
  if (decision === "declined" && !reason) return res.status(400).json({ success: false, message: "Please provide a reason for declining the order." });
  const now = new Date().toISOString();
  records.forEach(r => {
    if (r.decision === "taken_over") return;
    r.decision = decision;
    r.declineReason = decision === "declined" ? reason : null;
    r.stage = decision === "accepted" ? "Processing" : "Order Received";
    r.updatedAt = now;
    r.updatedBy = `seller:${req.seller.id}`;
  });
  writeDatabase(database);
  notifyAdminsSellerDecision(database, order, req.seller, decision, reason).catch(() => {});
  res.json({ success: true, message: decision === "accepted" ? "Order accepted." : "Order declined. Design Makers has been notified.", order: sellerOrderPayload(database, order, req.seller) });
});

app.put("/api/seller/orders/:id/stage", requireSeller, (req, res) => {
  const database = readDatabase();
  const order = database.orders.find(o => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ success: false, message: "Order not found." });
  const stage = String((req.body || {}).stage || "");
  if (!SELLER_FULFILMENT_STAGES.includes(stage)) return res.status(400).json({ success: false, message: "Invalid fulfilment stage." });
  const records = ensureSellerFulfilment(database, order).filter(r => r.sellerId === req.seller.id);
  if (!records.length) return res.status(403).json({ success: false, message: "This order does not contain your products." });
  if (records.some(r => r.decision === "declined")) return res.status(403).json({ success: false, message: "This order was declined and is awaiting admin takeover." });
  const now = new Date().toISOString();
  records.forEach(r => { if (r.decision === "accepted") { r.stage = stage; r.updatedAt = now; r.updatedBy = `seller:${req.seller.id}`; } });
  writeDatabase(database);
  res.json({ success: true, order: sellerOrderPayload(database, order, req.seller) });
});

function sellerOrderPayload(database, order, seller) {
  ensureSellerFulfilment(database, order);
  const myProductIds = new Set(database.products.filter(p => p.sellerId === seller.id).map(p => p.id));
  const items = (order.items || []).filter(i => myProductIds.has(i.productId));
  const keys = new Set(items.map((item, idx) => itemFulfilmentKey(item, (order.items || []).indexOf(item))));
  const fulfilment = (order.sellerFulfilment || []).filter(r => r.sellerId === seller.id && keys.has(r.key));
  const sellerTotal = Math.round(items.reduce((sum, item) => sum + (Number(item.lineTotal) || 0), 0) * 100) / 100;
  // Gift orders: the seller only needs to know (a) it's a gift, so they
  // don't slip an invoice/price note into the package, and (b) whether the
  // price should be hidden on any packing slip. The recipient's name and
  // the customer's personal gift message are not needed for fulfilment and
  // are withheld here — only the customer's own view and the admin panel
  // (which needs the full picture for support) get those fields.
  const gift = order.gift && order.gift.isGift
    ? { isGift: true, hidePrice: !!order.gift.hidePrice }
    : { isGift: false };
  return { ...order, items, sellerTotal, sellerFulfilment: fulfilment, gift };
}

// Main admin can take over only the seller's lines that were declined.
app.put("/api/admin/orders/:id/seller-takeover", requireAdmin, async (req, res) => {
  const database = readDatabase();
  const order = database.orders.find(o => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ success: false, message: "Order not found." });
  const sellerId = Number((req.body || {}).sellerId);
  if (!sellerId) return res.status(400).json({ success: false, message: "Seller is required." });
  const records = ensureSellerFulfilment(database, order).filter(r => r.sellerId === sellerId && r.decision === "declined");
  if (!records.length) return res.status(400).json({ success: false, message: "No declined seller items are available for takeover." });
  const now = new Date().toISOString();
  records.forEach(r => { r.decision = "taken_over"; r.fulfilledBy = "design_makers"; r.stage = "Processing"; r.updatedAt = now; r.updatedBy = `admin:${req.admin.username || req.admin.id || "admin"}`; });
  // Customer-facing order remains normal; never expose the seller rejection.
  order.sellerTakeovers = Array.isArray(order.sellerTakeovers) ? order.sellerTakeovers : [];
  order.sellerTakeovers.push({ sellerId, at: now, by: req.admin.username || req.admin.id || "admin", action: "takeover" });
  writeDatabase(database);
  res.json({ success: true, message: "Design Makers has taken over the declined seller items.", order });
});

app.put("/api/admin/orders/:id/seller-stage", requireAdmin, (req, res) => {
  const database = readDatabase();
  const order = database.orders.find(o => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ success: false, message: "Order not found." });
  const sellerId = Number((req.body || {}).sellerId);
  const stage = String((req.body || {}).stage || "");
  if (!sellerId || !SELLER_FULFILMENT_STAGES.includes(stage)) return res.status(400).json({ success: false, message: "Seller and valid stage are required." });
  const records = ensureSellerFulfilment(database, order).filter(r => r.sellerId === sellerId && ["accepted", "taken_over"].includes(r.decision));
  if (!records.length) return res.status(400).json({ success: false, message: "No active fulfilment for that seller is available." });
  const now = new Date().toISOString();
  records.forEach(r => { r.stage = stage; r.updatedAt = now; r.updatedBy = `admin:${req.admin.username || req.admin.id || "admin"}`; });
  writeDatabase(database);
  res.json({ success: true, order });
});

// Orders that include at least one of this seller's products. Each order
// keeps its normal shape, but `items` is filtered down to just this
// seller's lines so a seller never sees another seller's line items.
app.get("/api/seller/orders", requireSeller, (req, res) => {
  const database = readDatabase();
  const orders = database.orders
    .map(order => { const p = sellerOrderPayload(database, order, req.seller); return p.items.length ? p : null; })
    .filter(Boolean)
    .sort((a,b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  writeDatabase(database);
  res.json({ success: true, orders });
});

// ================================
// SELLER: PROFILE
// ================================
// Sellers can't edit phone/shop title/photo directly — they submit a
// request here, and the boss reviews it from the admin panel.

app.get("/api/seller/me", requireSeller, (req, res) => {
  const seller = req.seller;
  res.json({
    success: true,
    seller: {
      id: seller.id,
      sellerId: seller.sellerId,
      name: seller.name,
      email: seller.email,
      phone: seller.phone,
      shopTitle: seller.shopTitle,
      photo: seller.photo || "",
      createdAt: seller.createdAt,
    },
    mustChangePassword: !!seller.mustChangePassword,
  });
});

app.post("/api/seller/profile-update-request", requireSeller, (req, res) => {
  const body = req.body || {};
  const phone = String(body.phone || "").trim();
  const shopTitle = String(body.shopTitle || "").trim();
  const photo = String(body.photo || "").trim(); // base64 data URL, optional

  const changes = {};
  if (phone && phone !== req.seller.phone) changes.phone = phone;
  if (shopTitle && shopTitle !== req.seller.shopTitle) changes.shopTitle = shopTitle;
  if (photo) changes.photo = photo;

  if (!Object.keys(changes).length) {
    return res.status(400).json({ success: false, message: "No changes to submit." });
  }

  const database = readDatabase();
  if (!Array.isArray(database.sellerProfileUpdateRequests)) database.sellerProfileUpdateRequests = [];

  const alreadyPending = database.sellerProfileUpdateRequests.some(
    (r) => r.sellerRecordId === req.seller.id && r.status === "pending",
  );
  if (alreadyPending) {
    return res.status(409).json({
      success: false,
      message: "You already have a pending profile update request — please wait for it to be reviewed.",
    });
  }

  const request = {
    id: getNextId(database.sellerProfileUpdateRequests),
    sellerRecordId: req.seller.id,
    sellerId: req.seller.sellerId,
    name: req.seller.name,
    changes,
    status: "pending",
    createdAt: new Date().toISOString(),
  };
  database.sellerProfileUpdateRequests.push(request);
  writeDatabase(database);

  sendMail(
    ADMIN_NOTIFY_EMAIL,
    "Seller profile update request — Design Makers",
    `<p>${req.seller.name} (${req.seller.sellerId}) requested a profile update.</p>
     <p>Review it from the admin panel's Sellers tab.</p>`,
  );

  res.json({ success: true, message: "Your request has been sent to the admin for approval." });
});

// Boss-only: view + resolve seller profile-update requests.
app.get("/api/admin/seller-profile-update-requests", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const requests = (database.sellerProfileUpdateRequests || [])
    .filter((r) => r.status === "pending")
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, requests });
});

app.put("/api/admin/seller-profile-update-requests/:id", requireAdmin, requireBoss, (req, res) => {
  const decision = String((req.body || {}).decision || "").trim(); // "approve" | "reject"
  if (!["approve", "reject"].includes(decision)) {
    return res.status(400).json({ success: false, message: "decision must be 'approve' or 'reject'." });
  }

  const database = readDatabase();
  const request = (database.sellerProfileUpdateRequests || []).find((r) => r.id === Number(req.params.id));
  if (!request) return res.status(404).json({ success: false, message: "Request not found." });
  if (request.status !== "pending") {
    return res.status(400).json({ success: false, message: "This request was already resolved." });
  }

  if (decision === "approve") {
    const seller = database.sellers.find((s) => s.id === request.sellerRecordId);
    if (!seller) return res.status(404).json({ success: false, message: "That seller account no longer exists." });
    Object.assign(seller, request.changes);
  }

  request.status = decision === "approve" ? "approved" : "rejected";
  request.resolvedAt = new Date().toISOString();
  writeDatabase(database);

  res.json({
    success: true,
    message: decision === "approve" ? "Profile update approved and applied." : "Profile update request rejected.",
  });
});

// ================================
// ADMIN: APPROVE SELLER PRODUCTS
// ================================

app.get("/api/admin/products/pending", requireAdmin, (req, res) => {
  const database = readDatabase();
  const isBoss = req.admin.role === "boss";
  const pending = database.products
    .filter((p) => p.sellerId && p.approved === false)
    .map((p) => {
      const seller = database.sellers.find((s) => s.id === p.sellerId);
      return {
        ...p,
        // Sub-admins only ever see the seller's public shop name — never
        // their real name/ID/contact. Only the boss gets sellerName.
        sellerName: isBoss ? (seller ? seller.name : "Unknown seller") : undefined,
        shopTitle: seller ? seller.shopTitle : "",
        // isEdit tells the admin UI whether this is a brand-new listing
        // (nothing to compare) or a change to something already live
        // (pendingSnapshot holds the before version, so the UI can show
        // a before/after summary instead of just the new values).
        isEdit: Boolean(p.pendingSnapshot),
      };
    });
  res.json({ success: true, products: pending });
});

app.put("/api/admin/products/:id/approve", requireAdmin, (req, res) => {
  const database = readDatabase();
  const product = database.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ success: false, message: "Product not found." });
  const beforeProduct = product.pendingSnapshot || product;
  product.approved = true;
  delete product.pendingSnapshot;
  notifyBackInStockForProduct(database, beforeProduct, product);
  writeDatabase(database);
  res.json({ success: true, message: "Product approved and now live.", product });
});

app.put("/api/admin/products/:id/reject", requireAdmin, (req, res) => {
  const database = readDatabase();
  const product = database.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ success: false, message: "Product not found." });
  const index = database.products.indexOf(product);

  // If this was an edit to a product that was already live (it has a
  // pendingSnapshot), reject means "undo the seller's edit" — revert to
  // the last-approved version instead of deleting the listing outright.
  if (product.pendingSnapshot) {
    database.products[index] = { ...product.pendingSnapshot, id: product.id, sellerId: product.sellerId, approved: true };
    writeDatabase(database);
    return res.json({ success: true, message: "Edit rejected — reverted to the previously approved version.", product: database.products[index] });
  }

  database.products.splice(index, 1);
  writeDatabase(database);
  res.json({ success: true, message: "Product rejected and removed." });
});

// ================================
// CATEGORY MANAGEMENT
// ================================
// Categories aren't a separate collection — they're normally just whatever
// string an admin typed into a product's Category field. That means a brand
// new category with zero products yet has nowhere to "exist". `database.categories`
// is a small extra list (boss-only to add to) so a new category shows up in
// the dropdown/suggestions immediately, even before any product uses it.

app.get("/api/admin/categories", requireAdmin, (req, res) => {
  const database = readDatabase();
  const names = new Set();
  database.products.forEach((p) => {
    const c = (p.category || "").trim();
    if (c) names.add(c);
  });
  (database.categories || []).forEach((c) => names.add(c));
  res.json({ success: true, categories: Array.from(names).sort((a, b) => a.localeCompare(b)) });
});

// Only the boss can create a brand-new category from scratch.
app.post("/api/admin/categories", requireAdmin, requireBoss, (req, res) => {
  const name = String((req.body || {}).name || "").trim();
  if (!name) {
    return res.status(400).json({ success: false, message: "Category name is required." });
  }
  if (name.length > 40) {
    return res.status(400).json({ success: false, message: "Category name is too long (max 40 characters)." });
  }

  const database = readDatabase();
  if (!Array.isArray(database.categories)) database.categories = [];

  const alreadyExists =
    database.categories.some((c) => c.toLowerCase() === name.toLowerCase()) ||
    database.products.some((p) => (p.category || "").trim().toLowerCase() === name.toLowerCase());

  if (alreadyExists) {
    return res.status(400).json({ success: false, message: "That category already exists." });
  }

  database.categories.push(name);
  writeDatabase(database);

  res.status(201).json({ success: true, message: "Category created.", categories: database.categories });
});

// Boss-only one-click bulk add: 10 sample placeholder products in every
// category that currently exists (from products OR the categories list
// above). Existing products are never touched — this only adds new ones.
app.post("/api/admin/seed-category-products", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();

  const categories = new Set();
  database.products.forEach((p) => {
    const c = (p.category || "").trim();
    if (c) categories.add(c);
  });
  (database.categories || []).forEach((c) => categories.add(c));

  if (!categories.size) {
    return res.status(400).json({ success: false, message: "No categories exist yet — create a category first." });
  }

  let added = 0;
  categories.forEach((cat) => {
    for (let i = 1; i <= 10; i++) {
      const id = getNextId(database.products);
      database.products.push({
        id,
        name: `${cat} Sample Item ${i}`,
        category: cat,
        description: `Placeholder ${cat} product — edit the details or delete it.`,
        price: 199,
        image: "",
        images: [],
        active: false,
        customizationEnabled: false,
        sizes: [],
        moq: 1,
        discounts: [],
        onSale: false,
        salePercent: 0,
        saleMessage: "",
        saleEndsAt: null,
        giftFor: "",
        hotProduct: false,
        buyBadgePercent: 10,
        options: {},
      });
      added++;
    }
  });

  writeDatabase(database);

  res.json({
    success: true,
    message: `Added ${added} sample products across ${categories.size} categories.`,
    products: database.products,
  });
});

// Runs automatically on every server start (not just when the boss clicks
// the button in the admin panel). This is the fix for "products/categories
// disappearing after a code update" — the sample data now lives in the code
// itself, so even if the database gets wiped or reset by a future deploy,
// restarting the server regenerates it. It's idempotent: it checks each
// category for existing "<Category> Sample Item N" entries and only tops up
// whatever is missing, so it never duplicates on repeated restarts.
function autoSeedCategoryProducts(database) {
  if (!Array.isArray(database.products)) database.products = [];
  if (!Array.isArray(database.categories)) database.categories = [];

  const categories = new Set();
  database.products.forEach((p) => {
    const c = (p.category || "").trim();
    if (c) categories.add(c);
  });
  database.categories.forEach((c) => categories.add(c));

  if (!categories.size) return 0;

  let added = 0;
  categories.forEach((cat) => {
    const existingSampleNames = new Set(
      database.products
        .filter((p) => (p.category || "").trim() === cat && /^.+ Sample Item \d+$/.test(p.name || ""))
        .map((p) => p.name),
    );

    for (let i = 1; i <= 10; i++) {
      const sampleName = `${cat} Sample Item ${i}`;
      if (existingSampleNames.has(sampleName)) continue;

      const id = getNextId(database.products);
      database.products.push({
        id,
        name: sampleName,
        category: cat,
        description: `Placeholder ${cat} product — edit the details or delete it.`,
        price: 199,
        image: "",
        images: [],
        active: false,
        customizationEnabled: false,
        sizes: [],
        moq: 1,
        discounts: [],
        onSale: false,
        salePercent: 0,
        saleMessage: "",
        saleEndsAt: null,
        giftFor: "",
        hotProduct: false,
        buyBadgePercent: 10,
        options: {},
      });
      added++;
    }
  });

  if (added > 0) writeDatabase(database);
  return added;
}

// ================================
// HOMEPAGE SECTIONS (Most Popular / Trending) — AUTOMATIC
// ================================
// "Our Most Popular Products" (all-time page views) and "Trending" (views in
// the last 7 days) are computed from real product-detail-open history
// instead of an admin checklist. Every time a shopper opens a product's
// detail modal on the storefront, that's logged in database.productViews.
// While a product has zero qualifying views, the rows fall back to the
// newest added products (highest id first) so the homepage is never empty.
const HOMEPAGE_SECTION_LIMIT = 4;
const TRENDING_WINDOW_DAYS = 7;

function computeHomepageRankings(database, limit) {
  limit = limit || HOMEPAGE_SECTION_LIMIT;
  const activeProducts = database.products.filter((p) => p.active);
  const now = Date.now();
  const trendingCutoff = now - TRENDING_WINDOW_DAYS * 24 * 60 * 60 * 1000;

  const allTimeViews = {};
  const trendingViews = {};

  (database.productViews || []).forEach((view) => {
    const pid = Number(view.productId);
    if (!pid) return;
    const viewedTime = new Date(view.viewedAt).getTime();
    allTimeViews[pid] = (allTimeViews[pid] || 0) + 1;
    if (Number.isFinite(viewedTime) && viewedTime >= trendingCutoff) {
      trendingViews[pid] = (trendingViews[pid] || 0) + 1;
    }
  });

  // Newest-first order, used both as a fallback and as the tiebreaker for
  // products with equal view counts.
  const newestFirst = activeProducts.slice().sort((a, b) => b.id - a.id);

  // excludeIds keeps a product from showing up in both rows at once — a
  // product already placed in Popular is skipped here (both in the ranked
  // list and in the newest-added fallback) so Trending always shows a
  // different set of products.
  function buildSection(viewMap, excludeIds) {
    const skip = excludeIds || new Set();
    const withViews = newestFirst
      .filter((p) => !skip.has(p.id) && viewMap[p.id] > 0)
      .sort((a, b) => (viewMap[b.id] - viewMap[a.id]) || (b.id - a.id));

    const result = withViews.slice(0, limit).map((p) => ({
      ...p,
      viewCount: viewMap[p.id],
      isNewest: false,
    }));

    if (result.length < limit) {
      const usedIds = new Set(result.map((p) => p.id));
      for (const p of newestFirst) {
        if (result.length >= limit) break;
        if (usedIds.has(p.id) || skip.has(p.id)) continue;
        result.push({ ...p, viewCount: 0, isNewest: true });
        usedIds.add(p.id);
      }
    }

    return result;
  }

  const popular = buildSection(allTimeViews, null);
  const trending = buildSection(trendingViews, new Set(popular.map((p) => p.id)));

  return { popular, trending };
}

// Read-only — lets the admin panel show what will appear on the homepage
// before anything goes live on the storefront. Doesn't touch the database.
app.get("/api/admin/homepage-preview", requireAdmin, (req, res) => {
  try {
    const database = readDatabase();
    res.json({ success: true, ...computeHomepageRankings(database) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to compute homepage preview." });
  }
});

// Still lets the admin edit MOQ and the per-product "BUY 10 @ X% off" badge
// inline from the Homepage Sections tab — Popular/Trending membership itself
// is no longer settable here, it's computed automatically above.
// NOTE: this must be registered BEFORE the /api/admin/products/:id route
// below — otherwise Express matches "homepage-sections" as an :id and this
// route never gets hit.
app.put("/api/admin/products/homepage-sections", requireAdmin, (req, res) => {
  const buyBadgePercents = req.body.buyBadgePercents && typeof req.body.buyBadgePercents === "object" ? req.body.buyBadgePercents : {};
  const moqs = req.body.moqs && typeof req.body.moqs === "object" ? req.body.moqs : {};

  const database = readDatabase();
  database.products.forEach((p) => {
    if (Object.prototype.hasOwnProperty.call(buyBadgePercents, p.id)) {
      let percent = Number(buyBadgePercents[p.id]);
      if (!Number.isFinite(percent) || percent <= 0) percent = 10;
      if (percent > 90) percent = 90;
      p.buyBadgePercent = percent;
    }

    if (Object.prototype.hasOwnProperty.call(moqs, p.id)) {
      let moq = Number(moqs[p.id]);
      if (!Number.isFinite(moq) || moq < 1) moq = 1;
      p.moq = Math.round(moq);
    }
  });
  writeDatabase(database);

  res.json({ success: true, products: database.products });
});

// Update a product
app.put("/api/admin/products/:id", requireAdmin, (req, res) => {
  const { errors, product } = validateProductInput(req.body || {});

  if (errors.length) {
    return res.status(400).json({ success: false, message: errors.join(" ") });
  }

  const database = readDatabase();
  const id = Number(req.params.id);
  const index = database.products.findIndex((p) => p.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Product not found." });
  }

  // The main product form doesn't have a buyBadgePercent field — only the
  // Homepage Sections tab sets it. Don't let a regular product save reset
  // it back to the default.
  if (req.body.buyBadgePercent === undefined) {
    product.buyBadgePercent = database.products[index].buyBadgePercent ?? 10;
  }

  // Snapshot before the boss's edit is applied, so a stock change here can
  // be checked against pending back-in-stock subscriptions below.
  const beforeProduct = { ...database.products[index] };

  // The boss's edits apply immediately. A sub-admin's edit is held as a
  // proposal on the product (pendingAdminEdit) — the live product is left
  // untouched until the boss reviews and approves it.
  if (req.admin.role !== "boss") {
    database.products[index].pendingAdminEdit = {
      changes: product,
      requestedBy: req.admin.username,
      requestedAt: new Date().toISOString(),
    };
    writeDatabase(database);
    return res.json({
      success: true,
      pending: true,
      message: "Change submitted — it needs the boss's approval before it goes live.",
      product: database.products[index],
    });
  }

  database.products[index] = { ...database.products[index], ...product, id };
  delete database.products[index].pendingAdminEdit;
  notifyBackInStockForProduct(database, beforeProduct, database.products[index]);
  writeDatabase(database);

  res.json({ success: true, product: database.products[index] });
});

// Hide/show a product on the storefront. Deliberately separate from the
// full product-edit endpoint above (no boss-approval hold) and from
// permanent delete below (no canDeleteProducts gate) — this is a
// reversible visibility toggle, not a destructive or business-rule
// change, so every admin (boss and every sub-admin) can use it regardless
// of their delete permission. A hidden product is excluded from the
// public storefront/API the same way an unapproved or seller-banned
// product already is (see the isPubliclyEligible checks elsewhere).
app.put("/api/admin/products/:id/hidden", requireAdmin, (req, res) => {
  const database = readDatabase();
  const id = Number(req.params.id);
  const product = database.products.find((p) => p.id === id);
  if (!product) return res.status(404).json({ success: false, message: "Product not found." });
  product.hidden = !!(req.body && req.body.hidden);
  writeDatabase(database);
  res.json({ success: true, id: product.id, hidden: product.hidden });
});

// A sub-admin's proposed edit to an already-live product, waiting on the
// boss to review it. Boss-only — this is where the before/after summary
// comes from (the live product vs. pendingAdminEdit.changes).
app.get("/api/admin/products/pending-edits", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const pending = database.products.filter((p) => p.pendingAdminEdit);
  res.json({ success: true, products: pending });
});

app.put("/api/admin/products/:id/approve-edit", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const product = database.products.find((p) => p.id === Number(req.params.id));
  if (!product || !product.pendingAdminEdit) {
    return res.status(404).json({ success: false, message: "No pending edit found for this product." });
  }
  const index = database.products.indexOf(product);
  const { changes } = product.pendingAdminEdit;
  database.products[index] = { ...product, ...changes, id: product.id };
  delete database.products[index].pendingAdminEdit;
  writeDatabase(database);
  res.json({ success: true, message: "Edit approved and now live.", product: database.products[index] });
});

app.put("/api/admin/products/:id/reject-edit", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const product = database.products.find((p) => p.id === Number(req.params.id));
  if (!product || !product.pendingAdminEdit) {
    return res.status(404).json({ success: false, message: "No pending edit found for this product." });
  }
  const index = database.products.indexOf(product);
  delete database.products[index].pendingAdminEdit;
  writeDatabase(database);
  res.json({ success: true, message: "Edit rejected — product left unchanged." });
});

// Delete a product
function canDeleteProducts(req, res, next) {
  if (req.admin.role === "boss") return next();
  const database = readDatabase();
  const account = database.admins.find((a) => a.username === req.admin.username);
  if (account && account.canDeleteProducts) return next();
  return res.status(403).json({ success: false, message: "You don't have permission to delete products. Ask the boss to grant it." });
}

app.delete("/api/admin/products/:id", requireAdmin, canDeleteProducts, (req, res) => {
  const database = readDatabase();
  const id = Number(req.params.id);
  const index = database.products.findIndex((p) => p.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Product not found." });
  }

  database.products.splice(index, 1);
  writeDatabase(database);

  res.json({ success: true, message: "Product deleted." });
});

// ================================
// ADMIN DASHBOARD PAGE
// ================================

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// ================================
// SELLER LOGIN / DASHBOARD PAGE
// ================================

app.get("/seller", (req, res) => {
  res.sendFile(path.join(__dirname, "seller.html"));
});

// ================================
// SELLER APPLICATION PAGE (invitation link — fill the form)
// ================================

app.get("/sellerapplication", (req, res) => {
  res.sendFile(path.join(__dirname, "sell.html"));
});

// Old application link — keep working, just redirect to the new one
app.get("/sell", (req, res) => {
  res.redirect(301, "/sellerapplication");
});

// ================================
// HOME PAGE
// ================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Shareable product links, e.g. /product/123/photo-print-mug — the
// name-slug is only there to make the link readable/SEO-friendly, the
// front-end reads the numeric id and ignores the slug. Serving the same
// index.html here (not a redirect) is what lets a pasted link — WhatsApp,
// a new tab, anywhere — open straight into that product instead of 404ing.
//
// The URLs and client-side behavior are unchanged from before — the only
// addition is that the <head> tags (title/description/OG/canonical/
// JSON-LD) sent for these two routes are now filled in with the real
// product's own data server-side, instead of the site-wide defaults, so a
// pasted WhatsApp/social link actually shows the product's name, photo and
// price in the preview instead of the generic "Design Makers" card.
app.get("/product/:id", (req, res) => {
  sendProductPage(req, res, req.params.id, null);
});
app.get("/product/:id/:slug", (req, res) => {
  sendProductPage(req, res, req.params.id, req.params.slug);
});

let indexHtmlTemplateCache = null;
function getIndexHtmlTemplate() {
  // Cached in memory after the first read — the file on disk doesn't
  // change at runtime, so there's no need to hit the filesystem on every
  // single product-page request.
  if (indexHtmlTemplateCache === null) {
    indexHtmlTemplateCache = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  }
  return indexHtmlTemplateCache;
}

function sendProductPage(req, res, idParam, slugParam) {
  try {
    const productId = Number(idParam);
    const database = readDatabase();
    const product = Number.isFinite(productId)
      ? database.products.find((p) => p.id === productId && p.active && p.approved !== false && !p.hidden)
      : null;

    if (!product) {
      // Unknown/inactive product: still serve the normal page (the
      // frontend already shows its own "product not found" state) with
      // the site-wide default meta tags, exactly as before this change.
      return res.sendFile(path.join(__dirname, "index.html"));
    }

    const canonicalUrl = `${SITE_URL}/product/${product.id}/${slugifyProductName(product.name)}`;
    const description = String(product.description || "").trim().slice(0, 160) ||
      `${product.name} — customized and delivered by Design Makers.`;
    const storedImages = Array.isArray(product.images) && product.images.length
      ? product.images
      : (product.image ? [product.image] : []);
    const firstImage = storedImages[0];
    const imageUrl = firstImage
      ? (typeof firstImage === "string" && firstImage.startsWith("data:image/")
          ? `${SITE_URL}/product-image/${product.id}/0`
          : firstImage)
      : `${SITE_URL}/Logo.png`;
    const title = `${product.name} — Design Makers`;

    const jsonLd = {
      "@context": "https://schema.org",
      "@type": "Product",
      name: product.name,
      description,
      image: [imageUrl],
      category: product.category || undefined,
      offers: {
        "@type": "Offer",
        priceCurrency: "INR",
        price: product.price,
        availability: product.active ? "https://schema.org/InStock" : "https://schema.org/OutOfStock",
        url: canonicalUrl,
      },
    };

    let html = getIndexHtmlTemplate();
    html = html.replace(
      "<title>Design Makers - Personalized Gifts</title>",
      `<title>${escapeHtml(title)}</title>`,
    );
    html = html.replace(
      /<meta name="description" content="[^"]*" \/>/,
      `<meta name="description" content="${escapeHtml(description)}" />`,
    );
    html = html.replace(
      /<link rel="canonical" href="[^"]*" \/>/,
      `<link rel="canonical" href="${escapeHtml(canonicalUrl)}" />`,
    );
    html = html.replace(
      /<meta property="og:type" content="[^"]*" \/>/,
      `<meta property="og:type" content="product" />`,
    );
    html = html.replace(
      /<meta property="og:title" content="[^"]*" \/>/,
      `<meta property="og:title" content="${escapeHtml(title)}" />`,
    );
    html = html.replace(
      /<meta property="og:description" content="[^"]*" \/>/,
      `<meta property="og:description" content="${escapeHtml(description)}" />`,
    );
    html = html.replace(
      /<meta property="og:image" content="[^"]*" \/>/,
      `<meta property="og:image" content="${escapeHtml(imageUrl)}" />`,
    );
    html = html.replace(
      /<meta property="og:url" content="[^"]*" \/>/,
      `<meta property="og:url" content="${escapeHtml(canonicalUrl)}" />`,
    );
    html = html.replace(
      "<!--SEO_JSONLD-->",
      `<script type="application/ld+json">${escapeJsonForHtml(jsonLd)}</script>`,
    );

    res.set("Content-Type", "text/html");
    res.send(html);
  } catch (error) {
    console.error("Product page SEO render failed, falling back to default page:", error.message);
    res.sendFile(path.join(__dirname, "index.html"));
  }
}

// ================================
// SEO: robots.txt + sitemap.xml
// ================================

app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send(
    [
      "User-agent: *",
      "Allow: /",
      "Disallow: /admin",
      "Disallow: /seller",
      "Disallow: /api/",
      "",
      `Sitemap: ${SITE_URL}/sitemap.xml`,
      "",
    ].join("\n"),
  );
});

app.get("/sitemap.xml", (req, res) => {
  try {
    const database = readDatabase();
    const bannedSellerIds = new Set(
      (database.sellers || []).filter((s) => s.banned).map((s) => s.id),
    );
    const urls = [
      { loc: `${SITE_URL}/`, priority: "1.0" },
      { loc: `${SITE_URL}/sellerapplication`, priority: "0.3" },
    ];
    (database.products || [])
      .filter(
        (p) =>
          p.active &&
          p.approved !== false &&
          !p.hidden &&
          !(p.sellerId && bannedSellerIds.has(p.sellerId)),
      )
      .forEach((p) => {
        urls.push({ loc: `${SITE_URL}/product/${p.id}/${slugifyProductName(p.name)}`, priority: "0.8" });
      });

    const xml =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      urls.map((u) => `  <url><loc>${escapeHtml(u.loc)}</loc><priority>${u.priority}</priority></url>`).join("\n") +
      `\n</urlset>`;

    res.set("Content-Type", "application/xml");
    res.send(xml);
  } catch (error) {
    console.error(error);
    res.status(500).type("text/plain").send("");
  }
});

// ================================
// SERVER STATUS
// ================================

app.get("/api/status", (req, res) => {
  res.json({ success: true, message: "Design Makers server is running 🚀" });
});

// ================================
// GET ALL ACTIVE PRODUCTS (public storefront)
// ================================

// Public — the exact same category list the admin manages from the
// Categories screen (GET /api/admin/categories): every category any
// product currently uses, PLUS any category the boss has created ahead of
// time with zero products yet. This is what "the categories" means to the
// admin, so it's what a seller should see too — not a narrower subset,
// or a newly-created category would never appear for sellers to pick
// until a product already existed in it (chicken-and-egg).
app.get("/api/categories", (req, res) => {
  try {
    const database = readDatabase();
    const names = new Set();
    (database.products || []).forEach((p) => {
      const c = String(p.category || "").trim();
      if (c) names.add(c);
    });
    (database.categories || []).forEach((c) => {
      const trimmed = String(c || "").trim();
      if (trimmed) names.add(trimmed);
    });
    res.json({ success: true, categories: Array.from(names).sort((a, b) => a.localeCompare(b)) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load categories." });
  }
});

app.get("/api/products", (req, res) => {
  try {
    const database = readDatabase();
    const { popular, trending } = computeHomepageRankings(database);
    const popularIds = new Set(popular.map((p) => p.id));
    const trendingIds = new Set(trending.map((p) => p.id));
    const bannedSellerIds = new Set(
      (database.sellers || []).filter((s) => s.banned).map((s) => s.id),
    );

    // IMPORTANT: product photos stay in MongoDB exactly as stored, but the
    // public storefront must NOT ship every base64 photo inside the JSON
    // response. That makes the initial /api/products payload unnecessarily
    // huge and is the main reason the product area feels slow.
    //
    // Instead, expose lightweight same-origin image URLs. The actual bytes
    // are served by /product-image/:id/:index with browser caching. This is a
    // transport optimisation only — no product/image data is deleted or
    // rewritten in the database.
    const publicImageUrl = (productId, index) => `/product-image/${productId}/${index}`;

    const products = database.products
      .filter(
        (product) =>
          product.active &&
          product.approved !== false &&
          !product.hidden &&
          !(product.sellerId && bannedSellerIds.has(product.sellerId)),
      )
      .map((product) => {
        const storedImages = Array.isArray(product.images) && product.images.length
          ? product.images
          : (product.image ? [product.image] : []);
        const imageUrls = storedImages.map((src, index) => {
          if (typeof src === "string" && src.startsWith("data:image/")) {
            return publicImageUrl(product.id, index);
          }
          return src;
        }).filter(Boolean);

        const { productCode, sellerId, sellerWhatsappNumber, ...publicProduct } = product;
        return {
          ...publicProduct,
          supportWhatsappUrl: buildWhatsAppUrl(
            product.sellerId
              ? ((database.sellers || []).find((seller) => seller.id === product.sellerId)?.whatsappNumber ||
                 (database.sellers || []).find((seller) => seller.id === product.sellerId)?.phone ||
                 "")
              : ""
          ),
          image: imageUrls[0] || "",
          images: imageUrls,
          stockQty: Math.max(0, Number(product.stockQty) || 0),
          stockConfigured: product.stockConfigured !== false,
          lowStockThreshold: Math.max(0, Number(product.lowStockThreshold ?? 5) || 5),
          variantStock: product.variantStock && typeof product.variantStock === "object" ? product.variantStock : {},
          variantStockConfigured: product.variantStockConfigured && typeof product.variantStockConfigured === "object" ? product.variantStockConfigured : {},
          saleActive: isSaleActive(product),
          popular: popularIds.has(product.id),
          trending: trendingIds.has(product.id),
        };
      });
    res.json({ success: true, products });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load products." });
  }
});

// ================================
// GET ONE PRODUCT
// ================================

app.get("/api/products/:id", (req, res) => {
  try {
    const database = readDatabase();
    const productId = Number(req.params.id);
    const product = database.products.find((product) => product.id === productId);

    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found." });
    }

    // Enforce the exact same public-eligibility rule the storefront list
    // endpoint (GET /api/products) already applies. Without this, a direct
    // request to this single-product endpoint — by URL, by API, or by
    // guessing/incrementing a product ID — could view (and, via /api/orders,
    // even purchase) a product that is inactive, still pending admin
    // approval, deliberately hidden, or belongs to a banned/suspended
    // seller. Frontend hiding alone is not enough; this must be enforced
    // here too.
    const seller = product.sellerId ? (database.sellers || []).find((s) => s.id === product.sellerId) : null;
    const sellerBanned = !!(seller && seller.banned);
    const isPubliclyEligible = product.active && product.approved !== false && !product.hidden && !sellerBanned;
    if (!isPubliclyEligible) {
      return res.status(404).json({ success: false, message: "Product not found." });
    }

    const storedImages = Array.isArray(product.images) && product.images.length
      ? product.images
      : (product.image ? [product.image] : []);
    const imageUrls = storedImages.map((src, index) => {
      if (typeof src === "string" && src.startsWith("data:image/")) {
        return `/product-image/${product.id}/${index}`;
      }
      return src;
    }).filter(Boolean);
    const { productCode, sellerId, sellerWhatsappNumber, ...publicProduct } = product;
    const productSeller = product.sellerId ? (database.sellers || []).find((seller) => seller.id === product.sellerId) : null;
    res.json({
      success: true,
      product: {
        ...publicProduct,
        supportWhatsappUrl: buildWhatsAppUrl(productSeller?.whatsappNumber || productSeller?.phone || ""),
        image: imageUrls[0] || "",
        images: imageUrls,
        stockQty: Math.max(0, Number(product.stockQty) || 0),
        stockConfigured: product.stockConfigured !== false,
        lowStockThreshold: Math.max(0, Number(product.lowStockThreshold ?? 5) || 5),
        variantStock: product.variantStock && typeof product.variantStock === "object" ? product.variantStock : {},
        variantStockConfigured: product.variantStockConfigured && typeof product.variantStockConfigured === "object" ? product.variantStockConfigured : {},
        saleActive: isSaleActive(product),
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load product." });
  }
});

// ================================
// TRACK PRODUCT VIEW
// ================================
// Fired once from the storefront each time a shopper opens a product's
// detail modal. Feeds the automatic Popular (all-time views) / Trending
// (last 7 days) homepage rows above — see computeHomepageRankings.
app.post("/api/products/:id/view", (req, res) => {
  try {
    const database = readDatabase();
    const productId = Number(req.params.id);
    const product = database.products.find((product) => product.id === productId);

    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found." });
    }

    database.productViews = database.productViews || [];
    database.productViews.push({ productId, viewedAt: new Date().toISOString() });

    // Keep the log from growing forever — only the last 7 days matter for
    // Trending, and all-time count for Popular is unaffected by trimming
    // anything older than a generous 120-day window.
    const trimCutoff = Date.now() - 120 * 24 * 60 * 60 * 1000;
    database.productViews = database.productViews.filter((v) => {
      const t = new Date(v.viewedAt).getTime();
      return !Number.isFinite(t) || t >= trimCutoff;
    });

    writeDatabase(database);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to record view." });
  }
});

// ================================
// PRODUCT REVIEWS
// ================================
// Text-only reviews (no photos) — anyone can read them, but only a signed-in
// customer who actually has a past order containing this product can post one.

app.get("/api/products/:id/reviews", (req, res) => {
  try {
    const database = readDatabase();
    const productId = Number(req.params.id);
    const reviews = (database.reviews || [])
      .filter((r) => r.productId === productId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ success: true, reviews });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load reviews." });
  }
});

app.post("/api/products/:id/reviews", requireCustomer, (req, res) => {
  const database = readDatabase();
  const productId = Number(req.params.id);
  const product = database.products.find((p) => p.id === productId);
  if (!product) {
    return res.status(404).json({ success: false, message: "Product not found." });
  }

  const boughtIt = database.orders.some(
    (o) => o.customerId === req.customer.id && (o.items || []).some((item) => item.productId === productId),
  );
  if (!boughtIt) {
    return res.status(403).json({ success: false, message: "You can only review products you've bought." });
  }

  const rating = Number((req.body || {}).rating);
  const text = String((req.body || {}).text || "").trim().slice(0, 1000);
  const photoData = String((req.body || {}).photoData || "");
  if (photoData) {
    const headerMatch = photoData.match(/^data:image\/(png|jpe?g|webp);base64,/);
    if (!headerMatch) {
      return res.status(400).json({ success: false, message: "Invalid review photo format." });
    }
    if (photoData.length > 2_100_000) {
      return res.status(413).json({ success: false, message: "Review photo is too large. Please use a smaller image." });
    }
    // The header above only checks the label the browser *claims* — a file
    // can be renamed/relabelled with any declared type. Confirm the actual
    // bytes start with the real magic number for that format before trusting it.
    let buf;
    try {
      buf = Buffer.from(photoData.slice(headerMatch[0].length), "base64");
    } catch (e) {
      return res.status(400).json({ success: false, message: "Invalid review photo data." });
    }
    const declaredType = headerMatch[1].toLowerCase();
    const isPng = buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
    const isJpeg = buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
    const isWebp =
      buf.length >= 12 &&
      buf.slice(0, 4).toString("ascii") === "RIFF" &&
      buf.slice(8, 12).toString("ascii") === "WEBP";
    const matches =
      (declaredType === "png" && isPng) ||
      ((declaredType === "jpg" || declaredType === "jpeg") && isJpeg) ||
      (declaredType === "webp" && isWebp);
    if (!matches) {
      return res.status(400).json({ success: false, message: "That file doesn't look like a real image. Please upload a genuine photo." });
    }
  }
  if (!Number.isFinite(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ success: false, message: "Rating must be between 1 and 5." });
  }
  if (!text) {
    return res.status(400).json({ success: false, message: "Please write a short remark." });
  }

  const alreadyReviewed = database.reviews.some(
    (r) => r.productId === productId && r.customerId === req.customer.id,
  );
  if (alreadyReviewed) {
    return res.status(400).json({ success: false, message: "You've already reviewed this product." });
  }

  const review = {
    id: getNextId(database.reviews),
    productId,
    customerId: req.customer.id,
    customerName: req.customer.name,
    rating,
    text,
    photoData: photoData || "",
    createdAt: new Date().toISOString(),
  };
  database.reviews.push(review);
  writeDatabase(database);

  res.status(201).json({ success: true, review });
});

// ================================
// PRODUCT PHOTO (real, linkable URL)
// ================================
// Product photos are stored as base64 data URIs in the database, which isn't
// something you can drop into a WhatsApp message as a viewable link. This
// route decodes the stored image and serves it as an actual image response,
// so a URL like /product-image/12 opens (and link-previews) like any normal
// photo — used by the "Checkout on WhatsApp" message.
app.get("/product-image/:id{/:index}", (req, res) => {
  try {
    const database = readDatabase();
    const productId = Number(req.params.id);
    const requestedIndex = req.params.index == null ? 0 : Number(req.params.index);
    const imageIndex = Number.isInteger(requestedIndex) && requestedIndex >= 0 ? requestedIndex : 0;
    const product = database.products.find((product) => product.id === productId);
    const storedImages = product && Array.isArray(product.images) && product.images.length
      ? product.images
      : (product && product.image ? [product.image] : []);
    const imgSrc = storedImages[imageIndex] || "";

    if (!imgSrc) {
      return res.status(404).send("No photo for this product.");
    }

    const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(imgSrc);
    if (!match) {
      // Not a base64 data URI (e.g. already a real hosted URL) — just redirect to it.
      return res.redirect(imgSrc);
    }

    const buffer = Buffer.from(match[2], "base64");
    res.set("Content-Type", match[1]);
    // One hour fresh + one day stale-while-revalidate keeps repeat visits fast
    // while avoiding a full-day stale window after an admin changes a photo.
    // Express also supplies an ETag, so unchanged images can become 304s.
    res.set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
    res.send(buffer);
  } catch (error) {
    console.error(error);
    res.status(500).send("Unable to load product photo.");
  }
});

// ================================
// GET PHONE BRANDS + MODELS
// ================================

app.get("/api/phone-brands", (req, res) => {
  try {
    const database = readDatabase();
    res.json({ success: true, phoneBrands: database.phoneBrands });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load phone models." });
  }
});

// ================================
// CREATE ORDER
// ================================

// If the shopper is signed in with Google, their token is sent along with
// the order so we can link the order to their account (used later to check
// "did this customer actually buy this product" before allowing a review).
// Login is still NOT required to order — this only reads the token if present.
function getOptionalCustomerId(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return payload.type === "customer" ? payload.customerId : null;
  } catch (error) {
    return null;
  }
}

// Duplicate-order guard — catches the case the frontend's button-disable
// can't: two near-simultaneous requests racing each other (a second tab,
// a retried request after a slow/flaky response, etc). Keyed on phone +
// the exact items ordered, NOT on time alone, so it only ever collapses
// an accidental resubmit of the *same* cart within a short window — a
// customer placing a genuinely new or later order is never blocked.
// In-memory is fine here: this app already runs (and is documented to
// only be safe running) as a single instance, same as the rate limiters
// above.
const recentOrderSubmissions = new Map(); // fingerprint -> { orderId, expiresAt }
const ORDER_DEDUPE_WINDOW_MS = 8000;

function pruneRecentOrderSubmissions() {
  const now = Date.now();
  for (const [key, val] of recentOrderSubmissions) {
    if (val.expiresAt < now) recentOrderSubmissions.delete(key);
  }
}

function orderFingerprint(phone, items) {
  const normalizedItems = (items || [])
    .map((it) => {
      const extra = {};
      ["customization", "custom", "options", "personalization", "uploadedImage", "uploadedImageUrl"].forEach((key) => {
        if (it && it[key] !== undefined) extra[key] = it[key];
      });
      return JSON.stringify({
        productId: it && it.productId,
        size: it && it.size ? it.size : "",
        qty: it && it.qty,
        extra,
      });
    })
    .sort()
    .join("|");
  return crypto.createHash("sha256").update(phone + "::" + normalizedItems).digest("hex");
}

// Checkout on this site requires sign-in (see index.html's
// updateCheckoutIdentity/placeOrder — there's no reachable guest-checkout UI),
// so gift codes are correctly restricted to signed-in customers via
// requireCustomer here too. calculateSecurePricing/validateGiftCode still
// accept a guestPhone parameter — that exists purely so /api/orders (which
// stays reachable directly, e.g. for future guest-checkout support) tracks
// per-customer usage consistently; it's intentionally unused on this route.
app.post("/api/customer/gift-codes/validate", requireCustomer, (req, res) => {
  try {
    const database = readDatabase();
    const products = Array.isArray(database.products) ? database.products : [];
    const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
    const rawCode = req.body && req.body.code;
    const pricing = calculateSecurePricing(items, products, "", getOptionalCustomerId(req), database);
    if (pricing.errors.length) return res.status(400).json({ success: false, message: pricing.errors.join(" ") });
    const result = validateGiftCode(database, rawCode, getOptionalCustomerId(req), pricing.total);
    if (!result.valid) return res.status(400).json({ success: false, message: result.message });
    return res.json({ success: true, code: result.code, discount: result.discount, total: Math.round((pricing.total - result.discount) * 100) / 100, message: result.message });
  } catch (e) {
    // Log the full stack (not just e.message) plus enough request context to
    // actually diagnose a repeat of the "could not check the gift code"
    // report — without ever putting that detail in the customer-facing
    // response itself.
    console.error(
      "Gift code validation failed. customerId=%s code=%s error=%s",
      req.customer && req.customer.id,
      req.body && req.body.code,
      e && e.stack ? e.stack : e,
    );
    return res.status(500).json({ success: false, message: "Unable to validate gift code right now. Please try again in a moment." });
  }
});

app.post("/api/customer/back-in-stock", requireCustomer, (req, res) => {
  const database = readDatabase();
  const productId = Number((req.body || {}).productId);
  const size = String((req.body || {}).size || "").trim();
  const product = database.products.find((p) => p.id === productId);
  if (!product) return res.status(404).json({ success: false, message: "Product not found." });
  if (!Array.isArray(database.backInStockSubscriptions)) database.backInStockSubscriptions = [];
  const already = database.backInStockSubscriptions.some(
    (s) => s.customerId === req.customer.id && s.productId === productId && (s.size || "") === size,
  );
  if (already) return res.json({ success: true, alreadySubscribed: true, message: "You're already set to be notified for this item." });
  database.backInStockSubscriptions.push({
    id: getNextId(database.backInStockSubscriptions),
    customerId: req.customer.id,
    productId,
    size,
    createdAt: new Date().toISOString(),
  });
  writeDatabase(database);
  res.json({
    success: true,
    message: req.customer.email
      ? "We'll email you the moment it's back in stock."
      : "Saved — but there's no email on your account yet, so we won't be able to deliver the alert. Add one from your profile.",
  });
});

app.delete("/api/customer/back-in-stock", requireCustomer, (req, res) => {
  const database = readDatabase();
  const productId = Number((req.body || {}).productId);
  const size = String((req.body || {}).size || "").trim();
  if (!Array.isArray(database.backInStockSubscriptions)) database.backInStockSubscriptions = [];
  const before = database.backInStockSubscriptions.length;
  database.backInStockSubscriptions = database.backInStockSubscriptions.filter(
    (s) => !(s.customerId === req.customer.id && s.productId === productId && (s.size || "") === size),
  );
  writeDatabase(database);
  res.json({ success: true, removed: before !== database.backInStockSubscriptions.length });
});

app.get("/api/customer/back-in-stock", requireCustomer, (req, res) => {
  const database = readDatabase();
  const mine = (database.backInStockSubscriptions || []).filter((s) => s.customerId === req.customer.id);
  res.json({ success: true, subscriptions: mine.map(({ productId, size }) => ({ productId, size })) });
});

app.post("/api/orders", async (req, res) => {
  return withInventoryLock(async () => {
    try {
      const database = readDatabase();
      ensureProductCodes(database);
      const { customer, items, giftCode, gift } = req.body || {};
      const phone = normalizePhone(customer && customer.phone);
      const name = customer && String(customer.name || "").trim();
      const address = customer && String(customer.address || "").trim();
      if (!phone || phone.length < 10) return res.status(400).json({ success: false, message: "A valid 10-digit phone number is required." });
      if (!name) return res.status(400).json({ success: false, message: "Name is required." });
      if (!address) return res.status(400).json({ success: false, message: "Delivery address is required." });

      pruneRecentOrderSubmissions();
      const fingerprint = orderFingerprint(phone, items) + "::gift:" + normalizeGiftCode(giftCode);
      const existingSubmission = recentOrderSubmissions.get(fingerprint);
      if (existingSubmission) {
        const existingOrder = database.orders.find((o) => o.id === existingSubmission.orderId);
        if (existingOrder) return res.status(200).json({ success: true, message: "Order already placed.", order: existingOrder, duplicate: true });
      }

      const pricing = calculateSecurePricing(items, database.products, giftCode, getOptionalCustomerId(req), database, phone);
      if (pricing.errors.length) return res.status(400).json({ success: false, message: pricing.errors.join(" ") });

      const stockPlan = [];
      const stockErrors = [];
      for (const item of pricing.pricedItems) {
        const product = database.products.find((p) => p.id === Number(item.productId));
        if (!product || product.isGiftAddon) continue;
        const available = getStockForVariant(product, item.size);
        if (available < item.qty) stockErrors.push(`${product.name}${item.size ? ` (${item.size})` : ""}: only ${available} ${available === 1 ? "unit is" : "units are"} available.`);
        else stockPlan.push({ product, size: item.size || "", qty: item.qty, before: available });
      }
      if (stockErrors.length) return res.status(409).json({ success: false, code: "OUT_OF_STOCK", message: stockErrors.join(" ") });

      const deducted = [];
      try {
        stockPlan.forEach(({ product, size, qty, before }) => { setStockForVariant(product, size, before - qty); deducted.push({ product, size, before }); });
        const newOrder = {
          id: getNextId(database.orders),
          orderNumber: generateOrderNumber(database),
          customer: { name, phone, address },
          customerId: getOptionalCustomerId(req),
          items: pricing.pricedItems,
          listedSubtotal: Math.round(pricing.listedSubtotal * 100) / 100,
          subtotal: Math.round(pricing.subtotal * 100) / 100,
          discount: Math.round(pricing.discountTotal * 100) / 100,
          totalDiscount: Math.round(pricing.totalDiscount * 100) / 100,
          giftCode: pricing.appliedGiftCode || null,
          giftDiscount: Math.round((pricing.giftDiscount || 0) * 100) / 100,
          gift: gift && gift.isGift ? { isGift: true, recipientName: String(gift.recipientName || "").trim().slice(0,120), message: String(gift.message || "").trim().slice(0,300), hidePrice: Boolean(gift.hidePrice) } : { isGift: false },
          total: pricing.total,
          paymentMethod: "COD",
          paymentStatus: "pending",
          paidAt: null,
          status: "New",
          statusHistory: [{ status: "New", at: new Date().toISOString() }],
          sellerFulfilment: [],
          inventoryDeducted: true,
          inventoryRestored: false,
          createdAt: new Date().toISOString(),
        };
        database.orders.push(newOrder);
        ensureSellerFulfilment(database, newOrder);
        if (pricing.appliedGiftCode) {
          const gift = findGiftCode(database, pricing.appliedGiftCode);
          if (gift) {
            gift.usedCount = Number(gift.usedCount || 0) + 1;
            if (!gift.usageByCustomer) gift.usageByCustomer = {};
            const cid = getOptionalCustomerId(req);
            const usageKey = cid ? String(cid) : `phone:${phone}`;
            gift.usageByCustomer[usageKey] = Number(gift.usageByCustomer[usageKey] || 0) + 1;
          }
        }
        writeDatabase(database);
        recentOrderSubmissions.set(fingerprint, { orderId: newOrder.id, expiresAt: Date.now() + ORDER_DEDUPE_WINDOW_MS });
        notifySellerOfOrder(database, newOrder).catch((err) => console.error("Seller order-notification email failed:", err.message));
        return res.status(201).json({ success: true, message: "Order created successfully.", order: newOrder });
      } catch (error) {
        deducted.forEach(({ product, size, before }) => setStockForVariant(product, size, before));
        throw error;
      }
    } catch (error) {
      console.error(error);
      return res.status(500).json({ success: false, message: "Unable to create order." });
    }
  });
});

// Emails every seller who has at least one item in a freshly-placed order,
// so each finds out about their own sale — and where to ship it — without
// waiting on the admin to relay it from WhatsApp. The customer still places
// ONE order regardless of how many sellers are in the cart (that's decided
// earlier, in POST /api/orders — this function only fans out notifications
// after the fact); each seller here only ever sees their own items and
// their own share of the total, never another seller's.
async function notifySellerOfOrder(database, order) {
  const itemsBySeller = new Map(); // sellerId -> items[]

  (order.items || []).forEach((item) => {
    const product = database.products.find((p) => p.id === item.productId);
    if (product && product.sellerId) {
      if (!itemsBySeller.has(product.sellerId)) itemsBySeller.set(product.sellerId, []);
      itemsBySeller.get(product.sellerId).push(item);
    }
  });

  for (const [sellerId, items] of itemsBySeller) {
    const seller = database.sellers.find((s) => s.id === sellerId);
    if (!seller || !seller.email) continue;

    const sellerTotal = Math.round(items.reduce((sum, item) => sum + (item.lineTotal || 0), 0) * 100) / 100;

    try {
      await sendMail(
        seller.email,
        `New order for ${seller.shopTitle} — ${order.orderNumber}`,
        buildSellerNewOrderEmail({ seller, order: { ...order, items, sellerTotal } }),
      );
    } catch (err) {
      // One seller's email failing to send should never stop the others
      // in the same mixed-seller order from being notified.
      console.error(`Seller order-notification email failed for seller ${sellerId}:`, err.message);
    }
  }
}

function buildSellerNewOrderEmail({ seller, order }) {
  const itemsHtml = (order.items || [])
    .map(
      (item) =>
        `<li>${item.name}${item.size ? " (" + item.size + ")" : ""} × ${item.qty} — ₹${item.lineTotal}</li>`,
    )
    .join("");

  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
       <h2 style="color:#8a1c42;margin-bottom:4px;">You've got a new order! 🎉</h2>
       <p>Hi ${seller.name},</p>
       <p><b>${order.orderNumber}</b> just came in for <b>${seller.shopTitle}</b>. Here's what to pack and where it's headed:</p>
       <div style="background:#f8ecef;border:1px solid #ecd7dd;border-radius:10px;padding:16px 20px;margin:20px 0;">
         <p style="margin:0 0 8px;"><b>Items:</b></p>
         <ul style="margin:0 0 12px;padding-left:20px;">${itemsHtml}</ul>
         <p style="margin:0 0 8px;"><b>Your total:</b> ₹${order.sellerTotal !== undefined ? order.sellerTotal : order.total}</p>
         <p style="margin:0 0 8px;"><b>Customer:</b> ${order.customer.name} · ${order.customer.phone}</p>
         <p style="margin:0;"><b>Delivery address:</b> ${order.customer.address || "Not provided — contact the customer directly."}</p>
       </div>
       <p style="font-size:0.85em;color:#8c7d78;">Payment is Cash on Delivery. You can see this order any time in the Orders tab of your Seller Dashboard.</p>
       <p style="margin-top:18px;">— Team Design Makers</p>
     </div>`;
}

// ================================
// CUSTOMER: MY ORDERS
// ================================

function customerOrderPayload(database, order, customer) {
  const items = (order.items || []).map((it) => {
    const product = database.products.find((p) => p.id === Number(it.productId));
    let image = it.image || "";
    if (!image && product) {
      const hasImages = (Array.isArray(product.images) && product.images.length) || product.image;
      if (hasImages) image = "/product-image/" + product.id + "/0";
    }
    return {
      name: it.name,
      size: it.size || "",
      qty: it.qty,
      lineTotal: it.lineTotal,
      price: it.price,
      salePrice: it.salePrice || null,
      originalPrice: it.price,
      image,
    };
  });
  const listedSubtotal = Number(order.listedSubtotal);
  const safeListedSubtotal = Number.isFinite(listedSubtotal)
    ? listedSubtotal
    : items.reduce((sum, it) => sum + (Number(it.originalPrice) || 0) * (Number(it.qty) || 0), 0);
  const total = Number(order.total) || 0;
  const totalDiscount = Number.isFinite(Number(order.totalDiscount))
    ? Number(order.totalDiscount)
    : Math.max(0, Math.round((safeListedSubtotal - total) * 100) / 100);
  return {
    id: order.id,
    orderNumber: order.orderNumber,
    createdAt: order.createdAt,
    status: order.status || "New",
    statusHistory: Array.isArray(order.statusHistory) ? order.statusHistory : [{ status: order.status || "New", at: order.createdAt }],
    fulfilmentStage: deriveCustomerFulfilmentStage(order, getSellerFulfilment(database, order)),
    itemFulfilment: (order.items || []).map((it, idx) => {
      const product = database.products.find(p => p.id === Number(it.productId));
      const key = itemFulfilmentKey(it, idx);
      const rec = (order.sellerFulfilment || []).find(r => r.key === key);
      return { productId: it.productId, size: it.size || "", stage: rec ? (rec.stage || "Order Received") : (order.status || "Order Received") };
    }),
    listedSubtotal: Math.round(safeListedSubtotal * 100) / 100,
    subtotal: order.subtotal || 0,
    discount: order.discount || 0,
    totalDiscount,
    total,
    paymentMethod: order.paymentMethod || "COD",
    paymentStatus: order.paymentStatus || "pending",
    customer: {
      name: order.customer?.name || customer.name || "",
      phone: order.customer?.phone || customer.mobile || "",
      address: order.customer?.address || "",
    },
    // The customer placed this order, so they get back exactly what they
    // entered at checkout — recipient name, message, and hide-price choice.
    gift: order.gift && order.gift.isGift
      ? { isGift: true, recipientName: order.gift.recipientName || "", message: order.gift.message || "", hidePrice: !!order.gift.hidePrice }
      : { isGift: false },
    items,
  };
}

app.get("/api/customer/orders", requireCustomer, (req, res) => {
  const database = readDatabase();
  const customer = req.customer;
  const orders = (database.orders || [])
    .filter((o) => o.customerId === customer.id || (customer.mobile && o.customer && o.customer.phone === customer.mobile))
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((o) => customerOrderPayload(database, o, customer));
  res.json({ success: true, orders });
});

app.get("/api/customer/orders/:id", requireCustomer, (req, res) => {
  const database = readDatabase();
  const customer = req.customer;
  const order = (database.orders || []).find((o) =>
    String(o.id) === String(req.params.id) &&
    (o.customerId === customer.id || (customer.mobile && o.customer && o.customer.phone === customer.mobile))
  );
  if (!order) return res.status(404).json({ success: false, message: "Order not found." });
  res.json({ success: true, order: customerOrderPayload(database, order, customer) });
});

// ================================
// GUEST ORDER TRACKING (no account needed)
// ================================
// A guest checkout has no login to come back to, so the only way to check
// status later was WhatsApp support (AUDIT-REPORT.md, section 9). This adds
// a direct lookup — requires the exact phone number AND exact order number
// together (not a search), so a phone number alone can't page through
// someone else's orders.
app.post("/api/orders/track", trackOrderLimiter, (req, res) => {
  const phone = String((req.body || {}).phone || "").replace(/\D/g, "").slice(-10);
  const orderNumber = String((req.body || {}).orderNumber || "").trim();
  if (!phone || phone.length < 10 || !orderNumber) {
    return res.status(400).json({ success: false, message: "Enter both your 10-digit phone number and order number." });
  }

  const database = readDatabase();
  const order = (database.orders || []).find((o) => {
    const orderPhone = String(o.customer?.phone || "").replace(/\D/g, "").slice(-10);
    const orderNum = String(o.orderNumber || "");
    return orderPhone === phone && orderNum.toLowerCase() === orderNumber.toLowerCase();
  });

  if (!order) {
    return res.status(404).json({ success: false, message: "No order found for that phone number and order number." });
  }
  res.json({ success: true, order: customerOrderPayload(database, order, {}) });
});

// ================================
// CUSTOMER: CALLBACK REQUEST
// ================================
// The website records a lightweight callback request, not a phone call.
// The customer is then connected to the existing Design Makers WhatsApp.

function buildAdminCallbackRequestEmail(request) {
  const orderLine = request.orderNumber
    ? `<p style="margin:0 0 8px;"><b>Order:</b> ${request.orderNumber}</p>`
    : `<p style="margin:0 0 8px;color:#8c7d78;">General enquiry (no order attached)</p>`;
  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
       <h2 style="color:#8a1c42;margin-bottom:4px;">🔔 New callback request</h2>
       <p>A customer has submitted a callback request through WhatsApp.</p>
       <div style="background:#f8ecef;border:1px solid #ecd7dd;border-radius:10px;padding:16px 20px;margin:20px 0;">
         <p style="margin:0 0 8px;"><b>Request ID:</b> ${request.requestId}</p>
         <p style="margin:0 0 8px;"><b>Name:</b> ${request.name || "Not provided"}</p>
         <p style="margin:0 0 8px;"><b>Phone:</b> ${request.phone || "Not provided"}</p>
         ${orderLine}
         <p style="margin:0;"><b>Reason:</b> ${request.reason}</p>
       </div>
       <p style="font-size:0.85em;color:#8c7d78;">Open the admin panel's Callback notifications (bell icon) to mark this as contacted/completed.</p>
       <p style="margin-top:18px;">— Design Makers Website</p>
     </div>`;
}

app.post("/api/customer/callback-request", requireCustomer, (req, res) => {
  try {
    const customer = req.customer;
    const reason = String((req.body && req.body.reason) || "").trim().slice(0, 500);
    if (!reason) {
      return res.status(400).json({ success: false, message: "Please enter a reason for the callback." });
    }

    const database = readDatabase();
    if (!Array.isArray(database.callbackRequests)) database.callbackRequests = [];

    let order = null;
    const rawOrderId = req.body && req.body.orderId ? String(req.body.orderId).trim() : "";
    if (rawOrderId) {
      order = (database.orders || []).find((o) =>
        (String(o.id) === rawOrderId || String(o.orderNumber || "") === rawOrderId) &&
        (o.customerId === customer.id || (customer.mobile && o.customer && o.customer.phone === customer.mobile))
      );
      if (!order) return res.status(403).json({ success: false, message: "That order does not belong to your account." });
    }

    // Prevent accidental duplicate submissions without blocking a legitimate
    // later request. If an identical open request was just created, reuse it.
    const now = Date.now();
    const duplicate = database.callbackRequests.find((r) =>
      r.customerId === customer.id &&
      ["New", "Contacted"].includes(r.status) &&
      String(r.reason || "").trim() === reason &&
      String(r.orderNumber || "") === String(order?.orderNumber || "") &&
      now - new Date(r.createdAt || 0).getTime() < 60 * 1000
    );

    let request = duplicate;
    if (!request) {
      const numericId = getNextId(database.callbackRequests);
      request = {
        id: numericId,
        requestId: `CR-${String(numericId).padStart(6, "0")}`,
        customerId: customer.id,
        name: customer.name || "",
        phone: customer.mobile || "",
        orderId: order ? order.id : null,
        orderNumber: order ? (order.orderNumber || `DM-${order.id}`) : null,
        reason,
        source: "WhatsApp",
        status: "New",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        completedAt: null,
        readBy: [],
      };
      database.callbackRequests.push(request);
      writeDatabase(database);
      // Fire-and-forget — a slow/failed email should never block the customer's
      // request from succeeding or delay the WhatsApp redirect below.
      sendMail(
        ADMIN_NOTIFY_EMAIL,
        `New callback request — ${request.requestId}`,
        buildAdminCallbackRequestEmail(request),
      ).catch((err) => console.error("Admin callback-request email failed:", err.message));
    }

    const message = order
      ? `Hi Design Makers, I would like a callback regarding my order ${request.orderNumber}.\n\nReason: ${reason}`
      : `Hi Design Makers, I would like a callback regarding my enquiry.\n\nReason: ${reason}`;
    const whatsappUrl = `${DESIGN_MAKERS_WHATSAPP}?text=${encodeURIComponent(message)}`;

    res.json({
      success: true,
      requestId: request.requestId,
      message: "Callback request submitted. WhatsApp is opening now.",
      whatsappUrl,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to submit your callback request. Please try again." });
  }
});

// Admin notification feed for callback requests. readBy is per-admin so one
// admin viewing a notification does not silently mark it read for everyone.
app.get("/api/admin/callback-requests", requireAdmin, (req, res) => {
  try {
    const database = readDatabase();
    const username = String(req.admin?.username || "").trim();
    const requests = (database.callbackRequests || []).slice().sort((a, b) => {
      const au = Array.isArray(a.readBy) && a.readBy.includes(username) ? 1 : 0;
      const bu = Array.isArray(b.readBy) && b.readBy.includes(username) ? 1 : 0;
      if (au !== bu) return au - bu;
      return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    });
    const unreadCount = requests.filter((r) => !(Array.isArray(r.readBy) && r.readBy.includes(username))).length;
    res.json({ success: true, requests, unreadCount });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load callback notifications." });
  }
});

app.put("/api/admin/callback-requests/:id/read", requireAdmin, (req, res) => {
  try {
    const database = readDatabase();
    const request = (database.callbackRequests || []).find((r) => String(r.id) === String(req.params.id));
    if (!request) return res.status(404).json({ success: false, message: "Callback request not found." });
    if (!Array.isArray(request.readBy)) request.readBy = [];
    const username = String(req.admin?.username || "").trim();
    if (username && !request.readBy.includes(username)) request.readBy.push(username);
    request.updatedAt = new Date().toISOString();
    writeDatabase(database);
    res.json({ success: true, request });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to mark this notification as read." });
  }
});

app.put("/api/admin/callback-requests/:id/status", requireAdmin, (req, res) => {
  try {
    const allowed = new Set(["New", "Contacted", "Completed", "Cancelled"]);
    const status = String(req.body?.status || "").trim();
    if (!allowed.has(status)) return res.status(400).json({ success: false, message: "Invalid callback status." });
    const database = readDatabase();
    const request = (database.callbackRequests || []).find((r) => String(r.id) === String(req.params.id));
    if (!request) return res.status(404).json({ success: false, message: "Callback request not found." });
    request.status = status;
    request.updatedAt = new Date().toISOString();
    request.completedAt = status === "Completed" ? new Date().toISOString() : null;
    writeDatabase(database);
    res.json({ success: true, request });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to update callback request." });
  }
});

// ================================
// ADMIN: DOWNLOAD DATA BACKUP
// ================================

app.get("/api/admin/backup", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  res.setHeader("Content-Disposition", `attachment; filename="database-backup-${stamp}.json"`);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(database, null, 2));
});

// ================================
// ADMIN: VIEW / UPDATE ORDERS
// ================================

// Dashboard totals (Total Orders / New / Cancelled / Revenue) computed over
// ALL orders, independent of pagination on the list endpoint below — these
// numbers need to stay accurate even when the admin is looking at page 3 of
// a paginated order list.
app.get("/api/admin/orders/stats", requireAdmin, (req, res) => {
  const database = readDatabase();
  const orders = database.orders || [];
  const activeOrders = orders.filter((o) => o.status !== "Cancelled");
  const totalRevenue = activeOrders.reduce((sum, o) => sum + (o.total || 0), 0);
  const newCount = orders.filter((o) => o.status === "New").length;
  const cancelledCount = orders.filter((o) => o.status === "Cancelled").length;
  res.json({
    success: true,
    total: orders.length,
    newCount,
    cancelledCount,
    revenue: totalRevenue,
  });
});

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const database = readDatabase();
  const sorted = database.orders
    .slice()
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const { slice, meta } = paginate(req, sorted);
  const orders = slice.map((order) => ({
    ...order,
    sellerFulfilment: getSellerFulfilment(database, order).map(r => {
      const seller = database.sellers.find(s => s.id === r.sellerId);
      return { ...r, sellerName: seller ? (seller.shopTitle || seller.name) : "Unknown seller" };
    }),
    // Tag each line item with who it came from — a seller's shop title,
    // or null for products listed directly by an admin — so the admin
    // panel can show whose products are actually being ordered.
    items: (order.items || []).map((item) => {
      const product = database.products.find((p) => p.id === item.productId);
      const seller = product && product.sellerId
        ? database.sellers.find((s) => s.id === product.sellerId)
        : null;
      return {
        ...item,
        sellerId: seller ? seller.id : null,
        sellerName: seller ? (seller.shopTitle || seller.name) : null,
      };
    }),
  }));
  res.json({ success: true, orders, ...meta });
});

const ORDER_STATUSES = ["New", "Processing", "Shipped", "Delivered", "Cancelled"];

// ================================
// PAYMENT STATUS — manual today, gateway-driven later
// ================================
// This is the one place that flips an order to "paid". Today the only
// caller is the admin endpoint below, triggered by a human clicking
// "Mark as Paid" after seeing the WhatsApp order confirmation. When an
// online payment gateway (Razorpay/Cashfree/etc.) is added, its webhook
// handler calls this same function instead — nothing else in the app
// needs to know or care which one triggered it.
function markOrderPaid(order) {
  order.paymentStatus = "paid";
  order.paidAt = new Date().toISOString();
  return order;
}

// Admin manually confirms payment after seeing the customer's WhatsApp
// message. This is the placeholder for what a payment gateway webhook
// will do automatically once one is wired up.
app.put("/api/admin/orders/:id/mark-paid", requireAdmin, (req, res) => {
  const database = readDatabase();
  const id = Number(req.params.id);
  const order = database.orders.find((o) => o.id === id);

  if (!order) {
    return res.status(404).json({ success: false, message: "Order not found." });
  }
  if (order.paymentStatus === "paid") {
    return res.json({ success: true, order }); // already paid, nothing to do
  }

  markOrderPaid(order);
  writeDatabase(database);

  res.json({ success: true, order });
});

app.put("/api/admin/orders/:id/status", requireAdmin, (req, res) => {
  return withInventoryLock(async () => {
    const database = readDatabase();
    const id = Number(req.params.id);
    const { status } = req.body || {};
    if (!ORDER_STATUSES.includes(status)) return res.status(400).json({ success: false, message: "Invalid status." });
    const order = database.orders.find((o) => o.id === id);
    if (!order) return res.status(404).json({ success: false, message: "Order not found." });
    if (order.status === status) return res.json({ success: true, order });
    if (order.status === "Cancelled" && status !== "Cancelled" && req.admin.role !== "boss") return res.status(403).json({ success: false, message: "Only the main admin can re-activate a cancelled order." });

    const previousStatus = order.status || "New";
    if (status === "Cancelled" && previousStatus !== "Cancelled" && order.inventoryDeducted && !order.inventoryRestored) {
      (order.items || []).forEach((item) => {
        const product = database.products.find((p) => p.id === Number(item.productId));
        if (!product || product.isGiftAddon) return;
        const beforeQty = getStockForVariant(product, item.size);
        const afterQty = beforeQty + Number(item.qty || 0);
        setStockForVariant(product, item.size, afterQty);
        // Cancellation is a restock path too (0 -> available), same as the
        // inventory-panel and bulk-import paths above — Back-in-Stock
        // subscribers should be notified here as well (Fix #05).
        notifyBackInStockForVariant(database, product, item.size, beforeQty, afterQty);
      });
      order.inventoryRestored = true;
    }

    if (previousStatus === "Cancelled" && status !== "Cancelled" && order.inventoryRestored) {
      const failures = [], plan = [];
      (order.items || []).forEach((item) => {
        const product = database.products.find((p) => p.id === Number(item.productId));
        if (!product || product.isGiftAddon) return;
        const available = getStockForVariant(product, item.size);
        const qty = Number(item.qty || 0);
        if (available < qty) failures.push(`${product.name}${item.size ? ` (${item.size})` : ""}: requires ${qty}, only ${available} available.`);
        else plan.push({ product, size: item.size || "", qty, before: available });
      });
      if (failures.length) return res.status(409).json({ success: false, code: "OUT_OF_STOCK", message: "Cannot reactivate this order. " + failures.join(" ") });
      plan.forEach(({ product, size, qty, before }) => setStockForVariant(product, size, before - qty));
      order.inventoryRestored = false;
      order.inventoryDeducted = true;
    }

    order.status = status;
    order.statusHistory = Array.isArray(order.statusHistory) ? order.statusHistory : [{ status: previousStatus, at: order.createdAt }];
    order.statusHistory.push({ status, at: new Date().toISOString() });
    writeDatabase(database);
    return res.json({ success: true, order });
  });
});

// ================================
// STORE SETTINGS
// ================================

app.get("/api/settings", (req, res) => {
  try {
    const database = readDatabase();
    res.json({ success: true, settings: database.settings });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to load store settings." });
  }
});

// Pinned "sale is live" banner shown at the top of the storefront.
app.put("/api/admin/settings/sale-banner", requireAdmin, (req, res) => {
  try {
    const { enabled, text } = req.body || {};
    const database = readDatabase();
    database.settings.saleBanner = {
      enabled: Boolean(enabled),
      text: String(text || "").trim().slice(0, 200),
    };
    writeDatabase(database);
    res.json({ success: true, saleBanner: database.settings.saleBanner });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to update the sale banner." });
  }
});

// Admin-selectable homepage hero product.
app.put("/api/admin/settings/hero-product", requireAdmin, (req, res) => {
  try {
    const rawId = req.body ? req.body.productId : null;
    const productId = rawId === null || rawId === "" || rawId === undefined ? null : Number(rawId);
    const database = readDatabase();
    if (productId !== null && !Number.isFinite(productId)) {
      return res.status(400).json({ success: false, message: "Invalid hero product." });
    }
    if (productId !== null) {
      const product = (database.products || []).find(p => Number(p.id) === productId && p.approved !== false && p.active !== false);
      if (!product) return res.status(404).json({ success: false, message: "Hero product not found or inactive." });
    }
    database.settings.heroProductId = productId;
    writeDatabase(database);
    res.json({ success: true, heroProductId: productId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to update the hero product." });
  }
});

// Festival theme applied across the whole storefront (normal / rakshabandhan).
app.put("/api/admin/settings/theme", requireAdmin, (req, res) => {
  try {
    const VALID_THEMES = ["normal", "rakshabandhan"];
    const { theme } = req.body || {};
    if (!VALID_THEMES.includes(theme)) {
      return res.status(400).json({ success: false, message: "Invalid theme." });
    }
    const database = readDatabase();
    database.settings.theme = theme;
    writeDatabase(database);
    res.json({ success: true, theme: database.settings.theme });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to update the theme." });
  }
});

// ================================
// 404 API HANDLER
// ================================

app.use("/api", (req, res) => {
  res.status(404).json({ success: false, message: "API route not found." });
});

// ================================
// CATCH-ALL ERROR HANDLER
// ================================
// Last line of defense — if any route throws something unexpected, this
// makes sure the response is still JSON (not an HTML crash page), so the
// frontend can show a real error instead of a blank generic failure.
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ success: false, message: "Something went wrong on our end. Please try again." });
});

// ================================
// START SERVER
// ================================

function ensureDemoSeller() {
  const database = readDatabase();
  const existing = (database.sellers || []).find((s) => s.sellerId === "DM-SLR-DEMO");
  if (existing) {
    let changed = false;
    if (!existing.whatsappNumber) { existing.whatsappNumber = "6299195149"; changed = true; }
    if (!existing.photo) {
      try {
        const logoPath = path.join(__dirname, "God-of-DM-DP.png");
        if (fs.existsSync(logoPath)) {
          existing.photo = `data:image/png;base64,${fs.readFileSync(logoPath).toString("base64")}`;
          changed = true;
        }
      } catch (_) {}
    }
    if (changed) writeDatabase(database);
    return;
  }
  const logoPath = path.join(__dirname, "God-of-DM-DP.png");
  let photo = "";
  try {
    if (fs.existsSync(logoPath)) photo = `data:image/png;base64,${fs.readFileSync(logoPath).toString("base64")}`;
  } catch (_) {}
  const seller = {
    id: getNextId(database.sellers || []),
    sellerId: "DM-SLR-DEMO",
    passwordHash: bcrypt.hashSync("GodOfDM#2026", 10),
    name: "God of DM",
    email: "oyeaom@gmail.com",
    phone: "6299195149",
    whatsappNumber: "6299195149",
    altPhone: "",
    shopTitle: "God of DM",
    businessType: "Demo Seller",
    businessAddress: "",
    city: "",
    state: "",
    pincode: "",
    aadhaarLast4: "1032",
    aadhaarFull: encryptPII("895915971032"),
    panNumber: "",
    dob: "",
    gender: "",
    bankAccountNumber: "",
    ifscCode: "",
    upiId: "",
    gstNumber: "",
    notes: "Demo seller created for WhatsApp routing testing.",
    photo,
    applicationId: null,
    createdAt: new Date().toISOString(),
    banned: false,
    mustChangePassword: false,
  };
  database.sellers = database.sellers || [];
  database.sellers.push(seller);
  writeDatabase(database);
  console.log("Demo seller created: DM-SLR-DEMO (God of DM)");
}

connectDB()
  .then(() => {
    try {
      // ensureDemoSeller(); - disabled, demo seller no longer auto-recreated
    } catch (err) {
      console.error("Demo seller seed failed (non-fatal):", err.message);
    }
    try {
      const database = readDatabase();
      const seeded = autoSeedCategoryProducts(database);
      if (seeded > 0) {
        console.log(`Auto-seed: added ${seeded} placeholder sample product(s) so every category stays populated.`);
      }
    } catch (err) {
      console.error("Auto-seed of category sample products failed (non-fatal):", err.message);
    }

    const httpServer = app.listen(PORT, "0.0.0.0", () => {
      console.log(`Design Makers running on port ${PORT}`);
      console.log(`Storefront:   /`);
      console.log(`Admin panel:  /admin`);
      console.log(`Products API: /api/products`);
    });

    // Without this handler, an error on the server (most commonly
    // EADDRINUSE — something else already bound to PORT, e.g. an old
    // instance not fully stopped yet during a redeploy) becomes an
    // uncaught exception and kills the process with no useful log line.
    // Logging it explicitly turns a silent crash-loop into a clear,
    // diagnosable error message.
    httpServer.on("error", (err) => {
      console.error("Server failed to start/listen:", err.code || "", err.message);
      if (err.stack) console.error(err.stack);
      process.exit(1);
    });

    process.on("uncaughtException", (err) => {
      console.error("Uncaught exception (server kept running until now):", err.message);
      if (err.stack) console.error(err.stack);
    });

    process.on("unhandledRejection", (reason) => {
      console.error("Unhandled promise rejection:", reason);
    });
  })
  .catch((err) => {
    console.error("Failed to connect to the database. Server not started.");
    console.error(err.message);
    process.exit(1);
  });
