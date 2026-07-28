const express = require("express");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const { connectDB, readDatabase, writeDatabase, getNextId } = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
app.set("trust proxy", true);

// ================================
// EMAIL (seller applications + credentials)
// ================================
// Sends mail through Gmail using an App Password (not your normal Gmail
// password — generate one at myaccount.google.com > Security >
// 2-Step Verification > App passwords). Set GMAIL_USER and
// GMAIL_APP_PASSWORD in Render's Environment tab. ADMIN_NOTIFY_EMAIL is
// where new-application alerts go — defaults to GMAIL_USER if not set.
const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";
const ADMIN_NOTIFY_EMAIL = process.env.ADMIN_NOTIFY_EMAIL || GMAIL_USER;

let mailTransporter = null;
if (GMAIL_USER && GMAIL_APP_PASSWORD) {
  mailTransporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
} else {
  console.warn(
    "⚠️  GMAIL_USER / GMAIL_APP_PASSWORD not set — seller application emails " +
      "will be skipped (the site still works, applications still save to the database).",
  );
}

// Never throws — email is a nice-to-have, not something that should ever
// break an approval or an application just because a message failed to send.
async function sendMail(to, subject, html) {
  if (!mailTransporter || !to) {
    console.warn(`(email skipped — not configured) To: ${to} | Subject: ${subject}`);
    return { sent: false, reason: !mailTransporter ? "not-configured" : "no-recipient" };
  }
  try {
    await mailTransporter.sendMail({
      from: `"Design Makers" <${GMAIL_USER}>`,
      to,
      subject,
      html,
    });
    return { sent: true };
  } catch (error) {
    console.error("Failed to send email:", error.message);
    return { sent: false, reason: error.message };
  }
}

// Generates a seller ID like DM-SLR-001 and a random 10-character password.
// Existing sellers already have SLR-xxxx IDs saved — those are untouched;
// this only applies to newly approved sellers going forward.
function generateSellerId(nextNumericId) {
  return `DM-SLR-${String(nextNumericId).padStart(3, "0")}`;
}

function generateSellerPassword() {
  return crypto.randomBytes(6).toString("base64url"); // 8 chars, URL-safe
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
const JWT_SECRET =
  process.env.JWT_SECRET || "dev-only-secret-change-me-" + Date.now();

const BOSS_ACCOUNT = {
  username: process.env.ADMIN1_USERNAME || "admin1",
  passwordHash: bcrypt.hashSync(process.env.ADMIN1_PASSWORD || "ChangeMe123!", 10),
};

const MAX_LOGIN_ATTEMPTS = 3;

// ================================
// CONCURRENT SESSION LIMIT — max 2 active logins per username at once.
// Kept in memory (resets on server restart) since sessions are short-lived
// by nature; no need to persist this to MongoDB.
// ================================
const MAX_CONCURRENT_SESSIONS = 2;
const activeSessions = {}; // username -> array of sessionIds, oldest first

function registerSession(username, sessionId) {
  if (!activeSessions[username]) activeSessions[username] = [];
  activeSessions[username].push(sessionId);
  // If this login pushes the account over the limit, the oldest session(s)
  // are evicted — that device/tab will get "logged in elsewhere" on its
  // next request instead of continuing to work silently.
  if (activeSessions[username].length > MAX_CONCURRENT_SESSIONS) {
    activeSessions[username] = activeSessions[username].slice(-MAX_CONCURRENT_SESSIONS);
  }
}

function isSessionActive(username, sessionId) {
  return !!(activeSessions[username] && activeSessions[username].includes(sessionId));
}

function revokeSession(username, sessionId) {
  if (!activeSessions[username]) return;
  activeSessions[username] = activeSessions[username].filter((id) => id !== sessionId);
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

// Serve website files
app.use(
  express.static(__dirname, {
    etag: false,
    lastModified: false,
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".html")) {
        // HTML pages (index.html, admin.html) must always be revalidated —
        // this is what was causing "close and reopen still shows old data".
        res.set("Cache-Control", "no-cache");
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
    if (!isSessionActive(payload.username, payload.sessionId)) {
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
// ADMIN LOGIN
// ================================

app.post("/api/admin/login", (req, res) => {
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
    writeDatabase(database);
    const sessionId = crypto.randomUUID();
    registerSession(username, sessionId);
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
  writeDatabase(database);

  const sessionId = crypto.randomUUID();
  registerSession(username, sessionId);
  const token = jwt.sign({ username, role: "admin", sessionId }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, token, username, role: "admin" });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  revokeSession(req.admin.username, req.admin.sessionId);
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
  return /^[6-9]\d{9}$/.test(mobile); // 10-digit Indian mobile number
}

app.post("/api/customer/register", (req, res) => {
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

  const database = readDatabase();
  const exists = database.customers.find((c) => c.mobile === cleanMobile);
  if (exists) {
    return res.status(409).json({ success: false, message: "An account with this mobile number already exists. Please log in instead." });
  }

  const customer = {
    id: getNextId(database.customers),
    mobile: cleanMobile,
    name: cleanName,
    passwordHash: bcrypt.hashSync(String(password), 10),
    picture: "",
    cart: [],
    role: "customer",
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
    },
  });
});

app.post("/api/customer/login", (req, res) => {
  const { mobile, password } = req.body || {};
  const cleanMobile = normalizeMobile(mobile);
  if (!cleanMobile || !password) {
    return res.status(400).json({ success: false, message: "Mobile number and password are required." });
  }

  const database = readDatabase();
  const customer = database.customers.find((c) => c.mobile === cleanMobile);

  // No account for this number → tell the frontend so it can offer sign-up.
  if (!customer || !customer.passwordHash) {
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
      mobile: c.mobile,
      picture: c.picture || "",
      role: c.role,
      shopTitle: c.shopTitle,
      sellerStatus: c.sellerStatus,
    },
  });
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
// SELLER APPLICATIONS (public — no account needed)
// ================================
// Anyone can apply from the /sell page (or the "Become a Seller" link in a
// customer's account). No login required to submit. Only the LAST 4 DIGITS
// of the Aadhaar number are ever stored — never the full number — along
// with a photo of the card for the admin to manually verify.

app.post("/api/seller-applications", async (req, res) => {
  const body = req.body || {};
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim();
  const phone = String(body.phone || "").trim();
  const shopTitle = String(body.shopTitle || "").trim();
  const aadhaar = String(body.aadhaar || "").replace(/\D/g, "");
  const aadhaarPhoto = String(body.aadhaarPhoto || ""); // base64 data URL
  const personPhoto = String(body.personPhoto || ""); // base64 data URL — a photo of the applicant

  if (!name || !email || !phone || !shopTitle || aadhaar.length !== 12 || !personPhoto) {
    return res.status(400).json({
      success: false,
      message: "Name, email, phone, shop title, a photo of yourself, and a valid 12-digit Aadhaar number are required.",
    });
  }

  const database = readDatabase();

  // Block duplicate applications — same person applying twice (by email or
  // phone) while an earlier application is still pending or already
  // approved. A previously REJECTED application doesn't block a fresh one.
  const emailLower = email.toLowerCase();
  const duplicate = database.sellerApplications.find(
    (a) =>
      a.status !== "rejected" &&
      (String(a.email || "").toLowerCase() === emailLower || String(a.phone || "") === phone),
  );
  const alreadySeller = database.sellers.find(
    (s) => String(s.email || "").toLowerCase() === emailLower || String(s.phone || "") === phone,
  );
  if (duplicate || alreadySeller) {
    return res.status(409).json({
      success: false,
      message: alreadySeller
        ? "You're already registered as a seller with this email/phone."
        : "You've already submitted an application with this email/phone. Please wait for it to be reviewed.",
    });
  }

  const application = {
    id: getNextId(database.sellerApplications),
    name,
    email,
    phone,
    shopTitle,
    aadhaarLast4: aadhaar.slice(-4),
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

  res.json({ success: true, message: "Application submitted — we'll email you once it's reviewed." });
});

// ================================
// SELLER LOGIN (ID + password, issued on approval)
// ================================

app.post("/api/seller/login", (req, res) => {
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

  const token = jwt.sign({ type: "seller", sellerId: seller.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({
    success: true,
    token,
    seller: { id: seller.id, sellerId: seller.sellerId, name: seller.name, shopTitle: seller.shopTitle },
  });
});

// ================================
// SELLER: FORGOT PASSWORD
// ================================
// No self-service reset — sellers only have an ID + password, with no
// email/OTP flow behind it. Instead this raises a query that shows up in
// the admin panel; the boss reviews it and clicks a button to generate a
// fresh password and email it to the seller.

app.post("/api/seller/forgot-password", async (req, res) => {
  const sellerId = String((req.body || {}).sellerId || "").trim();
  if (!sellerId) {
    return res.status(400).json({ success: false, message: "Enter your Seller ID." });
  }

  const database = readDatabase();
  const seller = database.sellers.find((s) => s.sellerId === sellerId);
  if (!seller) {
    return res.status(404).json({ success: false, message: "We couldn't find that Seller ID." });
  }

  if (!Array.isArray(database.sellerPasswordResetRequests)) database.sellerPasswordResetRequests = [];

  const alreadyPending = database.sellerPasswordResetRequests.some(
    (r) => r.sellerRecordId === seller.id && r.status === "pending",
  );

  if (!alreadyPending) {
    database.sellerPasswordResetRequests.push({
      id: getNextId(database.sellerPasswordResetRequests),
      sellerRecordId: seller.id,
      sellerId: seller.sellerId,
      name: seller.name,
      shopTitle: seller.shopTitle,
      email: seller.email,
      status: "pending",
      createdAt: new Date().toISOString(),
    });
    writeDatabase(database);

    sendMail(
      ADMIN_NOTIFY_EMAIL,
      "Seller password reset request — Design Makers",
      `<p>${seller.name} (${seller.sellerId}, ${seller.shopTitle}) has requested a password reset.</p>
       <p>Resolve it from the admin panel's Sellers tab.</p>`,
    );
  }

  res.json({
    success: true,
    message: "Your request has been sent to the admin — you'll get a new password by email once it's resolved.",
  });
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
  request.status = "resolved";
  request.resolvedAt = new Date().toISOString();
  writeDatabase(database);

  const emailResult = await sendMail(
    seller.email,
    "Your Design Makers password has been reset",
    `<p>Hi ${seller.name},</p>
     <p>Your password has been reset. Here's your new login for <b>${seller.shopTitle}</b>:</p>
     <ul>
       <li><b>Seller ID:</b> ${seller.sellerId}</li>
       <li><b>New Password:</b> ${newPassword}</li>
     </ul>
     <p>Please keep this password safe — we recommend not sharing it with anyone.</p>`,
  );

  res.json({
    success: true,
    message: emailResult.sent
      ? `New password generated and emailed to ${seller.name}.`
      : `New password generated for ${seller.name}, but the EMAIL FAILED to send. Share these credentials with them yourself.`,
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
// ADMIN: CUSTOMERS (mobile + password accounts)
// ================================
// Read-only list for the admin panel, plus a "reset password" action.
// We never expose passwordHash — resetting generates a brand-new plaintext
// password, saves its hash, and returns the plaintext ONCE so the admin can
// pass it on to the customer.

app.get("/api/admin/customers", requireAdmin, (req, res) => {
  const database = readDatabase();
  const orders = database.orders || [];
  const customers = (database.customers || [])
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((c) => {
      const theirOrders = orders.filter(
        (o) => (c.mobile && o.customer && o.customer.phone === c.mobile) || o.customerId === c.id,
      );
      return {
        id: c.id,
        name: c.name,
        mobile: c.mobile || null,
        role: c.role,
        shopTitle: c.shopTitle,
        sellerStatus: c.sellerStatus,
        createdAt: c.createdAt,
        orderCount: theirOrders.length,
        // Older test/Google-era rows have no mobile — flag them so they can be cleaned up.
        legacy: !c.mobile,
      };
    });
  res.json({ success: true, customers });
});

// Full details for one customer, including their order history.
app.get("/api/admin/customers/:id", requireAdmin, (req, res) => {
  const database = readDatabase();
  const customer = (database.customers || []).find((c) => c.id === Number(req.params.id));
  if (!customer) {
    return res.status(404).json({ success: false, message: "Customer not found." });
  }
  const theirOrders = (database.orders || [])
    .filter((o) => (customer.mobile && o.customer && o.customer.phone === customer.mobile) || o.customerId === customer.id)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((o) => ({
      orderNumber: o.orderNumber,
      createdAt: o.createdAt,
      status: o.status,
      total: o.total,
      items: (o.items || []).map((it) => ({ name: it.name, size: it.size || "", qty: it.qty })),
    }));

  // Amount spent excludes cancelled orders.
  const totalSpent = theirOrders
    .filter((o) => o.status !== "Cancelled")
    .reduce((sum, o) => sum + (o.total || 0), 0);

  res.json({
    success: true,
    customer: {
      id: customer.id,
      name: customer.name,
      mobile: customer.mobile || null,
      role: customer.role,
      shopTitle: customer.shopTitle,
      sellerStatus: customer.sellerStatus,
      createdAt: customer.createdAt,
      legacy: !customer.mobile,
      orders: theirOrders,
      totalSpent,
    },
  });
});

// Permanently delete a customer account.
app.delete("/api/admin/customers/:id", requireAdmin, (req, res) => {
  const database = readDatabase();
  const idx = (database.customers || []).findIndex((c) => c.id === Number(req.params.id));
  if (idx === -1) {
    return res.status(404).json({ success: false, message: "Customer not found." });
  }
  const [removed] = database.customers.splice(idx, 1);
  writeDatabase(database);
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
// ADMIN: SELLER LIST (approved sellers + their products)
// ================================

app.get("/api/admin/sellers", requireAdmin, requireBoss, (req, res) => {
  const database = readDatabase();
  const allProducts = database.products || [];
  const sellers = (database.sellers || [])
    .slice()
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .map((s) => {
      const products = allProducts.filter((p) => p.sellerId === s.id);
      const approvedCount = products.filter((p) => p.approved !== false).length;
      const pendingCount = products.filter((p) => p.approved === false).length;
      return {
        id: s.id,
        sellerId: s.sellerId,
        name: s.name,
        email: s.email,
        phone: s.phone,
        shopTitle: s.shopTitle,
        createdAt: s.createdAt,
        banned: !!s.banned,
        productCount: products.length,
        approvedCount,
        pendingCount,
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
      shopTitle: a.shopTitle,
      aadhaarLast4: a.aadhaarLast4,
      aadhaarPhoto: a.aadhaarPhoto,
      personPhoto: a.personPhoto,
      createdAt: a.createdAt,
    }));
  res.json({ success: true, applications });
});

// Approving generates a Seller ID + random password, creates the seller
// account, and emails the credentials — nothing further needed from you.
app.put("/api/admin/seller-applications/:id/approve", requireAdmin, requireBoss, async (req, res) => {
  const database = readDatabase();
  const application = database.sellerApplications.find((a) => a.id === Number(req.params.id));
  if (!application) return res.status(404).json({ success: false, message: "Application not found." });
  if (application.status === "approved") {
    return res.status(400).json({ success: false, message: "Already approved." });
  }

  const nextNum = getNextId(database.sellers);
  const sellerId = generateSellerId(nextNum);
  const plainPassword = generateSellerPassword();

  const seller = {
    id: nextNum,
    sellerId,
    passwordHash: bcrypt.hashSync(plainPassword, 10),
    name: application.name,
    email: application.email,
    phone: application.phone,
    shopTitle: application.shopTitle,
    applicationId: application.id,
    createdAt: new Date().toISOString(),
    banned: false,
  };
  database.sellers.push(seller);
  application.status = "approved";
  writeDatabase(database);

  const emailResult = await sendMail(
    application.email,
    "You're approved as a seller on Design Makers!",
    `<p>Hi ${application.name},</p>
     <p>Your seller application for <b>${application.shopTitle}</b> has been approved.</p>
     <p>Log in to your seller dashboard with:</p>
     <ul>
       <li><b>Seller ID:</b> ${sellerId}</li>
       <li><b>Password:</b> ${plainPassword}</li>
     </ul>
     <p>Please keep this password safe — we recommend not sharing it with anyone.</p>`,
  );

  res.json({
    success: true,
    message: emailResult.sent
      ? `${application.name} is now an approved seller (${sellerId}). Login email sent.`
      : `${application.name} is now an approved seller (${sellerId}), but the login EMAIL FAILED to send. Share these credentials with them yourself.`,
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
  const designation = String((req.body || {}).designation || "").trim();
  const canDeleteFlag = !!(req.body || {}).canDeleteProducts;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required." });
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

  database.admins.push({
    username,
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
  let images = Array.isArray(body.images) ? body.images : [];
  images = images.map((s) => String(s || "").trim()).filter(Boolean).slice(0, 6);
  if (!images.length && body.image) images = [String(body.image).trim()];

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
// SECURE SERVER-SIDE ORDER PRICING
// ================================
// Never trust a total sent from the browser — recompute every line from the
// real product data on disk so a tampered request can't change what's charged.

function calculateSecurePricing(items, products) {
  const errors = [];
  const pricedItems = [];
  let subtotal = 0;
  let discountTotal = 0;

  if (!Array.isArray(items) || items.length === 0) {
    return { errors: ["Your cart is empty."], pricedItems, subtotal: 0, discountTotal: 0, total: 0 };
  }

  items.forEach((item, idx) => {
    const product = products.find((p) => p.id === Number(item.productId));

    if (!product || !product.active) {
      errors.push(`Item ${idx + 1}: product not found or no longer available.`);
      return;
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

    const lineSubtotal = effectivePrice * qty;
    const lineDiscount = lineSubtotal * (discountPct / 100);
    const lineTotal = Math.round((lineSubtotal - lineDiscount) * 100) / 100;

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

  const total = Math.round((subtotal - discountTotal) * 100) / 100;

  return { errors, pricedItems, subtotal, discountTotal, total };
}

// ================================
// PHONE HELPER
// ================================
// No login system — a customer's WhatsApp phone number is their identity
// on an order, even though we no longer keep a customer record for it.

function normalizePhone(phone) {
  return String(phone || "").replace(/\D/g, "").slice(-10);
}

// ================================
// ADMIN PRODUCT MANAGEMENT
// ================================

// List ALL products (including inactive) for the dashboard
app.get("/api/admin/products", requireAdmin, (req, res) => {
  const database = readDatabase();
  res.json({ success: true, products: database.products });
});

// Create a product
app.post("/api/admin/products", requireAdmin, (req, res) => {
  const { errors, product } = validateProductInput(req.body || {});

  if (errors.length) {
    return res.status(400).json({ success: false, message: errors.join(" ") });
  }

  const database = readDatabase();
  const newProduct = { id: getNextId(database.products), sellerId: null, approved: true, ...product };
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
  const newProduct = {
    id: getNextId(database.products),
    sellerId: req.seller.id,
    approved: false, // waits for admin approval before showing on the storefront
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

// Orders that include at least one of this seller's products. Each order
// keeps its normal shape, but `items` is filtered down to just this
// seller's lines so a seller never sees another seller's line items.
app.get("/api/seller/orders", requireSeller, (req, res) => {
  const database = readDatabase();
  const myProductIds = new Set(
    database.products.filter((p) => p.sellerId === req.seller.id).map((p) => p.id),
  );

  const orders = database.orders
    .map((order) => {
      const myItems = (order.items || []).filter((item) => myProductIds.has(item.productId));
      if (!myItems.length) return null;
      // A single order can contain products from more than one seller, so
      // order.total (the whole order) is NOT this seller's revenue — only
      // the lines that are actually theirs count.
      const sellerTotal = Math.round(myItems.reduce((sum, item) => sum + (item.lineTotal || 0), 0) * 100) / 100;
      return { ...order, items: myItems, sellerTotal };
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

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
      };
    });
  res.json({ success: true, products: pending });
});

app.put("/api/admin/products/:id/approve", requireAdmin, (req, res) => {
  const database = readDatabase();
  const product = database.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ success: false, message: "Product not found." });
  product.approved = true;
  writeDatabase(database);
  res.json({ success: true, message: "Product approved and now live.", product });
});

app.put("/api/admin/products/:id/reject", requireAdmin, (req, res) => {
  const database = readDatabase();
  const product = database.products.find((p) => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ success: false, message: "Product not found." });
  const index = database.products.indexOf(product);
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

  database.products[index] = { ...database.products[index], ...product, id };
  writeDatabase(database);

  res.json({ success: true, product: database.products[index] });
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
// SELLER APPLICATION PAGE (invitation link — fill the form)
// ================================

app.get("/seller", (req, res) => {
  res.sendFile(path.join(__dirname, "sell.html"));
});

// ================================
// SELLER LOGIN / DASHBOARD PAGE
// ================================

app.get("/sell", (req, res) => {
  res.sendFile(path.join(__dirname, "seller.html"));
});


// ================================
// HOME PAGE
// ================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
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

app.get("/api/products", (req, res) => {
  try {
    const database = readDatabase();
    const { popular, trending } = computeHomepageRankings(database);
    const popularIds = new Set(popular.map((p) => p.id));
    const trendingIds = new Set(trending.map((p) => p.id));
    const bannedSellerIds = new Set(
      (database.sellers || []).filter((s) => s.banned).map((s) => s.id),
    );

    const products = database.products
      .filter(
        (product) =>
          product.active &&
          product.approved !== false &&
          !(product.sellerId && bannedSellerIds.has(product.sellerId)),
      )
      .map((product) => ({
        ...product,
        saleActive: isSaleActive(product),
        popular: popularIds.has(product.id),
        trending: trendingIds.has(product.id),
      }));
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

    res.json({ success: true, product: { ...product, saleActive: isSaleActive(product) } });
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
app.get("/product-image/:id", (req, res) => {
  try {
    const database = readDatabase();
    const productId = Number(req.params.id);
    const product = database.products.find((product) => product.id === productId);
    const imgSrc = product && ((Array.isArray(product.images) && product.images[0]) || product.image);

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
    res.set("Cache-Control", "public, max-age=86400");
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

app.post("/api/orders", (req, res) => {
  try {
    const database = readDatabase();
    const { customer, items } = req.body || {};

    const phone = normalizePhone(customer && customer.phone);
    const name = customer && String(customer.name || "").trim();

    if (!phone || phone.length < 10) {
      return res.status(400).json({ success: false, message: "A valid 10-digit phone number is required." });
    }
    if (!name) {
      return res.status(400).json({ success: false, message: "Name is required." });
    }

    // Price the order from the real product data — the client's numbers are never trusted.
    const pricing = calculateSecurePricing(items, database.products);
    if (pricing.errors.length) {
      return res.status(400).json({ success: false, message: pricing.errors.join(" ") });
    }

    const newOrder = {
      id: getNextId(database.orders),
      orderNumber: "DM-" + Date.now().toString().slice(-8),
      customer: { name, phone },
      customerId: getOptionalCustomerId(req),
      items: pricing.pricedItems,
      subtotal: Math.round(pricing.subtotal * 100) / 100,
      discount: Math.round(pricing.discountTotal * 100) / 100,
      total: pricing.total,
      paymentMethod: "COD",
      status: "New",
      createdAt: new Date().toISOString(),
    };

    database.orders.push(newOrder);
    writeDatabase(database);

    res.status(201).json({
      success: true,
      message: "Order created successfully.",
      order: newOrder,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Unable to create order." });
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

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const database = readDatabase();
  const orders = database.orders
    .slice()
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map((order) => ({
      ...order,
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
  res.json({ success: true, orders });
});

const ORDER_STATUSES = ["New", "Processing", "Shipped", "Delivered", "Cancelled"];

app.put("/api/admin/orders/:id/status", requireAdmin, (req, res) => {
  const database = readDatabase();
  const id = Number(req.params.id);
  const { status } = req.body || {};

  if (!ORDER_STATUSES.includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid status." });
  }

  const order = database.orders.find((o) => o.id === id);
  if (!order) {
    return res.status(404).json({ success: false, message: "Order not found." });
  }

  // Re-activating a cancelled order (moving it out of "Cancelled") is
  // restricted to the main admin (boss) account.
  if (order.status === "Cancelled" && status !== "Cancelled" && req.admin.role !== "boss") {
    return res.status(403).json({ success: false, message: "Only the main admin can re-activate a cancelled order." });
  }

  order.status = status;
  writeDatabase(database);

  res.json({ success: true, order });
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

// Festival theme applied across the whole storefront (normal / rakshabandhan / aug15).
app.put("/api/admin/settings/theme", requireAdmin, (req, res) => {
  try {
    const VALID_THEMES = ["normal", "rakshabandhan", "aug15"];
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

connectDB()
  .then(() => {
    try {
      const database = readDatabase();
      const seeded = autoSeedCategoryProducts(database);
      if (seeded > 0) {
        console.log(`Auto-seed: added ${seeded} placeholder sample product(s) so every category stays populated.`);
      }
    } catch (err) {
      console.error("Auto-seed of category sample products failed (non-fatal):", err.message);
    }

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Design Makers running on port ${PORT}`);
      console.log(`Storefront:   /`);
      console.log(`Admin panel:  /admin`);
      console.log(`Products API: /api/products`);
    });
  })
  .catch((err) => {
    console.error("Failed to connect to the database. Server not started.");
    console.error(err.message);
    process.exit(1);
  });
