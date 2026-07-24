const express = require("express");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { connectDB, readDatabase, writeDatabase, getNextId } = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
app.set("trust proxy", true);

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

if (!process.env.ADMIN1_PASSWORD) {
  console.warn(
    "⚠️  Using a default boss password. Set ADMIN1_USERNAME, ADMIN1_PASSWORD, " +
      "and JWT_SECRET in Replit Secrets before going live.",
  );
}

// Middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Serve website files
app.use(express.static(__dirname));

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
    req.admin = { username: payload.username, role: payload.role || "admin" };
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
    const token = jwt.sign({ username, role: "boss" }, JWT_SECRET, { expiresIn: "7d" });
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

  const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, token, username, role: "admin" });
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
  const newProduct = { id: getNextId(database.products), ...product };
  database.products.push(newProduct);
  writeDatabase(database);

  res.status(201).json({ success: true, product: newProduct });
});

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

    const products = database.products
      .filter((product) => product.active)
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
  const orders = database.orders.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
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

// ================================
// 404 API HANDLER
// ================================

app.use("/api", (req, res) => {
  res.status(404).json({ success: false, message: "API route not found." });
});

// ================================
// START SERVER
// ================================

connectDB()
  .then(() => {
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
