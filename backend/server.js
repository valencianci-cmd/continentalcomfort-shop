"use strict";
/*
 * ContinentalComfort.Shop — custom store API (Phase 1 foundation)
 * Enforces the core rules the business asked for:
 *   - admin login requires 2FA (TOTP)
 *   - new customer accounts are 'pending'; trade pricing is gated to approved accounts
 *   - all pricing is computed server-side from the account's granted tier,
 *     so contractor/distributor prices never reach an unapproved account
 */
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const braintree = require("braintree");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error("JWT_SECRET is required"); process.exit(1); }
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "disable" ? false : { rejectUnauthorized: false },
});

// Braintree gateway. Only initialised when all keys are present, so the
// service stays healthy before the sandbox/live keys are added.
let gateway = null;
if (process.env.BRAINTREE_MERCHANT_ID && process.env.BRAINTREE_PUBLIC_KEY && process.env.BRAINTREE_PRIVATE_KEY) {
  gateway = new braintree.BraintreeGateway({
    environment: process.env.BRAINTREE_ENV === "production" ? braintree.Environment.Production : braintree.Environment.Sandbox,
    merchantId: process.env.BRAINTREE_MERCHANT_ID,
    publicKey: process.env.BRAINTREE_PUBLIC_KEY,
    privateKey: process.env.BRAINTREE_PRIVATE_KEY,
  });
  console.log("Braintree gateway ready (" + (process.env.BRAINTREE_ENV === "production" ? "production" : "sandbox") + ")");
} else {
  console.log("Braintree not configured yet - orders record without charging");
}

const app = express();
app.set("trust proxy", 1); // behind Render's proxy, so rate limits key off the real client IP
app.use(helmet());
app.use(express.json({ limit: "64kb" }));
app.use(cors({ origin: (process.env.CORS_ORIGINS || "*").split(","), credentials: false }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }); // blunt brute force
const checkoutLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 40 }); // Drop-in token fetches
// Card-testing defense: cap order attempts per IP.
const orderLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 12, message: { error: "too many checkout attempts, please wait a few minutes and try again" } });

// ---------- helpers ----------
const sign = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
function auth(required = true) {
  return (req, res, next) => {
    const h = req.headers.authorization || "";
    const tok = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!tok) { if (required) return res.status(401).json({ error: "sign in required" }); req.user = null; return next(); }
    try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
    catch { return res.status(401).json({ error: "session expired" }); }
  };
}
const requireAdmin = (req, res, next) =>
  req.user && req.user.kind === "admin" ? next() : res.status(403).json({ error: "admin only" });

// The granted tier for the requesting account. Unauthenticated or unapproved => homeowner.
async function tierFor(user) {
  if (!user || user.kind !== "customer") return "homeowner";
  const { rows } = await pool.query("SELECT tier, status FROM customers WHERE id=$1", [user.id]);
  const c = rows[0];
  return c && c.status === "approved" ? c.tier : "homeowner";
}
async function multiplier(tier) {
  const { rows } = await pool.query("SELECT multiplier FROM pricing_tiers WHERE tier=$1", [tier]);
  return rows[0] ? Number(rows[0].multiplier) : 1;
}
const priced = (listPrice, m) => Math.round(Number(listPrice) * m * 100) / 100;

// Matched systems, heat-pump systems, ductless systems and accessories are not
// individual catalog rows, so their prices live here, generated from the same
// numbers the storefront displays (backend/bundles.json). Keyed by the cart key
// (sys-/hp-/ds-/acc-). base is the Guest/home price; trade tiers apply the same
// multiplier as catalog products.
let BUNDLES = {};
try {
  BUNDLES = JSON.parse(require("fs").readFileSync(require("path").join(__dirname, "bundles.json"), "utf8"));
  console.log("bundle prices loaded:", Object.keys(BUNDLES).length);
} catch (e) { console.error("could not load bundles.json:", String(e.message || e)); }

// ---------- health ----------
app.get("/api/health", async (_req, res) => {
  try { await pool.query("SELECT 1"); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ ok: false, error: String(e) }); }
});

// ---------- catalog (tier-aware; trade prices only for approved accounts) ----------
app.get("/api/products", auth(false), async (req, res) => {
  const tier = await tierFor(req.user);
  const m = await multiplier(tier);
  const q = req.query.category ? "AND category=$1" : "";
  const params = req.query.category ? [req.query.category] : [];
  const { rows } = await pool.query(
    `SELECT sku, napoleon_sku, name, category, list_price, image_url, specs, ahri, stock_qty
       FROM products WHERE active=TRUE ${q} ORDER BY category, name`, params);
  res.json({
    tier,
    products: rows.map(p => ({
      sku: p.sku, napoleon_sku: p.napoleon_sku, name: p.name, category: p.category,
      price: priced(p.list_price, m), image_url: p.image_url, specs: p.specs,
      ahri: p.ahri, stock_qty: p.stock_qty,
    })),
  });
});

// ---------- customer accounts ----------
app.post("/api/auth/register", authLimiter, async (req, res) => {
  const { email, password, company_name, contact_name, phone, requested_tier } = req.body || {};
  if (!email || !password || password.length < 8) return res.status(400).json({ error: "email and an 8+ char password are required" });
  const rt = ["homeowner", "contractor", "distributor"].includes(requested_tier) ? requested_tier : "homeowner";
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO customers (email,password_hash,company_name,contact_name,phone,requested_tier)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,email,requested_tier,status`,
      [email.toLowerCase(), hash, company_name, contact_name, phone, rt]);
    // Homeowner accounts are usable immediately; trade requests wait for admin approval.
    res.status(201).json({ account: rows[0], note: rt === "homeowner" ? "account active" : "trade account submitted for approval" });
  } catch (e) {
    if (String(e).includes("duplicate")) return res.status(409).json({ error: "an account with that email already exists" });
    res.status(500).json({ error: "could not create account" });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query("SELECT * FROM customers WHERE email=$1", [(email || "").toLowerCase()]);
  const c = rows[0];
  if (!c || !(await bcrypt.compare(password || "", c.password_hash))) return res.status(401).json({ error: "wrong email or password" });
  res.json({ token: sign({ kind: "customer", id: c.id, email: c.email }), tier: c.status === "approved" ? c.tier : "homeowner", status: c.status });
});

// ---------- admin auth with mandatory 2FA ----------
// Step 1: email + password -> short-lived challenge token (must then pass 2FA)
app.post("/api/admin/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query("SELECT * FROM admin_users WHERE email=$1", [(email || "").toLowerCase()]);
  const a = rows[0];
  if (!a || !(await bcrypt.compare(password || "", a.password_hash))) return res.status(401).json({ error: "wrong email or password" });
  if (!a.totp_enabled) {
    // first login: enroll 2FA before granting access
    const secret = speakeasy.generateSecret({ name: `ContinentalComfort.Shop (${a.email})` });
    await pool.query("UPDATE admin_users SET totp_secret=$1 WHERE id=$2", [secret.base32, a.id]);
    return res.json({ enroll_2fa: true, otpauth_url: secret.otpauth_url, challenge: jwt.sign({ kind: "admin_challenge", id: a.id }, JWT_SECRET, { expiresIn: "10m" }) });
  }
  res.json({ require_2fa: true, challenge: jwt.sign({ kind: "admin_challenge", id: a.id }, JWT_SECRET, { expiresIn: "10m" }) });
});

// Step 2: challenge token + 6-digit code -> full admin session
app.post("/api/admin/2fa", authLimiter, async (req, res) => {
  const { challenge, code } = req.body || {};
  let payload;
  try { payload = jwt.verify(challenge, JWT_SECRET); } catch { return res.status(401).json({ error: "challenge expired, start over" }); }
  if (payload.kind !== "admin_challenge") return res.status(400).json({ error: "bad challenge" });
  const { rows } = await pool.query("SELECT * FROM admin_users WHERE id=$1", [payload.id]);
  const a = rows[0];
  if (!a || !a.totp_secret) return res.status(400).json({ error: "2FA not set up" });
  const ok = speakeasy.totp.verify({ secret: a.totp_secret, encoding: "base32", token: String(code || ""), window: 1 });
  if (!ok) return res.status(401).json({ error: "invalid 2FA code" });
  if (!a.totp_enabled) await pool.query("UPDATE admin_users SET totp_enabled=TRUE WHERE id=$1", [a.id]);
  res.json({ token: sign({ kind: "admin", id: a.id, role: a.role, email: a.email }) });
});

// ---------- admin: approvals and tier/discount pricing ----------
app.get("/api/admin/customers", auth(), requireAdmin, async (req, res) => {
  const status = req.query.status;
  const q = status ? "WHERE status=$1" : "";
  const { rows } = await pool.query(
    `SELECT id,email,company_name,contact_name,phone,requested_tier,tier,status,approved_at,created_at
       FROM customers ${q} ORDER BY created_at DESC`, status ? [status] : []);
  res.json({ customers: rows });
});

// Approve (or reject) a trade account and set the tier they are granted.
app.post("/api/admin/customers/:id/approve", auth(), requireAdmin, async (req, res) => {
  const { tier, reject } = req.body || {};
  if (reject) {
    await pool.query("UPDATE customers SET status='rejected' WHERE id=$1", [req.params.id]);
    return res.json({ ok: true, status: "rejected" });
  }
  if (!["homeowner", "contractor", "distributor"].includes(tier)) return res.status(400).json({ error: "tier must be homeowner, contractor, or distributor" });
  const { rows } = await pool.query(
    `UPDATE customers SET status='approved', tier=$1, approved_by=$2, approved_at=now()
       WHERE id=$3 RETURNING id,email,tier,status`, [tier, req.user.id, req.params.id]);
  res.json({ ok: true, customer: rows[0] });
});

// Current tier pricing (for the admin dashboard to display).
app.get("/api/admin/pricing", auth(), requireAdmin, async (_req, res) => {
  const { rows } = await pool.query("SELECT tier, multiplier, label FROM pricing_tiers ORDER BY multiplier DESC");
  res.json({ tiers: rows });
});

// Set the discount multiplier for a tier (this is where discount-off pricing is controlled).
app.put("/api/admin/pricing/:tier", auth(), requireAdmin, async (req, res) => {
  const { multiplier: mult } = req.body || {};
  if (!(mult > 0 && mult <= 1)) return res.status(400).json({ error: "multiplier must be between 0 and 1 (e.g. 0.80 = 20% off list)" });
  const { rows } = await pool.query("UPDATE pricing_tiers SET multiplier=$1 WHERE tier=$2 RETURNING *", [mult, req.params.tier]);
  if (!rows[0]) return res.status(404).json({ error: "unknown tier" });
  res.json({ ok: true, tier: rows[0] });
});

// ---------- checkout ----------
// Client token for the Braintree Drop-in UI on the storefront.
app.get("/api/checkout/token", checkoutLimiter, async (_req, res) => {
  if (!gateway) return res.status(503).json({ error: "payments are not configured yet" });
  try {
    const r = await gateway.clientToken.generate({});
    res.json({ clientToken: r.clientToken });
  } catch (e) {
    console.error("clientToken error:", (e && (e.type || e.name)) || "?", "|", (e && e.message) || String(e));
    res.status(500).json({ error: "could not start checkout" });
  }
});

// ---------- orders ----------
app.get("/api/admin/orders", auth(), requireAdmin, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM orders ORDER BY created_at DESC LIMIT 200");
  res.json({ orders: rows });
});

// Create an order. Prices are recomputed server-side from the account's tier —
// the client cannot send its own prices.
app.post("/api/orders", orderLimiter, auth(false), async (req, res) => {
  const { items, ship, nonce, deviceData, payment, poNumber } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: "no items" });
  const tier = await tierFor(req.user);
  const m = await multiplier(tier);
  const client = await pool.connect();
  let txnId = null;
  try {
    await client.query("BEGIN");
    let subtotal = 0; const lines = [];
    for (const it of items) {
      const qty = Math.max(1, parseInt(it.qty, 10) || 1);
      const b = BUNDLES[it.sku];
      if (b) {
        // Matched system / ductless / accessory: price from the server bundle file.
        const unit = priced(b.base, m);
        subtotal += unit * qty; lines.push({ sku: it.sku, name: b.name, qty, unit });
        continue;
      }
      const { rows } = await client.query("SELECT sku,name,list_price,active FROM products WHERE sku=$1", [it.sku]);
      const p = rows[0];
      if (!p || !p.active) throw new Error("unknown product " + it.sku);
      const unit = priced(p.list_price, m);
      subtotal += unit * qty; lines.push({ sku: p.sku, name: p.name, qty, unit });
    }
    subtotal = Math.round(subtotal * 100) / 100;
    if (!(subtotal > 0)) throw new Error("order total must be greater than zero");
    const email = (req.user && req.user.email) || (ship && ship.email);
    if (!email) throw new Error("email required");

    // Purchase order, or card charge. Prices are computed above from the
    // catalog, never taken from the client.
    let status = "pending";
    let poNum = null;
    const method = (payment === "po") ? "po" : "card";
    if (method === "po") {
      poNum = (poNumber || "").toString().trim().slice(0, 60);
      if (!poNum) throw new Error("a purchase order number is required");
      status = "po";
    } else if (gateway) {
      if (!nonce) throw new Error("payment required");
      const sale = await gateway.transaction.sale({
        amount: subtotal.toFixed(2),
        paymentMethodNonce: nonce,
        deviceData: deviceData || undefined,
        options: { submitForSettlement: true },
      });
      if (!sale.success) throw new Error(sale.message || "payment was declined");
      txnId = sale.transaction && sale.transaction.id;
      status = "paid";
    }

    const o = await client.query(
      `INSERT INTO orders (customer_id,email,tier,subtotal,status,braintree_txn,po_number,ship_name,ship_addr,ship_city,ship_state,ship_zip)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
      [req.user && req.user.kind === "customer" ? req.user.id : null, email, tier, subtotal, status, txnId, poNum,
       ship && ship.name, ship && ship.addr, ship && ship.city, ship && ship.state, ship && ship.zip]);
    const orderId = o.rows[0].id;
    for (const l of lines)
      await client.query("INSERT INTO order_items (order_id,sku,name,qty,unit_price) VALUES ($1,$2,$3,$4,$5)",
        [orderId, l.sku, l.name, l.qty, l.unit]);
    await client.query("COMMIT");
    res.status(201).json({ order_id: orderId, tier, subtotal, status, paid: status === "paid", po: status === "po" });
  } catch (e) {
    await client.query("ROLLBACK");
    // If the card was charged but the order failed to save, void so nobody is billed for nothing.
    if (txnId && gateway) { try { await gateway.transaction.void(txnId); } catch (_) {} }
    res.status(400).json({ error: String(e.message || e) });
  } finally { client.release(); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("ContinentalComfort.Shop API on :" + PORT));
