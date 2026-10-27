"use strict";
/* Applies schema.sql, seeds/updates the catalog from catalog.json, aligns the
 * Guest tier to current storefront pricing, and creates the first admin user.
 * Runs on every deploy (idempotent). Admin comes from ADMIN_EMAIL / ADMIN_PASSWORD. */
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "disable" ? false : { rejectUnauthorized: false },
});

(async () => {
  try {
    const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
    await pool.query(sql);
    await pool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS po_number TEXT");
    console.log("schema applied");

    // Catalog: upsert every product so prices/fields stay in sync with the file.
    const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, "catalog.json"), "utf8"));
    for (const p of catalog) {
      await pool.query(
        `INSERT INTO products (sku,napoleon_sku,name,category,list_price,image_url,specs,ahri)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (sku) DO UPDATE SET
           napoleon_sku=EXCLUDED.napoleon_sku, name=EXCLUDED.name, category=EXCLUDED.category,
           list_price=EXCLUDED.list_price, image_url=EXCLUDED.image_url, specs=EXCLUDED.specs`,
        [p.sku, p.napoleon_sku || null, p.name, p.category, p.list_price,
         p.image_url || null, JSON.stringify(p.specs || {}), p.ahri || null]);
    }
    console.log("catalog synced:", catalog.length, "products");

    // Keep only current catalog SKUs active; deactivate anything no longer in the file.
    const skus = catalog.map(p => p.sku);
    await pool.query("UPDATE products SET active = (sku = ANY($1::text[]))", [skus]);

    // Guest pays full MSRP (no discount). Correct the earlier 0.80 default to 1.0.
    // Only touches the 0.80 value; other admin-set values are preserved.
    await pool.query("UPDATE pricing_tiers SET multiplier=1.0000, label='Guest' WHERE tier='homeowner' AND multiplier=0.8000");

    const email = (process.env.ADMIN_EMAIL || "").toLowerCase();
    const pw = process.env.ADMIN_PASSWORD;
    if (email && pw) {
      const hash = await bcrypt.hash(pw, 12);
      await pool.query(
        `INSERT INTO admin_users (email,password_hash,role) VALUES ($1,$2,'admin')
         ON CONFLICT (email) DO NOTHING`, [email, hash]);
      console.log("admin user ready:", email, "(2FA enrolls on first login)");
    } else {
      console.log("no ADMIN_EMAIL/ADMIN_PASSWORD set - skipping admin creation");
    }
    console.log("migration complete");
    process.exit(0);
  } catch (e) { console.error(e); process.exit(1); }
})();
