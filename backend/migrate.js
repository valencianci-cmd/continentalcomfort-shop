"use strict";
/* Applies schema.sql, seeds the catalog, and creates the first admin user.
 * Run once after the database is provisioned:  node migrate.js
 * Admin is created from ADMIN_EMAIL / ADMIN_PASSWORD env vars (2FA is enrolled
 * on that admin's first login). */
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "disable" ? false : { rejectUnauthorized: false },
});

// A starter catalog seed; full catalog import comes from the storefront data + Eclipse.
const PRODUCTS = [
  ["WC-C97-C", "WC-C97-N", "C97 Gas Furnace", "furnaces", 2450, "https://images.salsify.com/image/upload/s--KUSJRA5p--/ic1hrkor1ax3hszhnhk6.png", { AFUE: "Up to 97%", Stage: "Two-stage" }, null],
  ["WC-CT-14-C", "WC-CT-14-N", "CT 14.3 SEER2 Air Conditioner", "air-conditioners", 1890, "https://images.salsify.com/image/upload/s--zqXp4TM9--/skhjjplacp2xir1kv4j1.png", { Efficiency: "Up to 14.3 SEER2", Capacity: "1.5-5 ton" }, null],
  ["CDHAS26-24", "NDHAS26-24", "CDHAS26 Ductless Single-Zone 2 Ton", "ductless", 2090, "https://images.salsify.com/image/upload/s--YCveO2cY--/am5oyqtkbut7zdaiw48p.png", { Efficiency: "21.5 SEER2", BTU: "24,000" }, null],
];

(async () => {
  try {
    const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
    await pool.query(sql);
    console.log("schema applied");

    for (const p of PRODUCTS) {
      await pool.query(
        `INSERT INTO products (sku,napoleon_sku,name,category,list_price,image_url,specs,ahri)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (sku) DO NOTHING`,
        [p[0], p[1], p[2], p[3], p[4], p[5], JSON.stringify(p[6]), p[7]]);
    }
    console.log("catalog seeded");

    const email = (process.env.ADMIN_EMAIL || "").toLowerCase();
    const pw = process.env.ADMIN_PASSWORD;
    if (email && pw) {
      const hash = await bcrypt.hash(pw, 12);
      await pool.query(
        `INSERT INTO admin_users (email,password_hash,role) VALUES ($1,$2,'admin')
         ON CONFLICT (email) DO NOTHING`, [email, hash]);
      console.log("admin user ready:", email, "(2FA enrolls on first login)");
    } else {
      console.log("no ADMIN_EMAIL/ADMIN_PASSWORD set — skipping admin creation");
    }
    console.log("migration complete");
    process.exit(0);
  } catch (e) { console.error(e); process.exit(1); }
})();
