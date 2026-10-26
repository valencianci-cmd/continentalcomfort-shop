-- ContinentalComfort.Shop — custom store schema
-- Pricing tiers are enforced server-side. Trade pricing is only ever computed
-- for customers whose account is approved AND assigned to that tier.

CREATE TABLE IF NOT EXISTS admin_users (
  id            SERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret   TEXT,                       -- base32; set when 2FA is enrolled
  totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
  role          TEXT NOT NULL DEFAULT 'staff',  -- 'admin' | 'staff' (least privilege)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Customers. New accounts default to the 'homeowner' tier and 'pending' status.
-- A contractor/distributor only sees trade pricing after status='approved' and
-- tier is set to 'contractor' or 'distributor' by an admin.
CREATE TABLE IF NOT EXISTS customers (
  id             SERIAL PRIMARY KEY,
  email          TEXT UNIQUE NOT NULL,
  password_hash  TEXT NOT NULL,
  company_name   TEXT,
  contact_name   TEXT,
  phone          TEXT,
  requested_tier TEXT NOT NULL DEFAULT 'homeowner', -- what they applied for
  tier           TEXT NOT NULL DEFAULT 'homeowner', -- what they are granted
  status         TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'approved' | 'rejected'
  approved_by    INTEGER REFERENCES admin_users(id),
  approved_at    TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT tier_values CHECK (tier IN ('homeowner','contractor','distributor')),
  CONSTRAINT status_values CHECK (status IN ('pending','approved','rejected'))
);

-- Tier pricing multipliers, editable in admin (this is where you set discount off pricing)
CREATE TABLE IF NOT EXISTS pricing_tiers (
  tier       TEXT PRIMARY KEY,
  multiplier NUMERIC(6,4) NOT NULL,         -- applied to base/list price
  label      TEXT NOT NULL
);
INSERT INTO pricing_tiers (tier, multiplier, label) VALUES
  ('homeowner',   1.0000, 'Homeowner'),
  ('contractor',  0.8000, 'Contractor'),
  ('distributor', 0.7000, 'Distributor')
ON CONFLICT (tier) DO NOTHING;

CREATE TABLE IF NOT EXISTS products (
  id          SERIAL PRIMARY KEY,
  sku         TEXT UNIQUE NOT NULL,         -- Continental -C model
  napoleon_sku TEXT,                        -- Napoleon -N equivalent
  name        TEXT NOT NULL,
  category    TEXT NOT NULL,
  list_price  NUMERIC(12,2) NOT NULL,       -- base price; tier multiplier applied
  image_url   TEXT,
  specs       JSONB NOT NULL DEFAULT '{}',
  ahri        TEXT,
  stock_qty   INTEGER,                      -- null until Eclipse sync populates it
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Matched AHRI systems (a bundle of products with one certificate number)
CREATE TABLE IF NOT EXISTS systems (
  id         SERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  series     TEXT,                          -- e.g. '14.3 SEER2'
  tonnage    TEXT,
  ahri       TEXT,
  list_price NUMERIC(12,2) NOT NULL,
  components JSONB NOT NULL DEFAULT '[]',    -- [{sku,name,role}]
  active     BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS orders (
  id           SERIAL PRIMARY KEY,
  customer_id  INTEGER REFERENCES customers(id),
  email        TEXT NOT NULL,               -- guest checkout allowed (homeowner)
  tier         TEXT NOT NULL,               -- tier charged, recorded at order time
  subtotal     NUMERIC(12,2) NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending', -- pending|paid|fulfilled|cancelled|refunded
  braintree_txn TEXT,                        -- Braintree transaction id (added in checkout phase)
  ship_name    TEXT, ship_addr TEXT, ship_city TEXT, ship_state TEXT, ship_zip TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS order_items (
  id         SERIAL PRIMARY KEY,
  order_id   INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  sku        TEXT NOT NULL,
  name       TEXT NOT NULL,
  qty        INTEGER NOT NULL,
  unit_price NUMERIC(12,2) NOT NULL          -- price actually charged (tier applied)
);

CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(status);
