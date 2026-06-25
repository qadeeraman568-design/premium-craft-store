-- Premium Craft — Supabase database setup
-- Run this once in Supabase: Dashboard -> SQL Editor -> New Query -> paste this -> Run

-- Products table (same structure as before, now in Postgres)
CREATE TABLE IF NOT EXISTS products (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL,
  tag TEXT DEFAULT '',
  description TEXT DEFAULT '',
  price INTEGER NOT NULL,
  image_path TEXT,
  glyph TEXT DEFAULT '◈',
  sort_order INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Admin accounts table
CREATE TABLE IF NOT EXISTS admin_users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL
);

-- Seed the 3 sample products (only runs if table is empty)
INSERT INTO products (name, tag, description, price, glyph, sort_order)
SELECT * FROM (VALUES
  ('The Maqam Wall Clock', 'Wall Clock · Sheesham', '12" solid wood face, brass hands, silent sweep movement. Engraved numerals, oil-finished.', 6500, '⊙', 1),
  ('Ayat Panel, Carved', 'Wall Panel · Walnut', 'Deep-relief calligraphy carved into solid walnut. 18"×24", ready to hang, custom verse on request.', 9800, '۩', 2),
  ('Bismillah Entry Plaque', 'Name Plaque · Sheesham', 'Hand-routed entryway plaque, 10"×6", with optional family name line beneath. Wall-mount kit included.', 4200, '۞', 3)
) AS seed_data(name, tag, description, price, glyph, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM products);

-- IMPORTANT: Row Level Security
-- This makes sure the PUBLIC API can only READ products (never edit/delete),
-- while your server (using the secret service key) can still do everything.
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

-- Allow anyone to READ products (needed for the public storefront)
CREATE POLICY "Public can view products"
  ON products FOR SELECT
  USING (true);

-- No public policies on admin_users at all — meaning the public API
-- can NEVER read, edit, or see admin accounts. Only your server's
-- service key (used in server.js) can access this table.
