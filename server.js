// server.js — Premium Craft backend
// Handles: product database, admin login, product CRUD, photo uploads, storefront API

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Folders ----------
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ---------- Database ----------
const db = new Database(path.join(DATA_DIR, 'store.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tag TEXT,
    description TEXT,
    price INTEGER NOT NULL,
    image_path TEXT,
    glyph TEXT DEFAULT '◈',
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
  );
`);

// ---------- Password hashing (built-in crypto, no extra dependency) ----------
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const candidate = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(hash, 'hex'));
}

// ---------- First-run setup: create default admin if none exists ----------
const adminCount = db.prepare('SELECT COUNT(*) as c FROM admin').get().c;
if (adminCount === 0) {
  const defaultUsername = process.env.ADMIN_USERNAME || 'admin';
  const defaultPassword = process.env.ADMIN_PASSWORD || 'premiumcraft2026';
  const { salt, hash } = createPasswordRecord(defaultPassword);
  db.prepare('INSERT INTO admin (username, password_hash, salt) VALUES (?, ?, ?)')
    .run(defaultUsername, hash, salt);
  console.log('========================================');
  console.log('Default admin account created:');
  console.log('  Username:', defaultUsername);
  console.log('  Password:', defaultPassword);
  console.log('  CHANGE THIS after first login.');
  console.log('========================================');
}

// ---------- Seed sample products on first run ----------
const productCount = db.prepare('SELECT COUNT(*) as c FROM products').get().c;
if (productCount === 0) {
  const seed = db.prepare(`
    INSERT INTO products (name, tag, description, price, glyph, sort_order)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  seed.run('The Maqam Wall Clock', 'Wall Clock · Sheesham', '12" solid wood face, brass hands, silent sweep movement. Engraved numerals, oil-finished.', 6500, '⊙', 1);
  seed.run('Ayat Panel, Carved', 'Wall Panel · Walnut', 'Deep-relief calligraphy carved into solid walnut. 18"×24", ready to hang, custom verse on request.', 9800, '۩', 2);
  seed.run('Bismillah Entry Plaque', 'Name Plaque · Sheesham', 'Hand-routed entryway plaque, 10"×6", with optional family name line beneath. Wall-mount kit included.', 4200, '۞', 3);
}

// ---------- Middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// ---------- File upload setup (photos) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeExt = ['.jpg', '.jpeg', '.png', '.webp'].includes(ext) ? ext : '.jpg';
    cb(null, `product-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${safeExt}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only JPG, PNG, or WEBP images are allowed'));
  }
});

// ---------- Auth middleware ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Not logged in' });
}

// ---------- AUTH ROUTES ----------
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const admin = db.prepare('SELECT * FROM admin WHERE username = ?').get(username);
  if (!admin || !verifyPassword(password, admin.salt, admin.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.adminId = admin.id;
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.adminId) });
});

app.post('/api/admin/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const admin = db.prepare('SELECT * FROM admin WHERE id = ?').get(req.session.adminId);
  if (!verifyPassword(currentPassword, admin.salt, admin.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const { salt, hash } = createPasswordRecord(newPassword);
  db.prepare('UPDATE admin SET password_hash = ?, salt = ? WHERE id = ?').run(hash, salt, admin.id);
  res.json({ ok: true });
});

// ---------- PUBLIC PRODUCT API (storefront reads this) ----------
app.get('/api/products', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY sort_order ASC, id ASC').all();
  res.json(products);
});

// ---------- ADMIN PRODUCT API (requires login) ----------
app.get('/api/admin/products', requireAuth, (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY sort_order ASC, id ASC').all();
  res.json(products);
});

app.post('/api/admin/products', requireAuth, upload.single('image'), (req, res) => {
  const { name, tag, description, price, glyph } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Name and price are required' });
  }
  const priceNum = parseInt(price, 10);
  if (isNaN(priceNum) || priceNum < 0) {
    return res.status(400).json({ error: 'Price must be a valid positive number' });
  }
  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
  const maxOrder = db.prepare('SELECT MAX(sort_order) as m FROM products').get().m || 0;

  const result = db.prepare(`
    INSERT INTO products (name, tag, description, price, image_path, glyph, sort_order)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(name, tag || '', description || '', priceNum, imagePath, glyph || '◈', maxOrder + 1);

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);
  res.json(product);
});

app.put('/api/admin/products/:id', requireAuth, upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { name, tag, description, price, glyph } = req.body;
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Product not found' });

  const priceNum = price !== undefined ? parseInt(price, 10) : existing.price;
  if (isNaN(priceNum) || priceNum < 0) {
    return res.status(400).json({ error: 'Price must be a valid positive number' });
  }

  let imagePath = existing.image_path;
  if (req.file) {
    // remove old image file if it exists
    if (existing.image_path) {
      const oldFile = path.join(__dirname, 'public', existing.image_path);
      if (fs.existsSync(oldFile)) fs.unlinkSync(oldFile);
    }
    imagePath = `/uploads/${req.file.filename}`;
  }

  db.prepare(`
    UPDATE products SET name = ?, tag = ?, description = ?, price = ?, image_path = ?, glyph = ?
    WHERE id = ?
  `).run(
    name || existing.name,
    tag !== undefined ? tag : existing.tag,
    description !== undefined ? description : existing.description,
    priceNum,
    imagePath,
    glyph || existing.glyph,
    id
  );

  const updated = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  res.json(updated);
});

app.delete('/api/admin/products/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Product not found' });

  if (existing.image_path) {
    const file = path.join(__dirname, 'public', existing.image_path);
    if (fs.existsSync(file)) fs.unlinkSync(file);
  }
  db.prepare('DELETE FROM products WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.put('/api/admin/products/:id/reorder', requireAuth, (req, res) => {
  const { id } = req.params;
  const { sort_order } = req.body;
  db.prepare('UPDATE products SET sort_order = ? WHERE id = ?').run(sort_order, id);
  res.json({ ok: true });
});

// ---------- Error handler for upload errors ----------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message.includes('Only JPG')) {
    return res.status(400).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our end' });
});

app.listen(PORT, () => {
  console.log(`Premium Craft server running on port ${PORT}`);
});
