// server.js — Premium Craft backend (Supabase + Render version)
// Handles: product database (Supabase), admin login, product CRUD,
// photo uploads (Supabase Storage), storefront API

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Supabase client ----------
// SUPABASE_URL and SUPABASE_SERVICE_KEY come from environment variables,
// set in Render's dashboard. The "service key" (not the public "anon key")
// is required here because the server needs to bypass Row Level Security
// to manage products and admin accounts directly.
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables.');
  process.exit(1);
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const PHOTOS_BUCKET = 'product-photos';

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

// ---------- First-run setup: create default admin + storage bucket if missing ----------
async function ensureSetup() {
  // Create the photo storage bucket if it doesn't exist yet
  const { data: buckets } = await supabase.storage.listBuckets();
  const bucketExists = buckets && buckets.some(b => b.name === PHOTOS_BUCKET);
  if (!bucketExists) {
    const { error } = await supabase.storage.createBucket(PHOTOS_BUCKET, { public: true });
    if (error) console.error('Could not create storage bucket:', error.message);
    else console.log(`Created storage bucket: ${PHOTOS_BUCKET}`);
  }

  // Create a default admin account if none exists
  const { data: admins, error: adminErr } = await supabase.from('admin_users').select('id').limit(1);
  if (adminErr) {
    console.error('Could not check admin_users table. Did you run supabase-setup.sql?', adminErr.message);
    return;
  }
  if (!admins || admins.length === 0) {
    const defaultUsername = process.env.ADMIN_USERNAME || 'admin';
    const defaultPassword = process.env.ADMIN_PASSWORD || 'premiumcraft2026';
    const { salt, hash } = createPasswordRecord(defaultPassword);
    await supabase.from('admin_users').insert({
      username: defaultUsername,
      password_hash: hash,
      salt
    });
    console.log('========================================');
    console.log('Default admin account created:');
    console.log('  Username:', defaultUsername);
    console.log('  Password:', defaultPassword);
    console.log('  CHANGE THIS after first login.');
    console.log('========================================');
  }
}

// ---------- Middleware ----------
// Required so Express correctly detects HTTPS when running behind
// Render's proxy — without this, secure cookies can silently fail to set.
app.set('trust proxy', 1);

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
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// ---------- File upload setup (photos go to memory, then up to Supabase Storage) ----------
// Using memory storage (not disk) because Render's free tier filesystem
// is NOT persistent — files written to disk can disappear on restart.
// Supabase Storage is the permanent home for photos instead.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only JPG, PNG, or WEBP images are allowed'));
  }
});

async function uploadPhotoToSupabase(file) {
  const ext = path.extname(file.originalname).toLowerCase();
  const safeExt = ['.jpg', '.jpeg', '.png', '.webp'].includes(ext) ? ext : '.jpg';
  const filename = `product-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${safeExt}`;

  const { error } = await supabase.storage
    .from(PHOTOS_BUCKET)
    .upload(filename, file.buffer, { contentType: file.mimetype });

  if (error) throw new Error(`Photo upload failed: ${error.message}`);

  const { data } = supabase.storage.from(PHOTOS_BUCKET).getPublicUrl(filename);
  return { publicUrl: data.publicUrl, filename };
}

async function deletePhotoFromSupabase(imagePath) {
  if (!imagePath) return;
  // imagePath is a full public URL; extract just the filename at the end
  const filename = imagePath.split('/').pop();
  if (filename) {
    await supabase.storage.from(PHOTOS_BUCKET).remove([filename]);
  }
}

// ---------- Auth middleware ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Not logged in' });
}

// ---------- AUTH ROUTES ----------
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const { data: admin, error } = await supabase
      .from('admin_users')
      .select('*')
      .eq('username', username)
      .maybeSingle();

    if (error || !admin || !verifyPassword(password, admin.salt, admin.password_hash)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.adminId = admin.id;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on our end' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.adminId) });
});

app.post('/api/admin/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    const { data: admin } = await supabase
      .from('admin_users')
      .select('*')
      .eq('id', req.session.adminId)
      .maybeSingle();

    if (!admin || !verifyPassword(currentPassword, admin.salt, admin.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const { salt, hash } = createPasswordRecord(newPassword);
    await supabase.from('admin_users').update({ password_hash: hash, salt }).eq('id', admin.id);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on our end' });
  }
});

// ---------- PUBLIC PRODUCT API (storefront reads this) ----------
app.get('/api/products', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .order('sort_order', { ascending: true })
      .order('id', { ascending: true });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load products' });
  }
});

// ---------- ADMIN PRODUCT API (requires login) ----------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*')
      .order('sort_order', { ascending: true })
      .order('id', { ascending: true });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load products' });
  }
});

app.post('/api/admin/products', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { name, tag, description, price, glyph } = req.body;
    if (!name || !price) {
      return res.status(400).json({ error: 'Name and price are required' });
    }
    const priceNum = parseInt(price, 10);
    if (isNaN(priceNum) || priceNum < 0) {
      return res.status(400).json({ error: 'Price must be a valid positive number' });
    }

    let imagePath = null;
    if (req.file) {
      const { publicUrl } = await uploadPhotoToSupabase(req.file);
      imagePath = publicUrl;
    }

    const { data: maxRow } = await supabase
      .from('products')
      .select('sort_order')
      .order('sort_order', { ascending: false })
      .limit(1)
      .maybeSingle();
    const nextOrder = (maxRow?.sort_order || 0) + 1;

    const { data, error } = await supabase
      .from('products')
      .insert({
        name, tag: tag || '', description: description || '',
        price: priceNum, image_path: imagePath, glyph: glyph || '◈',
        sort_order: nextOrder
      })
      .select()
      .single(); // safe here: insert().select() always returns exactly the row just created

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not save product' });
  }
});

app.put('/api/admin/products/:id', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, tag, description, price, glyph } = req.body;

    const { data: existing, error: fetchErr } = await supabase
      .from('products').select('*').eq('id', id).maybeSingle();
    if (fetchErr || !existing) return res.status(404).json({ error: 'Product not found' });
    if (isNaN(priceNum) || priceNum < 0) {
      return res.status(400).json({ error: 'Price must be a valid positive number' });
    }

    let imagePath = existing.image_path;
    if (req.file) {
      await deletePhotoFromSupabase(existing.image_path);
      const { publicUrl } = await uploadPhotoToSupabase(req.file);
      imagePath = publicUrl;
    }

    const { data, error } = await supabase
      .from('products')
      .update({
        name: name || existing.name,
        tag: tag !== undefined ? tag : existing.tag,
        description: description !== undefined ? description : existing.description,
        price: priceNum,
        image_path: imagePath,
        glyph: glyph || existing.glyph
      })
      .eq('id', id)
      .select()
      .single(); // safe here: 'existing' was already confirmed to exist above

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not update product' });
  }
});

app.delete('/api/admin/products/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existing, error: fetchErr } = await supabase
      .from('products').select('*').eq('id', id).maybeSingle();
    if (fetchErr || !existing) return res.status(404).json({ error: 'Product not found' });

    await deletePhotoFromSupabase(existing.image_path);
    const { error } = await supabase.from('products').delete().eq('id', id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not delete product' });
  }
});

app.put('/api/admin/products/:id/reorder', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { sort_order } = req.body;
    const { error } = await supabase.from('products').update({ sort_order }).eq('id', id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not reorder product' });
  }
});

// ---------- Error handler for upload errors ----------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || (err.message && err.message.includes('Only JPG'))) {
    return res.status(400).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our end' });
});

// ---------- Start server ----------
ensureSetup()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Premium Craft server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize server:', err);
    process.exit(1);
  });
