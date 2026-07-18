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
      .select('*, categories(id, name, glyph)')
      .order('sort_order', { ascending: true })
      .order('id', { ascending: true });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load products' });
  }
});

// ---------- PUBLIC CATEGORIES API (storefront circles read this) ----------
app.get('/api/categories', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('categories')
      .select('*')
      .order('sort_order', { ascending: true })
      .order('id', { ascending: true });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load categories' });
  }
});

// ---------- PUBLIC ORDERS API (checkout submits here) ----------
app.post('/api/orders', async (req, res) => {
  try {
    const { customer_name, customer_phone, customer_address, notes, items } = req.body;

    if (!customer_name || !customer_phone || !customer_address) {
      return res.status(400).json({ error: 'Name, phone, and address are required' });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    // Recalculate the total on the server from real product prices —
    // never trust a total sent from the browser, since it could be tampered with.
    const productIds = items.map(i => i.product_id);
    const { data: realProducts, error: productsErr } = await supabase
      .from('products')
      .select('id, name, price')
      .in('id', productIds);
    if (productsErr) throw productsErr;

    let total = 0;
    const verifiedItems = [];
    for (const item of items) {
      const realProduct = realProducts.find(p => p.id === item.product_id);
      if (!realProduct) {
        return res.status(400).json({ error: `Product ${item.product_id} no longer exists` });
      }
      const quantity = Math.max(1, parseInt(item.quantity, 10) || 1);
      total += realProduct.price * quantity;
      verifiedItems.push({
        product_id: realProduct.id,
        name: realProduct.name,
        price: realProduct.price,
        quantity
      });
    }

    const { data: order, error: orderErr } = await supabase
      .from('orders')
      .insert({
        customer_name,
        customer_phone,
        customer_address,
        notes: notes || '',
        items: verifiedItems,
        total_amount: total,
        payment_method: 'cod',
        status: 'pending'
      })
      .select()
      .single(); // safe here: insert().select() always returns exactly the row just created

    if (orderErr) throw orderErr;
    res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not place order. Please try again or message us on WhatsApp.' });
  }
});

// ---------- ADMIN PRODUCT API (requires login) ----------
app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('products')
      .select('*, categories(id, name, glyph)')
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
    const { name, category_id, description, price, glyph } = req.body;
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
        name,
        category_id: category_id ? parseInt(category_id, 10) : null,
        description: description || '',
        price: priceNum, image_path: imagePath, glyph: glyph || '◈',
        sort_order: nextOrder
      })
      .select('*, categories(id, name, glyph)')
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
    const { name, category_id, description, price, glyph } = req.body;

    const { data: existing, error: fetchErr } = await supabase
      .from('products').select('*').eq('id', id).maybeSingle();
    if (fetchErr || !existing) return res.status(404).json({ error: 'Product not found' });

    const priceNum = price !== undefined ? parseInt(price, 10) : existing.price;
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
        category_id: category_id !== undefined ? (category_id ? parseInt(category_id, 10) : null) : existing.category_id,
        description: description !== undefined ? description : existing.description,
        price: priceNum,
        image_path: imagePath,
        glyph: glyph || existing.glyph
      })
      .eq('id', id)
      .select('*, categories(id, name, glyph)')
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

// ---------- ADMIN CATEGORIES API ----------
app.get('/api/admin/categories', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('categories')
      .select('*')
      .order('sort_order', { ascending: true })
      .order('id', { ascending: true });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load categories' });
  }
});

app.post('/api/admin/categories', requireAuth, async (req, res) => {
  try {
    const { name, glyph } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Category name is required' });
    }

    const { data: maxRow } = await supabase
      .from('categories')
      .select('sort_order')
      .order('sort_order', { ascending: false })
      .limit(1)
      .maybeSingle();
    const nextOrder = (maxRow?.sort_order || 0) + 1;

    const { data, error } = await supabase
      .from('categories')
      .insert({ name: name.trim(), glyph: glyph || '◈', sort_order: nextOrder })
      .select()
      .single(); // safe here: insert().select() always returns exactly the row just created

    if (error) {
      if (error.code === '23505') {
        return res.status(400).json({ error: 'A category with this name already exists' });
      }
      throw error;
    }
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not save category' });
  }
});

app.put('/api/admin/categories/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, glyph } = req.body;

    const { data: existing, error: fetchErr } = await supabase
      .from('categories').select('*').eq('id', id).maybeSingle();
    if (fetchErr || !existing) return res.status(404).json({ error: 'Category not found' });

    const { data, error } = await supabase
      .from('categories')
      .update({
        name: name && name.trim() ? name.trim() : existing.name,
        glyph: glyph || existing.glyph
      })
      .eq('id', id)
      .select()
      .single(); // safe here: 'existing' was already confirmed to exist above

    if (error) {
      if (error.code === '23505') {
        return res.status(400).json({ error: 'A category with this name already exists' });
      }
      throw error;
    }
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not update category' });
  }
});

app.delete('/api/admin/categories/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existing, error: fetchErr } = await supabase
      .from('categories').select('*').eq('id', id).maybeSingle();
    if (fetchErr || !existing) return res.status(404).json({ error: 'Category not found' });

    // Products that used this category simply lose their category link
    // (category_id becomes null) rather than being deleted themselves.
    await supabase.from('products').update({ category_id: null }).eq('category_id', id);

    const { error } = await supabase.from('categories').delete().eq('id', id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not delete category' });
  }
});

// ---------- ADMIN ORDERS API ----------
app.get('/api/admin/orders', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load orders' });
  }
});

app.put('/api/admin/orders/:id/status', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const validStatuses = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }

    const { data, error } = await supabase
      .from('orders')
      .update({ status })
      .eq('id', id)
      .select()
      .maybeSingle();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Order not found' });
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not update order status' });
  }
});


// ============================================================
// FIELDPRO — Field Team API Endpoints
// ============================================================

// Field team login
app.post('/api/field/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const { data: user, error } = await supabase
      .from('field_users')
      .select('*')
      .eq('username', username.trim())
      .eq('is_active', true)
      .maybeSingle();

    if (error || !user) return res.status(401).json({ error: 'Invalid username or password' });

    const hash = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512').toString('hex');
    if (hash !== user.password_hash) return res.status(401).json({ error: 'Invalid username or password' });

    res.json({
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        phone: user.phone,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get tasks assigned to a field user
app.get('/api/field/tasks/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { data, error } = await supabase
      .from('tasks')
      .select(`
        *,
        stores ( name, address, latitude, longitude, cities ( name ) ),
        projects ( name ),
        clients ( name ),
        orders ( order_number, name )
      `)
      .eq('field_user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const tasks = (data || []).map(t => ({
      id: t.id,
      store_name: t.stores?.name,
      store_id: t.store_id,
      city_name: t.stores?.cities?.name,
      address: t.stores?.address,
      latitude: t.stores?.latitude,
      longitude: t.stores?.longitude,
      project_name: t.projects?.name,
      client_name: t.clients?.name,
      order_number: t.orders?.order_number,
      task_number: t.task_number,
      task_type: t.task_type,
      task_date: t.task_date,
      status: t.status,
      field_user_id: t.field_user_id,
    }));

    res.json({ tasks });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not fetch tasks' });
  }
});

// Update task status
app.put('/api/field/tasks/:taskId/status', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status } = req.body;
    const { error } = await supabase
      .from('tasks')
      .update({ status, completed_at: status === 'complete' ? new Date().toISOString() : null })
      .eq('id', taskId);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not update task status' });
  }
});

// Get assets for a task
app.get('/api/field/tasks/:taskId/assets', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { data, error } = await supabase
      .from('assets')
      .select('*')
      .eq('task_id', taskId)
      .order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ assets: data || [] });
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch assets' });
  }
});

// Update asset status
app.put('/api/field/assets/:assetId/status', async (req, res) => {
  try {
    const { assetId } = req.params;
    const { status } = req.body;
    const { error } = await supabase
      .from('assets')
      .update({ status })
      .eq('id', assetId);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not update asset status' });
  }
});

// Add repair item
app.post('/api/field/repairs', async (req, res) => {
  try {
    const { asset_id, task_id, repair_type, width_mm, height_mm, depth_mm, length_mm, quantity, remarks, status } = req.body;
    const { data, error } = await supabase
      .from('repair_items')
      .insert([{ asset_id, task_id, repair_type, width_mm, height_mm, depth_mm, length_mm, quantity, remarks, status }])
      .select()
      .single();
    if (error) throw error;
    res.json({ repair: data });
  } catch (err) {
    res.status(500).json({ error: 'Could not save repair item' });
  }
});

// Get survey template for a task
app.get('/api/field/tasks/:taskId/survey', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { data: task, error: taskError } = await supabase
      .from('tasks')
      .select('project_id, client_id')
      .eq('id', taskId)
      .maybeSingle();
    if (taskError || !task) return res.status(404).json({ error: 'Task not found' });

    const { data: template, error } = await supabase
      .from('survey_templates')
      .select('*, survey_fields ( * )')
      .eq('project_id', task.project_id)
      .maybeSingle();

    if (error) throw error;
    if (!template) return res.json({ template: null });

    const fields = (template.survey_fields || []).sort((a, b) => a.sort_order - b.sort_order);
    res.json({ template: { ...template, fields } });
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch survey template' });
  }
});

// Save survey response
app.post('/api/field/survey/save', async (req, res) => {
  try {
    const { task_id, template_id, store_id, brand, field_user_id, answers, complete } = req.body;

    const { data: response, error } = await supabase
      .from('survey_responses')
      .insert([{
        task_id, template_id, store_id, brand, field_user_id,
        status: complete ? 'complete' : 'in_progress',
        submitted_at: complete ? new Date().toISOString() : null,
      }])
      .select()
      .single(); // safe — fresh insert always returns one row
    if (error) throw error;

    if (answers && answers.length > 0) {
      const answerRows = answers.map(a => ({
        response_id: response.id,
        field_id: a.field_id,
        field_label: a.field_label,
        answer_text: a.answer_text,
        answer_image_path: a.answer_image_path,
      }));
      await supabase.from('survey_answers').insert(answerRows);
    }

    res.json({ success: true, response_id: response.id });
  } catch (err) {
    res.status(500).json({ error: 'Could not save survey' });
  }
});


// ============================================================
// FIELDPRO ADMIN — Management API Endpoints
// ============================================================

// --- Clients ---
app.get('/api/fieldpro/clients', async (req, res) => {
  try {
    const { data, error } = await supabase.from('clients').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Could not fetch clients' }); }
});

app.post('/api/fieldpro/clients', async (req, res) => {
  try {
    const { name, username, password, email } = req.body;
    if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password required' });
    const salt = require('crypto').randomBytes(16).toString('hex');
    const hash = require('crypto').pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const { data, error } = await supabase.from('clients').insert([{ name, username, password_hash: hash, salt, email }]).select().single();
    if (error) throw error;
    res.json({ client: data });
  } catch (err) { res.status(500).json({ error: 'Could not create client' }); }
});

app.delete('/api/fieldpro/clients/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('clients').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete client' }); }
});

// --- Projects ---
app.get('/api/fieldpro/projects', async (req, res) => {
  try {
    const { data, error } = await supabase.from('projects').select('*, clients(name)').order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(p => ({ ...p, client_name: p.clients?.name })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch projects' }); }
});

app.post('/api/fieldpro/projects', async (req, res) => {
  try {
    const { name, client_id, description } = req.body;
    if (!name || !client_id) return res.status(400).json({ error: 'Name and client required' });
    const { data, error } = await supabase.from('projects').insert([{ name, client_id, description }]).select().single();
    if (error) throw error;
    res.json({ project: data });
  } catch (err) { res.status(500).json({ error: 'Could not create project' }); }
});

app.delete('/api/fieldpro/projects/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('projects').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete project' }); }
});

// --- Orders ---
app.get('/api/fieldpro/orders', async (req, res) => {
  try {
    const { data, error } = await supabase.from('orders').select('*, projects(name), clients(name)').order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(o => ({ ...o, project_name: o.projects?.name, client_name: o.clients?.name })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch orders' }); }
});

app.post('/api/fieldpro/orders', async (req, res) => {
  try {
    const { order_number, name, project_id, client_id } = req.body;
    if (!order_number || !name || !project_id || !client_id) return res.status(400).json({ error: 'All fields required' });
    const { data, error } = await supabase.from('orders').insert([{ order_number, name, project_id, client_id }]).select().single();
    if (error) throw error;
    res.json({ order: data });
  } catch (err) { res.status(500).json({ error: 'Could not create order' }); }
});

app.delete('/api/fieldpro/orders/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('orders').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete order' }); }
});

// --- Stores ---
app.get('/api/fieldpro/stores', async (req, res) => {
  try {
    const { data, error } = await supabase.from('stores').select('*, cities(name)').order('name');
    if (error) throw error;
    res.json((data || []).map(s => ({ ...s, city_name: s.cities?.name })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch stores' }); }
});

app.post('/api/fieldpro/stores', async (req, res) => {
  try {
    const { name, city_id, address } = req.body;
    if (!name || !city_id) return res.status(400).json({ error: 'Name and city required' });
    const { data, error } = await supabase.from('stores').insert([{ name, city_id, address }]).select().single();
    if (error) throw error;
    res.json({ store: data });
  } catch (err) { res.status(500).json({ error: 'Could not create store' }); }
});

app.delete('/api/fieldpro/stores/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('stores').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete store' }); }
});

// --- Field Users ---
app.get('/api/fieldpro/field-users', async (req, res) => {
  try {
    const { data, error } = await supabase.from('field_users').select('id,name,username,phone,is_active,created_at').order('name');
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Could not fetch field users' }); }
});

app.post('/api/fieldpro/field-users', async (req, res) => {
  try {
    const { name, username, password, phone } = req.body;
    if (!name || !username || !password) return res.status(400).json({ error: 'Name, username and password required' });
    const salt = require('crypto').randomBytes(16).toString('hex');
    const hash = require('crypto').pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const { data, error } = await supabase.from('field_users').insert([{ name, username, password_hash: hash, salt, phone }]).select().single();
    if (error) throw error;
    res.json({ user: data });
  } catch (err) { res.status(500).json({ error: 'Could not create field user' }); }
});

app.delete('/api/fieldpro/field-users/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('field_users').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete field user' }); }
});

// --- Tasks (Admin) ---
app.get('/api/fieldpro/tasks', async (req, res) => {
  try {
    const { data, error } = await supabase.from('tasks').select(`
      *, stores(name, cities(name)), projects(name), clients(name),
      orders(order_number), field_users(name)
    `).order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(t => ({
      ...t,
      store_name: t.stores?.name,
      city_name: t.stores?.cities?.name,
      project_name: t.projects?.name,
      client_name: t.clients?.name,
      order_number: t.orders?.order_number,
      field_user_name: t.field_users?.name,
    })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch tasks' }); }
});

app.post('/api/fieldpro/tasks', async (req, res) => {
  try {
    const { store_id, order_id, field_user_id, task_type, task_date, task_number } = req.body;
    if (!store_id || !order_id || !field_user_id) return res.status(400).json({ error: 'Store, order and field user required' });
    const { data: order } = await supabase.from('orders').select('project_id, client_id').eq('id', order_id).maybeSingle();
    const { data, error } = await supabase.from('tasks').insert([{
      store_id, order_id, field_user_id, task_type, task_date, task_number,
      project_id: order?.project_id, client_id: order?.client_id, status: 'assign'
    }]).select().single();
    if (error) throw error;
    res.json({ task: data });
  } catch (err) { res.status(500).json({ error: 'Could not create task' }); }
});

app.delete('/api/fieldpro/tasks/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('tasks').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete task' }); }
});

// --- Survey Templates ---
app.get('/api/fieldpro/survey-templates', async (req, res) => {
  try {
    const { data, error } = await supabase.from('survey_templates').select('*, projects(name), clients(name), survey_fields(id)').order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(t => ({ ...t, project_name: t.projects?.name, client_name: t.clients?.name, field_count: t.survey_fields?.length || 0 })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch templates' }); }
});

app.post('/api/fieldpro/survey-templates', async (req, res) => {
  try {
    const { name, project_id, client_id, fields } = req.body;
    if (!name || !project_id || !client_id) return res.status(400).json({ error: 'Name, project and client required' });
    const { data: template, error } = await supabase.from('survey_templates').insert([{ name, project_id, client_id }]).select().single();
    if (error) throw error;
    if (fields && fields.length > 0) {
      const fieldRows = fields.map(f => ({ template_id: template.id, field_label: f.field_label, field_type: f.field_type, field_options: f.field_options, sort_order: f.sort_order }));
      await supabase.from('survey_fields').insert(fieldRows);
    }
    res.json({ template });
  } catch (err) { res.status(500).json({ error: 'Could not create template' }); }
});

app.delete('/api/fieldpro/survey-templates/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('survey_templates').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Could not delete template' }); }
});

// --- Survey Responses (Admin) ---
app.get('/api/fieldpro/survey-responses', async (req, res) => {
  try {
    const { data, error } = await supabase.from('survey_responses').select('*, stores(name), survey_templates(name), field_users(name)').order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(r => ({ ...r, store_name: r.stores?.name, template_name: r.survey_templates?.name, field_user_name: r.field_users?.name })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch responses' }); }
});

app.get('/api/fieldpro/survey-responses/:id', async (req, res) => {
  try {
    const { data, error } = await supabase.from('survey_responses').select('*, stores(name), survey_templates(name), field_users(name), survey_answers(*)').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not found' });
    res.json({ ...data, store_name: data.stores?.name, template_name: data.survey_templates?.name, field_user_name: data.field_users?.name, answers: data.survey_answers || [] });
  } catch (err) { res.status(500).json({ error: 'Could not fetch response' }); }
});

// --- Repairs (Admin) ---
app.get('/api/fieldpro/repairs', async (req, res) => {
  try {
    const { data, error } = await supabase.from('repair_items').select('*, assets(title)').order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(r => ({ ...r, asset_title: r.assets?.title })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch repairs' }); }
});

// ============================================================
// CLIENT PORTAL — API Endpoints
// ============================================================

// Client login
app.post('/api/client/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const { data: client, error } = await supabase.from('clients').select('*').eq('username', username.trim()).eq('is_active', true).maybeSingle();
    if (error || !client) return res.status(401).json({ error: 'Invalid username or password' });
    const hash = require('crypto').pbkdf2Sync(password, client.salt, 100000, 64, 'sha512').toString('hex');
    if (hash !== client.password_hash) return res.status(401).json({ error: 'Invalid username or password' });
    req.session.client_id = client.id;
    req.session.client_name = client.name;
    res.json({ client: { id: client.id, name: client.name, username: client.username } });
  } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});

function requireClient(req, res, next) {
  if (!req.session?.client_id) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// Client tasks
app.get('/api/client/tasks', requireClient, async (req, res) => {
  try {
    const { data, error } = await supabase.from('tasks').select(`
      *, stores(name, cities(name)), projects(name), orders(order_number), field_users(name)
    `).eq('client_id', req.session.client_id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(t => ({
      ...t, store_name: t.stores?.name, city_name: t.stores?.cities?.name,
      project_name: t.projects?.name, order_number: t.orders?.order_number, field_user_name: t.field_users?.name,
    })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch tasks' }); }
});

// Client survey responses
app.get('/api/client/survey-responses', requireClient, async (req, res) => {
  try {
    const { data, error } = await supabase.from('survey_responses').select('*, stores(name), survey_templates(name), field_users(name)').eq('task_id', supabase.from('tasks').select('id').eq('client_id', req.session.client_id)).order('created_at', { ascending: false });
    // Simpler approach - get tasks first then responses
    const { data: tasks } = await supabase.from('tasks').select('id').eq('client_id', req.session.client_id);
    const taskIds = (tasks || []).map(t => t.id);
    if (!taskIds.length) return res.json([]);
    const { data: responses, error: rErr } = await supabase.from('survey_responses').select('*, stores(name), survey_templates(name), field_users(name)').in('task_id', taskIds).order('created_at', { ascending: false });
    if (rErr) throw rErr;
    res.json((responses || []).map(r => ({ ...r, store_name: r.stores?.name, template_name: r.survey_templates?.name, field_user_name: r.field_users?.name })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch responses' }); }
});

// Client single survey response
app.get('/api/client/survey-responses/:id', requireClient, async (req, res) => {
  try {
    const { data, error } = await supabase.from('survey_responses').select('*, stores(name), survey_templates(name), field_users(name), survey_answers(*)').eq('id', req.params.id).maybeSingle();
    if (error || !data) return res.status(404).json({ error: 'Not found' });
    res.json({ ...data, store_name: data.stores?.name, template_name: data.survey_templates?.name, field_user_name: data.field_users?.name, answers: data.survey_answers || [] });
  } catch (err) { res.status(500).json({ error: 'Could not fetch response' }); }
});

// Client repairs
app.get('/api/client/repairs', requireClient, async (req, res) => {
  try {
    const { data: tasks } = await supabase.from('tasks').select('id').eq('client_id', req.session.client_id);
    const taskIds = (tasks || []).map(t => t.id);
    if (!taskIds.length) return res.json([]);
    const { data, error } = await supabase.from('repair_items').select('*, assets(title), tasks(store_id), stores:tasks(store_id(name))').in('task_id', taskIds).order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(r => ({ ...r, asset_title: r.assets?.title })));
  } catch (err) { res.status(500).json({ error: 'Could not fetch repairs' }); }
});

// Client stores
app.get('/api/client/stores', requireClient, async (req, res) => {
  try {
    const { data: tasks } = await supabase.from('tasks').select('store_id, status').eq('client_id', req.session.client_id);
    if (!tasks?.length) return res.json([]);
    const storeIds = [...new Set(tasks.map(t => t.store_id))];
    const { data: stores } = await supabase.from('stores').select('*, cities(name)').in('id', storeIds);
    const { data: responses } = await supabase.from('survey_responses').select('store_id').in('task_id', tasks.map(t => t.store_id));
    res.json((stores || []).map(s => {
      const storeTasks = tasks.filter(t => t.store_id === s.id);
      return {
        ...s, city_name: s.cities?.name,
        total_tasks: storeTasks.length,
        complete_tasks: storeTasks.filter(t => t.status === 'complete').length,
        survey_count: (responses || []).filter(r => r.store_id === s.id).length,
      };
    }));
  } catch (err) { res.status(500).json({ error: 'Could not fetch stores' }); }
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
