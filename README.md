# Premium Craft — Self-Serve Store

This is your website plus a private admin dashboard where you can add, edit,
and delete products (with photos and prices) yourself, any time.

## What's inside

- `server.js` — the backend (handles the database, login, and photo uploads)
- `public/index.html` — your live storefront (customers see this)
- `public/admin/index.html` — admin login page
- `public/admin/dashboard.html` — admin dashboard (add/edit/delete products)

## Your default admin login

  Username: admin
  Password: premiumcraft2026

**Change this password the first time you log in** (there's a "Change
Password" button in the dashboard).

## How to deploy this on Railway

1. Go to your Railway project (the empty one you already created).
2. Click "Deploy from GitHub repo" — you'll first need to push this code
   to a new GitHub repository:
   - Create a new repository at github.com/new (name it anything,
     e.g. "premium-craft-store")
   - Upload all the files in this folder to that repository
     (GitHub's web interface lets you drag-and-drop files directly —
     look for "uploading an existing file" on the new repo page)
3. Back in Railway, click "Deploy from GitHub repo" and select the
   repository you just created.
4. Railway will automatically detect this is a Node.js project and
   install everything it needs.
5. Once deployed, go to the "Settings" tab of your service and click
   "Generate Domain" to get a live public link.
6. Go to the "Variables" tab and add these (see .env.example for reference):
   - ADMIN_USERNAME — your chosen admin username
   - ADMIN_PASSWORD — your chosen admin password
   - SESSION_SECRET — any long random string (mash your keyboard)
   - NODE_ENV — set to: production

## Using the dashboard day to day

1. Go to yoursite.up.railway.app/admin/index.html
2. Log in
3. Click "+ Add Product" — upload a photo, type the name, price,
   description, and category tag
4. Click "Save Product" — it appears on your live site immediately
5. To change a price or photo later, click "Edit" on that product
6. To remove a product, click "Delete"

## A note on cost

This uses a lightweight database (SQLite) that lives inside your Railway
project — it's efficient and should comfortably stay within Railway's
free $5/month credit while your traffic is light. Railway will notify
you if you ever approach that limit.
