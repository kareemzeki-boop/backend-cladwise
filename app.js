import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Stripe from 'stripe'
import pg from 'pg'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 5000
const { Pool } = pg
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder', { apiVersion: '2024-04-10' })

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}))

app.use('/api/payments/webhook', express.raw({ type: 'application/json' }))
app.use(express.json())

// ─── DB INIT — create tables if they don't exist ──────────────────────────────
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('ARCHITECT','SUPPLIER')),
      subscription_status TEXT NOT NULL DEFAULT 'INACTIVE',
      stripe_customer_id TEXT UNIQUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS profiles_architect (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      company_name TEXT NOT NULL,
      license_number TEXT UNIQUE NOT NULL,
      portfolio TEXT
    );

    CREATE TABLE IF NOT EXISTS profiles_supplier (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      shop_name TEXT NOT NULL,
      category TEXT NOT NULL,
      tax_id TEXT UNIQUE NOT NULL,
      trade_licence_number TEXT UNIQUE,
      trade_licence_emirate TEXT,
      trade_licence_expiry TIMESTAMPTZ,
      verification_status TEXT DEFAULT 'PENDING',
      verification_note TEXT,
      verified_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `)
  console.log('✅ Database tables ready')
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function signToken(userId, role) {
  return jwt.sign({ userId, role }, process.env.JWT_SECRET || 'cladwise_secret_2025', { expiresIn: '7d' })
}

async function protect(req, res, next) {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token provided.' })
    const token = authHeader.split(' ')[1]
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cladwise_secret_2025')
    const { rows } = await db.query('SELECT id, role, subscription_status FROM users WHERE id=$1', [decoded.userId])
    if (!rows[0]) return res.status(401).json({ message: 'User not found.' })
    req.user = { userId: rows[0].id, role: rows[0].role, subscriptionStatus: rows[0].subscription_status }
    next()
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' })
  }
}

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', app: 'CladWise UAE API' }))
app.get('/api/health', (req, res) => res.json({ status: 'ok', app: 'CladWise UAE' }))

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role, profile } = req.body
    if (!email || !password || !role || !profile) return res.status(400).json({ message: 'All fields required.' })
    if (!['ARCHITECT', 'SUPPLIER'].includes(role)) return res.status(400).json({ message: 'Invalid role.' })

    const hashed = await bcrypt.hash(password, 12)

    const { rows: existing } = await db.query('SELECT id FROM users WHERE email=$1', [email])
    if (existing[0]) return res.status(409).json({ message: 'Email already in use.' })

    const { rows: [user] } = await db.query(
      'INSERT INTO users (email, password, role) VALUES ($1,$2,$3) RETURNING id, email, role, subscription_status, created_at',
      [email.toLowerCase().trim(), hashed, role]
    )

    if (role === 'ARCHITECT') {
      const { companyName, licenseNumber, portfolio } = profile
      if (!companyName || !licenseNumber) return res.status(400).json({ message: 'companyName and licenseNumber required.' })
      await db.query(
        'INSERT INTO profiles_architect (user_id, company_name, license_number, portfolio) VALUES ($1,$2,$3,$4)',
        [user.id, companyName, licenseNumber, portfolio || null]
      )
    } else {
      const { shopName, category, taxId, tradeLicenceNumber, tradeLicenceEmirate, tradeLicenceExpiry } = profile
      if (!shopName || !category || !taxId) return res.status(400).json({ message: 'shopName, category and taxId required.' })
      await db.query(
        `INSERT INTO profiles_supplier (user_id, shop_name, category, tax_id, trade_licence_number, trade_licence_emirate, trade_licence_expiry)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [user.id, shopName, category, taxId, tradeLicenceNumber || null, tradeLicenceEmirate || null, tradeLicenceExpiry ? new Date(tradeLicenceExpiry) : null]
      )
    }

    const token = signToken(user.id, user.role)
    return res.status(201).json({ message: 'Account created.', token, user })
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ message: 'Email or ID already in use.' })
    return res.status(400).json({ message: err.message || 'Registration failed.' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({ message: 'Email and password required.' })
    const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()])
    const user = rows[0]
    const dummyHash = '$2a$12$dummyhashtopreventtiming00000000000000000000000000000000'
    const isMatch = user ? await bcrypt.compare(password, user.password) : await bcrypt.compare(password, dummyHash).then(() => false)
    if (!user || !isMatch) return res.status(401).json({ message: 'Invalid email or password.' })
    const token = signToken(user.id, user.role)
    const { password: _, ...safeUser } = user
    return res.json({ token, user: safeUser })
  } catch (err) {
    return res.status(500).json({ message: 'Login failed.' })
  }
})

// ─── USERS ────────────────────────────────────────────────────────────────────
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const { rows: [user] } = await db.query(
      'SELECT id, email, role, subscription_status, created_at FROM users WHERE id=$1',
      [req.user.userId]
    )
    if (!user) return res.status(404).json({ message: 'User not found.' })

    let profile = null
    if (user.role === 'ARCHITECT') {
      const { rows } = await db.query('SELECT * FROM profiles_architect WHERE user_id=$1', [user.id])
      profile = rows[0] || null
    } else {
      const { rows } = await db.query('SELECT * FROM profiles_supplier WHERE user_id=$1', [user.id])
      profile = rows[0] || null
    }
    return res.json({ user, profile })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch user.' })
  }
})

// ─── ADMIN ────────────────────────────────────────────────────────────────────
app.get('/api/admin/users', protect, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT id, email, role, subscription_status, created_at FROM users ORDER BY created_at DESC'
    )
    return res.json({ users: rows, count: rows.length })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch users.' })
  }
})

app.get('/api/admin/suppliers', protect, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT ps.*, u.email, u.created_at as user_created_at
      FROM profiles_supplier ps
      JOIN users u ON u.id = ps.user_id
      ORDER BY ps.created_at DESC
    `)
    const suppliers = rows.map(r => ({
      id: r.id, shopName: r.shop_name, category: r.category, taxId: r.tax_id,
      tradeLicenceNumber: r.trade_licence_number, tradeLicenceEmirate: r.trade_licence_emirate,
      tradeLicenceExpiry: r.trade_licence_expiry, verificationStatus: r.verification_status,
      verificationNote: r.verification_note, verifiedAt: r.verified_at, createdAt: r.created_at,
      user: { email: r.email, createdAt: r.user_created_at }
    }))
    return res.json({ suppliers })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch suppliers.' })
  }
})

app.patch('/api/admin/suppliers/:id/verify', protect, async (req, res) => {
  try {
    const { id } = req.params
    const { status, note } = req.body
    if (!['VERIFIED', 'REJECTED'].includes(status)) return res.status(400).json({ message: 'Status must be VERIFIED or REJECTED.' })
    await db.query(
      `UPDATE profiles_supplier SET verification_status=$1, verification_note=$2, verified_at=$3 WHERE id=$4`,
      [status, note || null, status === 'VERIFIED' ? new Date() : null, id]
    )
    return res.json({ message: `Supplier ${status.toLowerCase()}.` })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update.' })
  }
})

// ─── PAYMENTS ─────────────────────────────────────────────────────────────────
app.post('/api/payments/create-session', protect, async (req, res) => {
  try {
    const priceId = req.body.priceId || process.env.STRIPE_PRICE_ID
    const { rows: [user] } = await db.query('SELECT * FROM users WHERE id=$1', [req.user.userId])
    if (!user) return res.status(404).json({ message: 'User not found.' })

    let customerId = user.stripe_customer_id
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, metadata: { userId: user.id } })
      customerId = customer.id
      await db.query('UPDATE users SET stripe_customer_id=$1 WHERE id=$2', [customerId, user.id])
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.CLIENT_URL || 'https://cladwise-front.vercel.app'}?payment=success`,
      cancel_url: `${process.env.CLIENT_URL || 'https://cladwise-front.vercel.app'}?payment=cancelled`,
      metadata: { userId: user.id },
    })
    return res.json({ url: session.url, sessionId: session.id })
  } catch (err) {
    return res.status(500).json({ message: 'Checkout failed: ' + err.message })
  }
})

app.post('/api/payments/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature']
  let event
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'whsec_placeholder')
  } catch (err) {
    return res.status(400).json({ message: 'Webhook error: ' + err.message })
  }
  if (event.type === 'checkout.session.completed') {
    const userId = event.data.object.metadata?.userId
    if (userId) await db.query("UPDATE users SET subscription_status='ACTIVE' WHERE id=$1", [userId])
  }
  return res.json({ received: true })
})

app.get('/api/payments/status', protect, async (req, res) => {
  try {
    const { rows: [user] } = await db.query('SELECT subscription_status FROM users WHERE id=$1', [req.user.userId])
    return res.json({ subscriptionStatus: user.subscription_status, isPremium: user.subscription_status === 'ACTIVE' })
  } catch (err) {
    return res.status(500).json({ message: 'Failed.' })
  }
})

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ message: 'Route not found.' }))

// ─── START ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ CladWise running on port ${PORT}`))
}).catch(err => {
  console.error('❌ DB init failed:', err.message)
  process.exit(1)
})
