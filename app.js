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
    return res.json({ user: { ...user, subscriptionStatus: user.subscription_status, isPremium: user.subscription_status === 'ACTIVE' }, profile, isPremium: user.subscription_status === 'ACTIVE' })
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



// ─── TEMP UPGRADE ROUTE ───────────────────────────────────────────────────────
app.get('/api/admin/upgrade/:secret/:email', async (req, res) => {
  try {
    if (req.params.secret !== 'cladwise2025admin') return res.status(403).json({ message: 'Forbidden' })
    const { rows } = await db.query(
      "UPDATE users SET subscription_status='ACTIVE' WHERE email=$1 RETURNING id, email, subscription_status",
      [req.params.email]
    )
    if (!rows[0]) return res.status(404).json({ message: 'User not found — have you registered?' })
    return res.json({ success: true, message: '✅ Account upgraded to ACTIVE', user: rows[0] })
  } catch (err) {
    return res.status(500).json({ message: err.message })
  }
})


// ─── TEMP ADMIN UPGRADE (remove after testing) ────────────────────────────────
app.post('/api/admin/force-premium', async (req, res) => {
  try {
    const { email, secret } = req.body
    if (secret !== 'cladwise_admin_2025') return res.status(403).json({ message: 'Forbidden' })
    const { rows } = await db.query(
      "UPDATE users SET subscription_status='ACTIVE' WHERE email=$1 RETURNING id, email, subscription_status",
      [email]
    )
    if (!rows[0]) return res.status(404).json({ message: 'User not found' })
    return res.json({ message: 'User upgraded to ACTIVE', user: rows[0] })
  } catch (err) {
    return res.status(500).json({ message: err.message })
  }
})

// ─── AI PROJECT SPEC ANALYSER ─────────────────────────────────────────────────
app.post('/api/ai/spec-analyser', protect, async (req, res) => {
  try {
    // Must be premium
    const { rows } = await db.query('SELECT subscription_status FROM users WHERE id=$1', [req.user.userId])
    if (rows[0]?.subscription_status !== 'ACTIVE') {
      return res.status(402).json({ message: 'Premium subscription required.', paywall: true })
    }

    const { projectType, location, height, budget, programme, brief, file } = req.body

    const systemPrompt = `You are CladWise UAE's Senior Material Specification Engineer. You produce professional, precise, actionable facade cladding recommendations for UAE construction projects.

Your recommendations must cite specific UAE codes, real 2025 UAE market pricing, and practical supplier/procurement guidance.

MARKET PRICING DATA (UAE 2025 — AED/m² supply only):
- GFRC: AED 350–900/m² (entry to premium custom)
- GFRP: AED 280–750/m² 
- Aluminum (solid/cassette): AED 220–600/m²
- Natural Stone: AED 600–1,800/m²
- ACM-FR: AED 180–420/m²

Installation (labour + fixing): add AED 80–250/m² depending on complexity
Total installed cost = supply + installation + overhead (~15%)

OUTPUT STRUCTURE — always use exactly this format:

## Executive Summary
Brief 2-3 sentence overview of recommendation and key reasoning.

## Primary Recommendation
**Material:** [Name]
**Compliance Status:** PASS ✅ / CONDITIONAL ⚠️
**Primary Reference:** [UAE code citation]
**Why This Material:** Detailed justification tied to project parameters

## Cost Breakdown
**Supply Cost:** AED X–Y /m²
**Installation:** AED X–Y /m²  
**Total Installed (estimated):** AED X–Y /m²
**For [project facade area if mentioned] m²:** AED X–Y total
**Lead Time:** X–Y weeks from order

## UAE Compliance & Approvals
- Fire rating requirement vs material capability
- Civil Defense (DCD/ADCD) requirements
- DCL or QCC testing/certification needed
- ECAS certification status
- Al Sa'fat / Estidama requirements if applicable

## Alternative Options
**Option 2:** [Material] — brief justification, cost range
**Option 3:** [Material] — brief justification, cost range

## Key Risks & Watch Points
Bullet list of project-specific risks and mitigation

## Next Steps
Practical numbered action list for the specifier

Be precise, professional, and commercially useful. Use actual code references.`

    const userMessage = `PROJECT BRIEF FOR ANALYSIS:
- Type: ${projectType}
- Location: ${location}
- Height: ${height}
- Budget: ${budget}
- Programme: ${programme || 'Not specified'}
- Brief: ${brief || 'No additional brief provided'}
${file ? `\nProject document "${file.name}" has been uploaded — incorporate any relevant details.` : ''}`

    const messages = [{ role: 'user', content: userMessage }]

    // If file provided, add as document
    if (file?.data) {
      messages[0].content = [
        { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: file.data } },
        { type: 'text', text: userMessage }
      ]
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 2000,
        system: systemPrompt,
        messages
      })
    })

    const data = await response.json()
    const report = data.content?.[0]?.text || 'Could not generate report.'
    return res.json({ report })
  } catch (err) {
    return res.status(500).json({ message: 'Analyser error: ' + err.message })
  }
})

// ─── SUPPLIER TRIAL APPLICATION ───────────────────────────────────────────────
// ─── EMAIL HELPER (Resend) ────────────────────────────────────────────────────
async function sendEmail({ to, subject, html }) {
  const key = process.env.RESEND_API_KEY
  if (!key) { console.warn('⚠ RESEND_API_KEY not set — skipping email'); return }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'CladWise UAE <notifications@cladwise.ae>', to, subject, html })
    })
    const data = await r.json()
    if (!r.ok) console.error('Resend error:', data)
    else console.log('✅ Email sent to', to)
  } catch (e) { console.error('Email send failed:', e.message) }
}

// ─── SUPPLIER APPLICATION ─────────────────────────────────────────────────────
app.post('/api/suppliers/apply', async (req, res) => {
  try {
    const payload = req.body
    if (!payload?.company?.name || !payload?.contact?.email) {
      return res.status(400).json({ message: 'Company name and contact email are required.' })
    }

    // Ensure table has all needed columns
    await db.query(`
      CREATE TABLE IF NOT EXISTS supplier_applications (
        id SERIAL PRIMARY KEY,
        company_name TEXT NOT NULL,
        contact_email TEXT NOT NULL,
        contact_name TEXT,
        data JSONB NOT NULL,
        status TEXT DEFAULT 'pending',
        review_note TEXT,
        reviewed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `)
    // Add review columns if table pre-existed without them
    await db.query(`ALTER TABLE supplier_applications ADD COLUMN IF NOT EXISTS review_note TEXT`).catch(() => {})
    await db.query(`ALTER TABLE supplier_applications ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ`).catch(() => {})

    const { rows } = await db.query(
      `INSERT INTO supplier_applications (company_name, contact_email, contact_name, data)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [payload.company.name, payload.contact.email, payload.contact.name, JSON.stringify(payload)]
    )
    const appId = rows[0].id

    // ── Notify Kareem ─────────────────────────────────────────────────────────
    const d = payload
    const mats = d.materials?.live?.join(', ') || '—'
    const svcs = d.materials?.services?.join(', ') || '—'
    const emirates = d.materials?.emirates?.join(', ') || '—'
    await sendEmail({
      to: 'kareemzeki@hotmail.com',
      subject: `🏗️ New Founding Supplier Application — ${d.company.name} (#${appId})`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;background:#0b110d;color:#e8f0ea;padding:32px;border-radius:8px">
          <div style="color:#00e5a0;font-size:22px;font-weight:900;margin-bottom:4px">CladWise UAE</div>
          <div style="color:#888;font-size:11px;margin-bottom:24px;letter-spacing:2px">NEW FOUNDING SUPPLIER APPLICATION</div>
          
          <div style="background:#111a13;border:1px solid rgba(0,229,160,0.2);border-left:3px solid #00e5a0;padding:20px;border-radius:4px;margin-bottom:20px">
            <div style="font-size:20px;font-weight:bold;color:#fff">${d.company.name}</div>
            <div style="color:#888;font-size:12px">Application #${appId} · ${new Date().toLocaleString('en-AE', {timeZone:'Asia/Dubai'})}</div>
          </div>

          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <tr><td style="padding:8px 0;color:#888;width:40%">Trade Licence</td><td style="color:#e8f0ea">${d.company.licenseNum || '—'} (${d.company.licenseEmirate || '—'})</td></tr>
            <tr><td style="padding:8px 0;color:#888">Established</td><td style="color:#e8f0ea">${d.company.established || '—'}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Turnover</td><td style="color:#e8f0ea">${d.company.turnover || '—'}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Website</td><td style="color:#e8f0ea">${d.company.website || '—'}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Materials</td><td style="color:#00e5a0">${mats}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Services</td><td style="color:#e8f0ea">${svcs}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Emirates</td><td style="color:#e8f0ea">${emirates}</td></tr>
            <tr><td style="padding:8px 0;color:#888;border-top:1px solid #1a2a1f">Contact Name</td><td style="color:#e8f0ea;border-top:1px solid #1a2a1f">${d.contact.name || '—'} · ${d.contact.title || '—'}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Contact Email</td><td style="color:#e8f0ea">${d.contact.email}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Contact Phone</td><td style="color:#e8f0ea">${d.contact.phone || '—'}</td></tr>
            <tr><td style="padding:8px 0;color:#888">Address</td><td style="color:#e8f0ea">${d.contact.address || '—'}</td></tr>
          </table>

          ${d.company.tagline ? `<div style="margin-top:16px;padding:12px 16px;background:#0d1a0f;border-radius:4px;font-style:italic;color:#aaa;font-size:12px">"${d.company.tagline}"</div>` : ''}

          <div style="margin-top:24px;text-align:center">
            <a href="https://kareemzeki-boop.github.io/Frotned/admin.html" style="background:#00e5a0;color:#000;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:13px">Open Admin Panel →</a>
          </div>
        </div>`
    })

    // ── Confirm to applicant ───────────────────────────────────────────────────
    await sendEmail({
      to: d.contact.email,
      subject: `Your CladWise UAE Founding Supplier Application — ${d.company.name}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;background:#0b110d;color:#e8f0ea;padding:32px;border-radius:8px">
          <div style="color:#00e5a0;font-size:22px;font-weight:900;margin-bottom:24px">CladWise UAE</div>
          <h2 style="font-size:24px;margin-bottom:8px">Application Received ✓</h2>
          <p style="color:#888;line-height:1.7">Dear ${d.contact.name || 'Supplier'},<br><br>
          We have received the founding supplier application for <strong style="color:#fff">${d.company.name}</strong>.<br><br>
          Our team will review your trade licence and details within <strong style="color:#00e5a0">2 business days</strong>. 
          We may reach out to request additional documents if needed.<br><br>
          Once approved, your listing will go live on CladWise UAE with the <strong style="color:#00e5a0">✓ Verified</strong> badge — 
          permanently listed as a founding supplier, visible to every architect and specifier on the platform.</p>

          <div style="background:#111a13;border:1px solid rgba(0,229,160,0.2);padding:16px 20px;border-radius:4px;margin:24px 0">
            <div style="color:#888;font-size:11px;letter-spacing:2px;margin-bottom:8px">YOUR APPLICATION REFERENCE</div>
            <div style="font-size:20px;font-weight:bold;color:#00e5a0">#${appId}</div>
          </div>

          <p style="color:#888;font-size:12px;line-height:1.6">
            Questions? Reply to this email or contact us at <a href="mailto:kareemzeki@hotmail.com" style="color:#00e5a0">kareemzeki@hotmail.com</a><br>
            CladWise UAE · UAE Façade Specification Platform
          </p>
        </div>`
    })

    return res.json({ success: true, id: appId, message: 'Application received. Our team will review within 2 business days.' })
  } catch (err) {
    console.error('Supplier apply error:', err.message)
    return res.status(500).json({ message: 'Application error: ' + err.message })
  }
})

// ─── ADMIN: LIST ALL APPLICATIONS ────────────────────────────────────────────
app.get('/api/admin/applications', async (req, res) => {
  const secret = req.headers['x-admin-secret']
  if (secret !== 'cladwise2025admin') return res.status(403).json({ message: 'Forbidden' })
  try {
    const { rows } = await db.query(
      `SELECT id, company_name, contact_email, contact_name, status, review_note, reviewed_at, created_at, data
       FROM supplier_applications ORDER BY created_at DESC`
    )
    return res.json({ applications: rows })
  } catch (err) {
    return res.status(500).json({ message: err.message })
  }
})

// ─── ADMIN: APPROVE APPLICATION ───────────────────────────────────────────────
app.patch('/api/admin/applications/:id/approve', async (req, res) => {
  const secret = req.headers['x-admin-secret']
  if (secret !== 'cladwise2025admin') return res.status(403).json({ message: 'Forbidden' })
  try {
    const { note } = req.body
    const { rows } = await db.query(
      `UPDATE supplier_applications SET status='approved', review_note=$1, reviewed_at=NOW()
       WHERE id=$2 RETURNING *`,
      [note || '', req.params.id]
    )
    if (!rows[0]) return res.status(404).json({ message: 'Application not found' })
    const a = rows[0]
    const d = a.data
    await sendEmail({
      to: a.contact_email,
      subject: `✓ Approved — Your CladWise UAE Listing is Live`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;background:#0b110d;color:#e8f0ea;padding:32px;border-radius:8px">
          <div style="color:#00e5a0;font-size:22px;font-weight:900;margin-bottom:24px">CladWise UAE</div>
          <div style="color:#00e5a0;font-size:32px;font-weight:900;margin-bottom:8px">You're Live ✓</div>
          <p style="color:#888;line-height:1.7">Dear ${d?.contact?.name || a.contact_name || 'Supplier'},<br><br>
          Your founding supplier listing for <strong style="color:#fff">${a.company_name}</strong> has been <strong style="color:#00e5a0">approved and is now live</strong> on CladWise UAE.<br><br>
          Your profile carries the <strong style="color:#00e5a0">✓ Verified</strong> badge and is visible to every architect and specifier using the platform.
          ${note ? `<br><br><em style="color:#aaa">${note}</em>` : ''}</p>
          <div style="margin-top:24px;text-align:center">
            <a href="https://kareemzeki-boop.github.io/Frotned/#suppliers" style="background:#00e5a0;color:#000;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:13px">View Your Listing →</a>
          </div>
        </div>`
    })
    return res.json({ success: true })
  } catch (err) {
    return res.status(500).json({ message: err.message })
  }
})

// ─── ADMIN: REJECT APPLICATION ────────────────────────────────────────────────
app.patch('/api/admin/applications/:id/reject', async (req, res) => {
  const secret = req.headers['x-admin-secret']
  if (secret !== 'cladwise2025admin') return res.status(403).json({ message: 'Forbidden' })
  try {
    const { note } = req.body
    const { rows } = await db.query(
      `UPDATE supplier_applications SET status='rejected', review_note=$1, reviewed_at=NOW()
       WHERE id=$2 RETURNING *`,
      [note || '', req.params.id]
    )
    if (!rows[0]) return res.status(404).json({ message: 'Application not found' })
    const a = rows[0]
    const d = a.data
    await sendEmail({
      to: a.contact_email,
      subject: `CladWise UAE — Supplier Application Update`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;background:#0b110d;color:#e8f0ea;padding:32px;border-radius:8px">
          <div style="color:#00e5a0;font-size:22px;font-weight:900;margin-bottom:24px">CladWise UAE</div>
          <h2 style="font-size:22px;margin-bottom:8px">Application Update</h2>
          <p style="color:#888;line-height:1.7">Dear ${d?.contact?.name || a.contact_name || 'Supplier'},<br><br>
          Thank you for applying to list <strong style="color:#fff">${a.company_name}</strong> on CladWise UAE.<br><br>
          After review, we are unable to approve your application at this time.
          ${note ? `<br><br><strong style="color:#fff">Reason:</strong> <em style="color:#aaa">${note}</em>` : ''}<br><br>
          If you believe this is an error or wish to provide additional documents, please reply to this email.</p>
          <p style="color:#555;font-size:12px;margin-top:24px">CladWise UAE · UAE Façade Specification Platform</p>
        </div>`
    })
    return res.json({ success: true })
  } catch (err) {
    return res.status(500).json({ message: err.message })
  }
})

// ─── AI DRAWING ANALYSIS ──────────────────────────────────────────────────────
// Accepts a base64-encoded PDF or image, returns extracted facade dimensions.
// No auth required — same open access as /api/ai/specs.
app.post('/api/ai/drawing-analysis', async (req, res) => {
  try {
    const { data, mediaType, filename } = req.body
    if (!data || !mediaType) {
      return res.status(400).json({ message: 'data and mediaType are required.' })
    }

    const isPDF = mediaType === 'application/pdf'
    const contentBlock = isPDF
      ? { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data } }
      : { type: 'image',    source: { type: 'base64', media_type: mediaType, data } }

    const prompt = `You are a UAE facade cost estimation assistant. Analyse this architectural drawing or document and extract facade specification data.

Return ONLY a JSON object (no markdown, no explanation, no code fences) with exactly these fields:
{
  "area_m2": <number — total facade cladding area in m², your best estimate>,
  "height_category": <one of: "low" | "mid" | "high" | "tall" | "stall">,
  "complexity": <one of: "simple" | "medium" | "complex">,
  "confidence": <"high" | "medium" | "low">,
  "notes": "<one concise sentence explaining what you found and any assumptions made>"
}

Height categories: low = under 15m, mid = 15–30m, high = 30–60m, tall = 60–150m, stall = 150m+
Complexity: simple = flat rectilinear panels, medium = some articulation, complex = curves/3D/parametric

If you cannot read the drawing clearly, make a reasonable assumption and note it. Always return valid JSON.`

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'pdfs-2024-09-25'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 500,
        messages: [{ role: 'user', content: [contentBlock, { type: 'text', text: prompt }] }]
      })
    })

    if (!response.ok) {
      const err = await response.text()
      return res.status(500).json({ message: 'Anthropic API error: ' + err })
    }

    const aiData = await response.json()
    const rawText = (aiData.content || []).filter(b => b.type === 'text').map(b => b.text).join('')

    // Strip any accidental markdown fences
    const clean = rawText.replace(/```json|```/g, '').trim()
    let parsed
    try {
      parsed = JSON.parse(clean)
    } catch (e) {
      return res.status(500).json({ message: 'AI returned non-JSON response: ' + rawText.slice(0, 200) })
    }

    return res.json(parsed)
  } catch (err) {
    return res.status(500).json({ message: 'Drawing analysis error: ' + err.message })
  }
})

// ─── AI SPECS ADVISOR ─────────────────────────────────────────────────────────
const SPECS_SYSTEM = `You are the Lead Technical Specifications Advisor for CladWise UAE, a UAE-based construction platform. Act as a "Digital Rulebook" for facade cladding material specification and compliance.

KNOWLEDGE BASE HIERARCHY:
1. UAE Federal Laws: UAE Fire and Life Safety Code of Practice, MoIAT ECAS certification
2. Dubai: Dubai Building Code (DBC 2021), Al Sa'fat Green Building System, DEWA, DM, DCL (Dubai Central Laboratory)
3. Abu Dhabi: Estidama Pearl Rating, ADM Specs, ADSSC, QCC, ADCD (Abu Dhabi Civil Defense)
4. Sharjah: SEWA and Sharjah Municipality
5. International: ISO, ASTM, BS EN, DIN (where local codes reference them)

KEY AUTHORITIES:
- MoIAT: UAE Federal product conformity and ECAS certification
- DCL (Dubai Central Lab): Testing/certification for Dubai materials
- QCC (Abu Dhabi Quality & Conformity): Product certification for Abu Dhabi
- Civil Defense (DCD/ADCD): Mandatory for cladding, insulation, fire-related specs

MATERIALS: GFRC, GFRP, Aluminum/ACM-FR, Natural Stone, ACM-FR

ALWAYS structure responses exactly as:
**Compliance Status:** PASS ✅ / FAIL ❌ / CONDITIONAL ⚠️ / MORE INFO NEEDED ℹ️
**Primary Reference:** [Specific code, year, part, section]
**Technical Requirement:** [Specific values — fire rating, U-value, thickness, test standard]
**Local Nuance:** [Jurisdiction-specific note, approval body, special requirement]
**Recommendation:** [Clear action for the specifier]

Be precise, cite specific standards, flag when Civil Defense or DCL/QCC testing is mandatory.`

// Free usage tracking (by IP — simple, no DB needed)
const freeUsage = new Map()

app.post('/api/ai/specs', async (req, res) => {
  try {
    const { messages, jurisdiction } = req.body
    if (!messages || !Array.isArray(messages)) return res.status(400).json({ message: 'messages array required.' })

    // Check if user is premium
    let isPremium = false
    const authHeader = req.headers.authorization
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const token = authHeader.split(' ')[1]
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'cladwise_secret_2025')
        const { rows } = await db.query('SELECT subscription_status FROM users WHERE id=$1', [decoded.userId])
        if (rows[0]?.subscription_status === 'ACTIVE') isPremium = true
      } catch (e) {}
    }

    // Free limit check (by IP)
    if (!isPremium) {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown'
      const used = freeUsage.get(ip) || 0
      if (used >= 2) {
        return res.status(402).json({ message: 'Free limit reached. Please upgrade to continue.', paywall: true })
      }
      freeUsage.set(ip, used + 1)
    }

    // Proxy to Anthropic
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: SPECS_SYSTEM,
        messages: messages.map(m => ({
          role: m.role,
          content: m.role === 'user' ? `[Jurisdiction: ${jurisdiction || 'Dubai (DBC)'}]\n\n${m.content}` : m.content
        }))
      })
    })

    const data = await response.json()
    const reply = data.content?.[0]?.text || 'Could not process request.'
    return res.json({ reply, isPremium })
  } catch (err) {
    return res.status(500).json({ message: 'AI service error: ' + err.message })
  }
})

// ─── WAITLIST ─────────────────────────────────────────────────────────────────
app.post('/api/waitlist', async (req, res) => {
  const { email, source } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ message: 'Invalid email' });
  try {
    await prisma.waitlist.upsert({
      where: { email },
      update: { source, updatedAt: new Date() },
      create: { email, source: source || 'unknown' }
    });
    res.json({ success: true });
  } catch (e) {
    // If waitlist table doesn't exist yet, just log and succeed silently
    console.log('Waitlist save failed (table may not exist yet):', e.message);
    res.json({ success: true });
  }
});

// ─── AI ADVISORY REPORT PROXY ─────────────────────────────────────────────────
// No auth — open access, proxies a single material prompt to Anthropic
app.post('/api/ai/advisory', async (req, res) => {
  try {
    const { prompt } = req.body
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'prompt string required' })
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }]
      })
    })

    const data = await response.json()
    if (!response.ok) return res.status(response.status).json({ error: data })
    const text = data.content?.[0]?.text || '{}'
    res.json({ text })
  } catch (err) {
    console.error('/api/ai/advisory error:', err)
    res.status(500).json({ error: err.message })
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
