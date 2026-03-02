import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Stripe from 'stripe'
import { PrismaClient } from '@prisma/client'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 5000
const prisma = new PrismaClient()
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-04-10' })

// ─── CORS ─────────────────────────────────────────────────────────────────────
const allowedOrigins = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  process.env.CLIENT_URL,
].filter(Boolean)

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true)
    cb(null, true) // allow all for now
  },
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}))

// ─── BODY PARSING ─────────────────────────────────────────────────────────────
app.use('/api/payments/webhook', express.raw({ type: 'application/json' }))
app.use(express.json())

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function signToken(userId, role) {
  return jwt.sign({ userId, role }, process.env.JWT_SECRET, { expiresIn: '7d' })
}

function safeUser(user) {
  const { password, ...rest } = user
  return rest
}

async function protect(req, res, next) {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided.' })
    }
    const token = authHeader.split(' ')[1]
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, role: true, subscriptionStatus: true },
    })
    if (!user) return res.status(401).json({ message: 'User no longer exists.' })
    req.user = { userId: user.id, role: user.role, subscriptionStatus: user.subscriptionStatus }
    next()
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' })
  }
}

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'CladWise UAE' }))
app.get('/', (req, res) => res.json({ status: 'ok', app: 'CladWise UAE API' }))

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role, profile } = req.body
    if (!email || !password || !role || !profile) {
      return res.status(400).json({ message: 'email, password, role and profile are required.' })
    }
    if (!['ARCHITECT', 'SUPPLIER'].includes(role)) {
      return res.status(400).json({ message: 'role must be ARCHITECT or SUPPLIER.' })
    }
    const hashed = await bcrypt.hash(password, 12)
    const user = await prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({ data: { email, password: hashed, role } })
      if (role === 'ARCHITECT') {
        const { companyName, licenseNumber, portfolio } = profile
        if (!companyName || !licenseNumber) throw new Error('companyName and licenseNumber are required.')
        await tx.profileArchitect.create({ data: { companyName, licenseNumber, portfolio: portfolio || null, userId: newUser.id } })
      } else {
        const { shopName, category, taxId } = profile
        if (!shopName || !category || !taxId) throw new Error('shopName, category and taxId are required.')
        await tx.profileSupplier.create({ data: { shopName, category, taxId, userId: newUser.id } })
      }
      return newUser
    })
    return res.status(201).json({ message: 'Account created.', user: safeUser(user) })
  } catch (err) {
    if (err.code === 'P2002') return res.status(409).json({ message: 'Email already in use.' })
    return res.status(400).json({ message: err.message || 'Registration failed.' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({ message: 'Email and password required.' })
    const user = await prisma.user.findUnique({ where: { email } })
    const dummyHash = '$2a$12$dummyhashtopreventtimingattacks00000000000000000000000'
    const isMatch = user ? await bcrypt.compare(password, user.password) : await bcrypt.compare(password, dummyHash).then(() => false)
    if (!user || !isMatch) return res.status(401).json({ message: 'Invalid email or password.' })
    const token = signToken(user.id, user.role)
    return res.json({ token, user: safeUser(user) })
  } catch (err) {
    return res.status(500).json({ message: 'Login failed.' })
  }
})

// ─── USER ROUTES ──────────────────────────────────────────────────────────────
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      include: { profileArchitect: true, profileSupplier: true },
    })
    if (!user) return res.status(404).json({ message: 'User not found.' })
    const { password, ...safeU } = user
    return res.json({ user: safeU, profile: user.role === 'ARCHITECT' ? user.profileArchitect : user.profileSupplier })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch user.' })
  }
})

app.patch('/api/users/profile', protect, async (req, res) => {
  try {
    const { userId, role } = req.user
    const allowed = role === 'ARCHITECT' ? ['companyName', 'licenseNumber', 'portfolio'] : ['shopName', 'category', 'taxId']
    const data = {}
    for (const key of allowed) { if (req.body[key] !== undefined) data[key] = req.body[key] }
    if (Object.keys(data).length === 0) return res.status(400).json({ message: 'No valid fields.' })
    const profile = role === 'ARCHITECT'
      ? await prisma.profileArchitect.update({ where: { userId }, data })
      : await prisma.profileSupplier.update({ where: { userId }, data })
    return res.json({ profile })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update profile.' })
  }
})

// ─── PROJECT ROUTES ───────────────────────────────────────────────────────────
app.get('/api/projects', protect, async (req, res) => {
  try {
    const projects = await prisma.project.findMany({ where: { userId: req.user.userId }, orderBy: { createdAt: 'desc' } })
    return res.json({ projects })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch projects.' })
  }
})

app.post('/api/projects', protect, async (req, res) => {
  try {
    const { name, location, budget, notes } = req.body
    if (!name) return res.status(400).json({ message: 'Project name required.' })
    const project = await prisma.project.create({ data: { name, location, budget, notes, userId: req.user.userId } })
    return res.status(201).json({ project })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create project.' })
  }
})

// ─── PRODUCT ROUTES ───────────────────────────────────────────────────────────
app.get('/api/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } })
    return res.json({ products })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch products.' })
  }
})

app.post('/api/products', protect, async (req, res) => {
  try {
    if (req.user.role !== 'SUPPLIER') return res.status(403).json({ message: 'Suppliers only.' })
    const { name, material, price, description } = req.body
    if (!name || !material) return res.status(400).json({ message: 'name and material required.' })
    const product = await prisma.product.create({ data: { name, material, price, description, userId: req.user.userId } })
    return res.status(201).json({ product })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create product.' })
  }
})

// ─── PAYMENT ROUTES ───────────────────────────────────────────────────────────
app.post('/api/payments/create-session', protect, async (req, res) => {
  try {
    const priceId = req.body.priceId || process.env.STRIPE_PRICE_ID
    const user = await prisma.user.findUnique({ where: { id: req.user.userId } })
    if (!user) return res.status(404).json({ message: 'User not found.' })
    let customerId = user.stripeCustomerId
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, metadata: { userId: user.id } })
      customerId = customer.id
      await prisma.user.update({ where: { id: user.id }, data: { stripeCustomerId: customerId } })
    }
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.CLIENT_URL}?payment=success`,
      cancel_url: `${process.env.CLIENT_URL}?payment=cancelled`,
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
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    return res.status(400).json({ message: 'Webhook error: ' + err.message })
  }
  if (event.type === 'checkout.session.completed') {
    const userId = event.data.object.metadata?.userId
    if (userId) await prisma.user.update({ where: { id: userId }, data: { subscriptionStatus: 'ACTIVE' } })
  }
  return res.json({ received: true })
})

app.get('/api/payments/status', protect, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.userId }, select: { subscriptionStatus: true } })
    return res.json({ subscriptionStatus: user.subscriptionStatus, isPremium: user.subscriptionStatus === 'ACTIVE' })
  } catch (err) {
    return res.status(500).json({ message: 'Failed.' })
  }
})

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ message: 'Route not found.' }))

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ CladWise server running on port ${PORT}`)
})
