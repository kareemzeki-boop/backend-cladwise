import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Stripe from 'stripe'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 5000
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-04-10' })

// ─── IN-MEMORY STORAGE (MOCK DB) ──────────────────────────────────────────────
// In a real production app, you'd use a database like MongoDB or PostgreSQL.
// For now, we'll use in-memory arrays to keep the app running without Prisma.
const USERS = []
const PROFILES_ARCHITECT = []
const PROFILES_SUPPLIER = []
const DOCUMENTS = []

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}))

app.use('/api/payments/webhook', express.raw({ type: 'application/json' }))
app.use(express.json({ limit: '50mb' }))
app.use(express.urlencoded({ limit: '50mb', extended: true }))

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
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token provided.' })
    const token = authHeader.split(' ')[1]
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = USERS.find(u => u.id === decoded.userId)
    if (!user) return res.status(401).json({ message: 'User no longer exists.' })
    req.user = { userId: user.id, role: user.role, subscriptionStatus: user.subscriptionStatus }
    next()
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' })
  }
}

async function protectAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token provided.' })
    const token = authHeader.split(' ')[1]
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = USERS.find(u => u.id === decoded.userId)
    if (!user || user.role !== 'ADMIN') return res.status(403).json({ message: 'Admin access required.' })
    req.user = { userId: user.id, role: user.role }
    next()
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' })
  }
}

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'CladWise UAE' }))
app.get('/', (req, res) => res.json({ status: 'ok', app: 'CladWise UAE API' }))

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role, profile } = req.body
    if (!email || !password || !role || !profile) return res.status(400).json({ message: 'All fields required.' })
    if (!['ARCHITECT', 'SUPPLIER'].includes(role)) return res.status(400).json({ message: 'Invalid role.' })
    
    if (USERS.find(u => u.email === email)) return res.status(409).json({ message: 'Email already in use.' })

    const hashed = await bcrypt.hash(password, 12)
    const newUser = {
      id: Math.random().toString(36).substr(2, 9),
      email,
      password: hashed,
      role,
      subscriptionStatus: 'FREE',
      createdAt: new Date()
    }
    USERS.push(newUser)
    
    if (role === 'ARCHITECT') {
      const { companyName, licenseNumber, portfolio } = profile
      PROFILES_ARCHITECT.push({ 
        id: Math.random().toString(36).substr(2, 9),
        companyName, licenseNumber, portfolio: portfolio || null, userId: newUser.id 
      })
    } else {
      const { 
        shopName, category, taxId, phoneNumber, contactPerson, address,
        tradeLicenceNumber, tradeLicenceEmirate, tradeLicenceExpiry, tradeLicenceIssueDate 
      } = profile
      
      PROFILES_SUPPLIER.push({
        id: Math.random().toString(36).substr(2, 9),
        shopName, category, taxId, userId: newUser.id,
        phoneNumber: phoneNumber || null,
        contactPerson: contactPerson || null,
        address: address || null,
        tradeLicenceNumber: tradeLicenceNumber || null,
        tradeLicenceEmirate: tradeLicenceEmirate || null,
        tradeLicenceExpiry: tradeLicenceExpiry ? new Date(tradeLicenceExpiry) : null,
        tradeLicenceIssueDate: tradeLicenceIssueDate ? new Date(tradeLicenceIssueDate) : null,
        verificationStatus: 'PENDING'
      })
    }
    
    return res.status(201).json({ message: 'Account created.', user: safeUser(newUser) })
  } catch (err) {
    return res.status(400).json({ message: err.message || 'Registration failed.' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({ message: 'Email and password required.' })
    const user = USERS.find(u => u.email === email)
    const isMatch = user ? await bcrypt.compare(password, user.password) : false
    if (!user || !isMatch) return res.status(401).json({ message: 'Invalid email or password.' })
    const token = signToken(user.id, user.role)
    return res.json({ token, user: safeUser(user) })
  } catch (err) {
    return res.status(500).json({ message: 'Login failed.' })
  }
})

// ─── USERS ────────────────────────────────────────────────────────────────────
app.get('/api/users/me', protect, async (req, res) => {
  try {
    const user = USERS.find(u => u.id === req.user.userId)
    if (!user) return res.status(404).json({ message: 'User not found.' })
    const profile = user.role === 'ARCHITECT' 
      ? PROFILES_ARCHITECT.find(p => p.userId === user.id)
      : PROFILES_SUPPLIER.find(p => p.userId === user.id)
    
    const docs = user.role === 'SUPPLIER' ? DOCUMENTS.filter(d => d.supplierId === profile?.id) : []
    
    return res.json({ user: safeUser(user), profile: { ...profile, documents: docs } })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch user.' })
  }
})

// ─── SUPPLIERS ────────────────────────────────────────────────────────────────
app.post('/api/suppliers/documents', protect, async (req, res) => {
  try {
    if (req.user.role !== 'SUPPLIER') return res.status(403).json({ message: 'Suppliers only.' })
    const { documentType, documentUrl, documentName, expiryDate } = req.body
    const supplier = PROFILES_SUPPLIER.find(p => p.userId === req.user.userId)
    if (!supplier) return res.status(404).json({ message: 'Supplier profile not found.' })
    
    const doc = {
      id: Math.random().toString(36).substr(2, 9),
      supplierId: supplier.id,
      documentType, documentUrl, documentName,
      expiryDate: expiryDate ? new Date(expiryDate) : null,
      uploadedAt: new Date()
    }
    DOCUMENTS.push(doc)
    return res.status(201).json({ document: doc })
  } catch (err) {
    return res.status(500).json({ message: 'Failed to upload document.' })
  }
})

// ─── ADMIN ────────────────────────────────────────────────────────────────────
app.get('/api/admin/suppliers', protectAdmin, async (req, res) => {
  return res.json({ suppliers: PROFILES_SUPPLIER })
})

app.patch('/api/admin/suppliers/:id/verify', protectAdmin, async (req, res) => {
  const { status } = req.body
  const supplier = PROFILES_SUPPLIER.find(p => p.id === req.params.id)
  if (!supplier) return res.status(404).json({ message: 'Supplier not found.' })
  supplier.verificationStatus = status
  return res.json({ supplier })
})

app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
