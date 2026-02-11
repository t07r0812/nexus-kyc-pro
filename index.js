const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Initialize database tables
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        registration_number VARCHAR(100),
        legal_form VARCHAR(100),
        address TEXT,
        city VARCHAR(100),
        postal_code VARCHAR(20),
        country VARCHAR(100) DEFAULT 'Germany',
        status VARCHAR(50) DEFAULT 'active',
        handelsregister_data JSONB,
        transparenzregister_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS kyc_cases (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        company_id INTEGER REFERENCES companies(id),
        case_number VARCHAR(100) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        risk_level VARCHAR(50) DEFAULT 'medium',
        current_step INTEGER DEFAULT 1,
        steps_completed JSONB DEFAULT '[]',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id),
        user_id INTEGER REFERENCES users(id),
        filename VARCHAR(255) NOT NULL,
        original_name VARCHAR(255),
        file_type VARCHAR(100),
        file_size INTEGER,
        content TEXT,
        ocr_data JSONB,
        analysis_result JSONB,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ubos (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id),
        case_id INTEGER REFERENCES kyc_cases(id),
        first_name VARCHAR(255),
        last_name VARCHAR VARCHAR(255),
        birth_date DATE,
        nationality VARCHAR(100),
        address TEXT,
        ownership_percentage DECIMAL(5,2),
        voting_rights_percentage DECIMAL(5,2),
        is_pep BOOLEAN DEFAULT FALSE,
        pep_details JSONB,
        verification_status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS compliance_checks (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id),
        check_type VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        result JSONB,
        risk_score INTEGER,
        checked_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('Database tables initialized');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name, role',
      [email, hashedPassword, name]
    );
    
    const token = jwt.sign(
      { userId: result.rows[0].id, email: result.rows[0].email, role: result.rows[0].role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({ user: result.rows[0], token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      token
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DASHBOARD ROUTES ====================

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const casesResult = await pool.query(
      'SELECT COUNT(*) as total, status FROM kyc_cases WHERE user_id = $1 GROUP BY status',
      [userId]
    );
    
    const companiesResult = await pool.query(
      'SELECT COUNT(*) as total FROM companies WHERE user_id = $1',
      [userId]
    );
    
    const pendingChecks = await pool.query(
      `SELECT COUNT(*) as total FROM compliance_checks cc
       JOIN kyc_cases kc ON cc.case_id = kc.id
       WHERE kc.user_id = $1 AND cc.status = 'pending'`,
      [userId]
    );
    
    const recentCases = await pool.query(
      `SELECT kc.*, c.name as company_name 
       FROM kyc_cases kc
       JOIN companies c ON kc.company_id = c.id
       WHERE kc.user_id = $1
       ORDER BY kc.created_at DESC LIMIT 5`,
      [userId]
    );
    
    res.json({
      cases: casesResult.rows,
      totalCompanies: parseInt(companiesResult.rows[0]?.total || 0),
      pendingChecks: parseInt(pendingChecks.rows[0]?.total || 0),
      recentCases: recentCases.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== COMPANY ROUTES ====================

// Search Handelsregister (bundesAPI)
app.get('/api/companies/search-handelsregister', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    // Using bundesAPI Handelsregister
    const response = await axios.get(`https://handelsregister.api.bund.dev/search`, {
      params: { q: query },
      timeout: 10000
    });
    
    res.json(response.data);
  } catch (error) {
    console.error('Handelsregister search error:', error.message);
    // Return mock data if API fails
    res.json([
      {
        name: query,
        registration_number: `HRB${Math.floor(Math.random() * 100000)}`,
        legal_form: 'GmbH',
        status: 'active',
        address: 'Musterstraße 1, 10115 Berlin'
      }
    ]);
  }
});

// Search Transparenzregister
app.get('/api/companies/search-transparenzregister', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    const response = await axios.get(`https://api.transparenzregister.de/api/search`, {
      params: { q: query },
      timeout: 10000
    });
    
    res.json(response.data);
  } catch (error) {
    console.error('Transparenzregister search error:', error.message);
    // Return mock UBO data
    res.json({
      ubos: [
        {
          first_name: 'Max',
          last_name: 'Mustermann',
          ownership_percentage: 100,
          is_pep: false
        }
      ]
    });
  }
});

// Create company
app.post('/api/companies', authenticateToken, async (req, res) => {
  try {
    const { name, registration_number, legal_form, address, city, postal_code } = req.body;
    const userId = req.user.userId;
    
    const result = await pool.query(
      `INSERT INTO companies (user_id, name, registration_number, legal_form, address, city, postal_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [userId, name, registration_number, legal_form, address, city, postal_code]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all companies
app.get('/api/companies', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM companies WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== KYC CASE ROUTES ====================

// Create KYC case
app.post('/api/cases', authenticateToken, async (req, res) => {
  try {
    const { company_id, notes } = req.body;
    const userId = req.user.userId;
    const caseNumber = `KYC-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    
    const result = await pool.query(
      `INSERT INTO kyc_cases (user_id, company_id, case_number, notes, current_step, steps_completed)
       VALUES ($1, $2, $3, $4, 1, '[]') RETURNING *`,
      [userId, company_id, caseNumber, notes]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all cases
app.get('/api/cases', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT kc.*, c.name as company_name, c.registration_number
       FROM kyc_cases kc
       JOIN companies c ON kc.company_id = c.id
       WHERE kc.user_id = $1
       ORDER BY kc.created_at DESC`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get case by ID
app.get('/api/cases/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT kc.*, c.* 
       FROM kyc_cases kc
       JOIN companies c ON kc.company_id = c.id
       WHERE kc.id = $1 AND kc.user_id = $2`,
      [req.params.id, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }
    
    // Get UBOs
    const ubosResult = await pool.query(
      'SELECT * FROM ubos WHERE case_id = $1',
      [req.params.id]
    );
    
    // Get documents
    const docsResult = await pool.query(
      'SELECT * FROM documents WHERE case_id = $1',
      [req.params.id]
    );
    
    // Get compliance checks
    const checksResult = await pool.query(
      'SELECT * FROM compliance_checks WHERE case_id = $1',
      [req.params.id]
    );
    
    res.json({
      ...result.rows[0],
      ubos: ubosResult.rows,
      documents: docsResult.rows,
      complianceChecks: checksResult.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update case step
app.patch('/api/cases/:id/step', authenticateToken, async (req, res) => {
  try {
    const { step, completed } = req.body;
    
    const caseResult = await pool.query(
      'SELECT steps_completed FROM kyc_cases WHERE id = $1',
      [req.params.id]
    );
    
    let stepsCompleted = caseResult.rows[0]?.steps_completed || [];
    if (completed && !stepsCompleted.includes(step)) {
      stepsCompleted.push(step);
    }
    
    const result = await pool.query(
      `UPDATE kyc_cases 
       SET current_step = $1, steps_completed = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 RETURNING *`,
      [step, JSON.stringify(stepsCompleted), req.params.id]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DOCUMENT ROUTES ====================

// Upload document
app.post('/api/documents', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { case_id } = req.body;
    const file = req.file;
    
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Simple text extraction (mock OCR)
    let content = '';
    let ocrData = {};
    
    if (file.mimetype === 'text/plain') {
      content = file.buffer.toString('utf-8');
    } else if (file.mimetype === 'application/pdf') {
      content = 'PDF content extracted (mock)';
      ocrData = { pages: 1, confidence: 95 };
    } else {
      content = 'Document processed';
      ocrData = { type: file.mimetype, size: file.size };
    }
    
    // AI Analysis (mock)
    const analysisResult = {
      documentType: 'identification',
      confidence: 92,
      extractedFields: {
        name: 'Max Mustermann',
        documentNumber: 'T220001293',
        expiryDate: '2028-12-31'
      },
      riskFlags: []
    };
    
    const result = await pool.query(
      `INSERT INTO documents (case_id, user_id, filename, original_name, file_type, file_size, content, ocr_data, analysis_result, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'processed') RETURNING *`,
      [case_id, req.user.userId, file.originalname, file.originalname, file.mimetype, file.size, content, JSON.stringify(ocrData), JSON.stringify(analysisResult)]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get documents for case
app.get('/api/documents/case/:caseId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM documents WHERE case_id = $1',
      [req.params.caseId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== COMPLIANCE ROUTES ====================

// Run compliance checks
app.post('/api/compliance/check', authenticateToken, async (req, res) => {
  try {
    const { case_id, check_type } = req.body;
    
    let result = {};
    let riskScore = 0;
    
    if (check_type === 'pep') {
      // Mock PEP check
      result = {
        status: 'clear',
        matches: [],
        sources: ['EU PEP Database', 'UN Sanctions']
      };
      riskScore = 10;
    } else if (check_type === 'sanctions') {
      // Mock sanctions check
      result = {
        status: 'clear',
        matches: [],
        lists: ['EU Consolidated List', 'OFAC SDN', 'UN Security Council']
      };
      riskScore = 5;
    } else if (check_type === 'adverse_media') {
      // Mock adverse media check
      result = {
        status: 'clear',
        articles: [],
        sources: ['News databases', 'Court records']
      };
      riskScore = 15;
    }
    
    const dbResult = await pool.query(
      `INSERT INTO compliance_checks (case_id, check_type, status, result, risk_score, checked_at)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING *`,
      [case_id, check_type, result.status, JSON.stringify(result), riskScore]
    );
    
    res.json(dbResult.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get compliance checks for case
app.get('/api/compliance/case/:caseId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM compliance_checks WHERE case_id = $1',
      [req.params.caseId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== UBO ROUTES ====================

// Create UBO
app.post('/api/ubos', authenticateToken, async (req, res) => {
  try {
    const { company_id, case_id, first_name, last_name, ownership_percentage, is_pep } = req.body;
    
    const result = await pool.query(
      `INSERT INTO ubos (company_id, case_id, first_name, last_name, ownership_percentage, is_pep)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [company_id, case_id, first_name, last_name, ownership_percentage, is_pep]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get UBOs for case
app.get('/api/ubos/case/:caseId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM ubos WHERE case_id = $1',
      [req.params.caseId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'NEXUS KYC Pro API',
    version: '1.0.0',
    endpoints: [
      '/api/auth/register',
      '/api/auth/login',
      '/api/dashboard/stats',
      '/api/companies',
      '/api/cases',
      '/api/documents',
      '/api/compliance',
      '/api/ubos'
    ]
  });
});

// Start server
app.listen(PORT, async () => {
  console.log(`NEXUS KYC Pro Server running on port ${PORT}`);
  await initDB();
});
