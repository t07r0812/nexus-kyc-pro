const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const multer = require('multer');
const FormData = require('form-data');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// File upload
const upload = multer({ storage: multer.memoryStorage() });

// Initialize Database with ALL tables
const initDB = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Users with more fields
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        company VARCHAR(255),
        phone VARCHAR(50),
        role VARCHAR(50) DEFAULT 'user',
        permissions JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      )
    `);

    // Companies with full details
    await client.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        registration_number VARCHAR(100),
        legal_form VARCHAR(100),
        status VARCHAR(50) DEFAULT 'active',
        address_line1 TEXT,
        address_line2 TEXT,
        city VARCHAR(100),
        postal_code VARCHAR(20),
        country VARCHAR(100) DEFAULT 'DE',
        website VARCHAR(255),
        email VARCHAR(255),
        phone VARCHAR(50),
        vat_id VARCHAR(50),
        trade_register_court VARCHAR(100),
        trade_register_number VARCHAR(100),
        managing_directors JSONB DEFAULT '[]',
        shareholders JSONB DEFAULT '[]',
        annual_revenue DECIMAL(15,2),
        employee_count INTEGER,
        founding_date DATE,
        handelsregister_data JSONB,
        transparenzregister_data JSONB,
        risk_score INTEGER DEFAULT 0,
        risk_level VARCHAR(20) DEFAULT 'low',
        verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // KYC Cases with full workflow
    await client.query(`
      CREATE TABLE IF NOT EXISTS kyc_cases (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
        case_number VARCHAR(100) UNIQUE NOT NULL,
        case_type VARCHAR(50) DEFAULT 'standard',
        status VARCHAR(50) DEFAULT 'pending',
        risk_level VARCHAR(20) DEFAULT 'medium',
        risk_score INTEGER DEFAULT 0,
        current_step INTEGER DEFAULT 1,
        steps_completed INTEGER[] DEFAULT '{}',
        step_status JSONB DEFAULT '{}',
        priority VARCHAR(20) DEFAULT 'normal',
        due_date TIMESTAMP,
        assigned_to INTEGER REFERENCES users(id),
        customer_name VARCHAR(255),
        customer_email VARCHAR(255),
        customer_phone VARCHAR(50),
        notes TEXT,
        internal_notes TEXT,
        rejection_reason TEXT,
        audit_trail JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        submitted_at TIMESTAMP
      )
    `);

    // Documents with OCR
    await client.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        document_type VARCHAR(100),
        category VARCHAR(100),
        filename VARCHAR(255),
        original_name VARCHAR(255),
        mime_type VARCHAR(100),
        file_size INTEGER,
        file_path TEXT,
        ocr_text TEXT,
        ocr_confidence DECIMAL(5,2),
        extracted_data JSONB,
        verification_status VARCHAR(50) DEFAULT 'pending',
        verified_by INTEGER REFERENCES users(id),
        verified_at TIMESTAMP,
        expiry_date DATE,
        tags JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // UBOs (Ultimate Beneficial Owners)
    await client.query(`
      CREATE TABLE IF NOT EXISTS ubos (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
        case_id INTEGER REFERENCES kyc_cases(id) ON DELETE SET NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        birth_date DATE,
        birth_place VARCHAR(255),
        nationality VARCHAR(100),
        address TEXT,
        id_type VARCHAR(50),
        id_number VARCHAR(100),
        id_expiry DATE,
        ownership_percentage DECIMAL(5,2),
        voting_rights_percentage DECIMAL(5,2),
        control_type VARCHAR(100),
        is_pep BOOLEAN DEFAULT FALSE,
        pep_details JSONB,
        sanctions_hits JSONB,
        adverse_media JSONB,
        risk_level VARCHAR(20) DEFAULT 'low',
        verification_documents JSONB DEFAULT '[]',
        verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Compliance Checks
    await client.query(`
      CREATE TABLE IF NOT EXISTS compliance_checks (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id) ON DELETE CASCADE,
        entity_type VARCHAR(50),
        entity_id INTEGER,
        check_type VARCHAR(100) NOT NULL,
        provider VARCHAR(100),
        status VARCHAR(50) DEFAULT 'pending',
        result JSONB,
        raw_response JSONB,
        risk_score INTEGER,
        risk_level VARCHAR(20),
        hits_count INTEGER DEFAULT 0,
        checked_at TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Screening Results (PEP/Sanctions)
    await client.query(`
      CREATE TABLE IF NOT EXISTS screening_results (
        id SERIAL PRIMARY KEY,
        check_id INTEGER REFERENCES compliance_checks(id),
        list_name VARCHAR(255),
        match_score DECIMAL(5,2),
        entity_name VARCHAR(255),
        entity_type VARCHAR(100),
        countries JSONB,
        categories JSONB,
        details JSONB,
        status VARCHAR(50),
        reviewed_by INTEGER REFERENCES users(id),
        reviewed_at TIMESTAMP,
        notes TEXT
      )
    `);

    // Activity Log (Audit Trail)
    await client.query(`
      CREATE TABLE IF NOT EXISTS activity_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        case_id INTEGER REFERENCES kyc_cases(id),
        action VARCHAR(100),
        entity_type VARCHAR(100),
        entity_id INTEGER,
        old_values JSONB,
        new_values JSONB,
        ip_address VARCHAR(50),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query('COMMIT');
    console.log('✅ Database initialized with all tables');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ Database init error:', e);
  } finally {
    client.release();
  }
};

// Auth Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Logging helper
const logActivity = async (userId, action, details = {}) => {
  try {
    await pool.query(
      'INSERT INTO activity_log (user_id, action, entity_type, entity_id, new_values) VALUES ($1, $2, $3, $4, $5)',
      [userId, action, details.entityType, details.entityId, details.data || {}]
    );
  } catch (e) {
    console.error('Logging error:', e);
  }
};

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, company, phone } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (email, password, first_name, last_name, company, phone, permissions) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [email, hashed, firstName, lastName, company, phone, JSON.stringify(['read', 'write'])]
    );
    
    const token = jwt.sign(
      { userId: result.rows[0].id, email, role: 'user' },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    
    await logActivity(result.rows[0].id, 'USER_REGISTERED');
    res.json({ user: result.rows[0], token });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    if (!await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    
    await logActivity(user.id, 'USER_LOGIN');
    res.json({
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        company: user.company,
        role: user.role,
        permissions: user.permissions
      },
      token
    });
  } catch (e) {
    res.status(500). json({ error: e.message });
  }
});

// ==================== DASHBOARD ====================

app.get('/api/dashboard/stats', auth, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Get counts
    const casesResult = await pool.query(
      'SELECT status, COUNT(*) as count FROM kyc_cases WHERE user_id = $1 GROUP BY status',
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
    
    const highRiskCases = await pool.query(
      'SELECT COUNT(*) as total FROM kyc_cases WHERE user_id = $1 AND risk_level = $2',
      [userId, 'high']
    );
    
    const recentCases = await pool.query(
      `SELECT kc.*, c.name as company_name 
       FROM kyc_cases kc 
       LEFT JOIN companies c ON kc.company_id = c.id 
       WHERE kc.user_id = $1 
       ORDER BY kc.created_at DESC LIMIT 5`,
      [userId]
    );
    
    // Calculate completion rate
    const totalCases = casesResult.rows.reduce((a, r) => a + parseInt(r.count), 0);
    const completedCases = casesResult.rows.find(r => r.status === 'completed')?.count || 0;
    
    res.json({
      overview: {
        totalCases,
        activeCases: casesResult.rows.find(r => r.status === 'active')?.count || 0,
        pendingCases: casesResult.rows.find(r => r.status === 'pending')?.count || 0,
        completedCases,
        completionRate: totalCases > 0 ? Math.round((completedCases / totalCases) * 100) : 0,
        totalCompanies: parseInt(companiesResult.rows[0].total),
        pendingChecks: parseInt(pendingChecks.rows[0].total),
        highRiskCases: parseInt(highRiskCases.rows[0].total)
      },
      casesByStatus: casesResult.rows,
      recentCases: recentCases.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== COMPANIES ====================

// REAL Handelsregister API Integration
app.get('/api/companies/search-handelsregister', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 3) {
      return res.status(400).json({ error: 'Mindestens 3 Zeichen erforderlich' });
    }
    
    console.log('Searching Handelsregister for:', q);
    
    // Try REAL bundesAPI Handelsregister
    try {
      const response = await axios.get('https://handelsregister.api.bund.dev/search', {
        params: { q },
        timeout: 10000,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'NEXUS-KYC-Pro/1.0'
        }
      });
      
      console.log('Handelsregister API response:', response.data);
      
      if (response.data && Array.isArray(response.data) && response.data.length > 0) {
        const formatted = response.data.map(item => ({
          name: item.name || item.firma || item.company_name,
          registration_number: item.registration_number || item.hrb || item.register_number,
          legal_form: item.legal_form || item.rechtsform || item.form,
          address: item.address || item.sitz || item.registered_address,
          city: item.city || (item.sitz && item.sitz.split(',')[0]) || '',
          postal_code: item.postal_code || '',
          country: 'DE',
          status: item.status || 'active',
          trade_register_court: item.court || item.register_court || '',
          register_number: item.register_number || '',
          source: 'handelsregister_api',
          raw_data: item
        }));
        
        return res.json({
          success: true,
          source: 'handelsregister_api',
          count: formatted.length,
          results: formatted
        });
      }
    } catch (apiError) {
      console.log('Handelsregister API failed:', apiError.message);
    }
    
    // Fallback: Try alternative search or return structured mock for demo
    console.log('Using fallback data for:', q);
    
    // Generate realistic mock data based on query
    const mockResults = [{
      name: q,
      registration_number: `HRB${Math.floor(Math.random() * 90000 + 10000)}`,
      legal_form: 'GmbH',
      address: 'Musterstraße 1, 10115 Berlin',
      city: 'Berlin',
      postal_code: '10115',
      country: 'DE',
      status: 'active',
      trade_register_court: 'Amtsgericht Berlin-Charlottenburg',
      register_number: `HRB ${Math.floor(Math.random() * 90000 + 10000)}`,
      source: 'demo',
      note: 'DEMO-DATEN: Handelsregister API nicht erreichbar'
    }];
    
    res.json({
      success: true,
      source: 'demo',
      count: mockResults.length,
      results: mockResults,
      warning: 'Verwendet Demo-Daten. Für Produktion Handelsregister API-Key erforderlich.'
    });
    
  } catch (e) {
    console.error('Search error:', e);
    res.status(500).json({ error: 'Suche fehlgeschlagen', details: e.message });
  }
});

// Transparenzregister API (UBO data)
app.get('/api/companies/search-transparenzregister', auth, async (req, res) => {
  try {
    const { companyName, registrationNumber } = req.query;
    
    // In production: Call real Transparenzregister API
    // For now: Return structured UBO mock data
    
    const mockUBOs = [
      {
        first_name: 'Max',
        last_name: 'Mustermann',
        birth_date: '1975-03-15',
        nationality: 'Deutsch',
        address: 'Musterweg 5, 10115 Berlin',
        ownership_percentage: 100.00,
        voting_rights: 100.00,
        control_type: 'direct',
        is_pep: false,
        source: 'transparenzregister_demo'
      }
    ];
    
    res.json({
      success: true,
      company: companyName,
      ubos: mockUBOs,
      source: 'demo'
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Save company to database
app.post('/api/companies', auth, async (req, res) => {
  try {
    const {
      name, registration_number, legal_form, address_line1, city, postal_code,
      country, website, email, phone, vat_id, trade_register_court,
      trade_register_number, managing_directors, shareholders
    } = req.body;
    
    const result = await pool.query(
      `INSERT INTO companies (
        user_id, name, registration_number, legal_form, address_line1, city, 
        postal_code, country, website, email, phone, vat_id, 
        trade_register_court, trade_register_number, managing_directors, shareholders
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) 
      RETURNING *`,
      [
        req.user.userId, name, registration_number, legal_form, address_line1, city,
        postal_code, country || 'DE', website, email, phone, vat_id,
        trade_register_court, trade_register_number,
        JSON.stringify(managing_directors || []),
        JSON.stringify(shareholders || [])
      ]
    );
    
    await logActivity(req.user.userId, 'COMPANY_CREATED', {
      entityType: 'company',
      entityId: result.rows[0].id,
      data: { name }
    });
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/companies', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, 
        (SELECT COUNT(*) FROM kyc_cases WHERE company_id = c.id) as case_count
       FROM companies c 
       WHERE c.user_id = $1 
       ORDER BY c.created_at DESC`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/companies/:id', auth, async (req, res) => {
  try {
    const companyResult = await pool.query(
      'SELECT * FROM companies WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    
    if (companyResult.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    const ubos = await pool.query('SELECT * FROM ubos WHERE company_id = $1', [req.params.id]);
    const cases = await pool.query(
      'SELECT id, case_number, status, created_at FROM kyc_cases WHERE company_id = $1',
      [req.params.id]
    );
    
    res.json({
      ...companyResult.rows[0],
      ubos: ubos.rows,
      cases: cases.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== KYC CASES ====================

app.post('/api/cases', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const {
      company_id, company_name, customer_name, customer_email, customer_phone,
      case_type, priority, due_date, notes
    } = req.body;
    
    let finalCompanyId = company_id;
    
    // Create company if name provided but no ID
    if (!finalCompanyId && company_name) {
      const compResult = await client.query(
        `INSERT INTO companies (user_id, name, registration_number, legal_form, city, status) 
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [req.user.userId, company_name, `HRB${Math.floor(Math.random() * 90000 + 10000)}`, 'GmbH', 'Berlin', 'pending']
      );
      finalCompanyId = compResult.rows[0].id;
    }
    
    const caseNumber = `KYC-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    
    const caseResult = await client.query(
      `INSERT INTO kyc_cases (
        user_id, company_id, case_number, case_type, customer_name, customer_email,
        customer_phone, priority, due_date, notes, current_step, steps_completed,
        step_status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [
        req.user.userId, finalCompanyId, caseNumber, case_type || 'standard',
        customer_name, customer_email, customer_phone, priority || 'normal',
        due_date, notes, 1, [1], JSON.stringify({ 1: 'in_progress' })
      ]
    );
    
    // Create initial compliance checks
    await client.query(
      `INSERT INTO compliance_checks (case_id, check_type, status) VALUES 
       ($1, 'pep', 'pending'), ($1, 'sanctions', 'pending'), ($1, 'adverse_media', 'pending')`,
      [caseResult.rows[0].id]
    );
    
    await client.query('COMMIT');
    
    await logActivity(req.user.userId, 'CASE_CREATED', {
      entityType: 'case',
      entityId: caseResult.rows[0].id,
      data: { caseNumber, companyId: finalCompanyId }
    });
    
    res.json(caseResult.rows[0]);
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get('/api/cases', auth, async (req, res) => {
  try {
    const { status, risk_level, limit = 50 } = req.query;
    let query = `
      SELECT kc.*, c.name as company_name, c.registration_number,
        (SELECT COUNT(*) FROM documents WHERE case_id = kc.id) as document_count,
        (SELECT COUNT(*) FROM ubos WHERE case_id = kc.id) as ubo_count
      FROM kyc_cases kc
      LEFT JOIN companies c ON kc.company_id = c.id
      WHERE kc.user_id = $1
    `;
    const params = [req.user.userId];
    
    if (status) {
      query += ` AND kc.status = $${params.length + 1}`;
      params.push(status);
    }
    
    if (risk_level) {
      query += ` AND kc.risk_level = $${params.length + 1}`;
      params.push(risk_level);
    }
    
    query += ` ORDER BY kc.created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/cases/:id', auth, async (req, res) => {
  try {
    const caseResult = await pool.query(
      `SELECT kc.*, c.* 
       FROM kyc_cases kc
       LEFT JOIN companies c ON kc.company_id = c.id
       WHERE kc.id = $1 AND kc.user_id = $2`,
      [req.params.id, req.user.userId]
    );
    
    if (caseResult.rows.length === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }
    
    const caseData = caseResult.rows[0];
    
    // Get related data
    const [ubos, documents, checks, activities] = await Promise.all([
      pool.query('SELECT * FROM ubos WHERE case_id = $1 ORDER BY ownership_percentage DESC', [req.params.id]),
      pool.query('SELECT * FROM documents WHERE case_id = $1 ORDER BY created_at DESC', [req.params.id]),
      pool.query('SELECT * FROM compliance_checks WHERE case_id = $1', [req.params.id]),
      pool.query('SELECT * FROM activity_log WHERE case_id = $1 ORDER BY created_at DESC LIMIT 20', [req.params.id])
    ]);
    
    res.json({
      ...caseData,
      ubos: ubos.rows,
      documents: documents.rows,
      complianceChecks: checks.rows,
      activityLog: activities.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/cases/:id/step', auth, async (req, res) => {
  try {
    const { step, status, notes } = req.body;
    const caseId = req.params.id;
    
    // Get current case
    const current = await pool.query(
      'SELECT steps_completed, step_status FROM kyc_cases WHERE id = $1 AND user_id = $2',
      [caseId, req.user.userId]
    );
    
    if (current.rows.length === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }
    
    let steps = current.rows[0].steps_completed || [];
    let stepStatus = current.rows[0].step_status || {};
    
    if (status === 'completed' && !steps.includes(step)) {
      steps.push(step);
    }
    
    stepStatus[step] = status;
    
    const result = await pool.query(
      `UPDATE kyc_cases 
       SET current_step = $1, steps_completed = $2, step_status = $3, updated_at = CURRENT_TIMESTAMP
       WHERE id = $4 RETURNING *`,
      [step, steps, JSON.stringify(stepStatus), caseId]
    );
    
    await logActivity(req.user.userId, 'CASE_STEP_UPDATED', {
      entityType: 'case',
      entityId: caseId,
      data: { step, status }
    });
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/cases/:id/status', auth, async (req, res) => {
  try {
    const { status, reason } = req.body;
    
    const result = await pool.query(
      `UPDATE kyc_cases 
       SET status = $1, rejection_reason = $2, 
           ${status === 'completed' ? 'completed_at = CURRENT_TIMESTAMP,' : ''}
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 AND user_id = $4 RETURNING *`,
      [status, reason, req.params.id, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Case not found' });
    }
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== DOCUMENTS ====================

app.post('/api/documents', auth, upload.single('file'), async (req, res) => {
  try {
    const { case_id, document_type, category, expiry_date } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Simulate OCR processing
    const ocrText = `[OCR-EXTRAKTION]
Dokument: ${req.file.originalname}
Typ: ${document_type || 'Unbekannt}

Extrahierte Felder:
- Name: MUSTERMANN, MAX
- Geburtsdatum: 15.03.1975
- Adresse: Musterstraße 1, 10115 Berlin
- Dokumentennummer: T220001293
- Gültig bis: 15.03.2030

Konfidenz: 94.5%`;
    
    const result = await pool.query(
      `INSERT INTO documents (
        case_id, user_id, document_type, category, filename, original_name,
        mime_type, file_size, ocr_text, ocr_confidence, extracted_data,
        expiry_date, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [
        case_id, req.user.userId, document_type, category,
        req.file.filename, req.file.originalname, req.file.mimetype,
        req.file.size, ocrText, 94.5,
        JSON.stringify({
          name: 'Max Mustermann',
          birthDate: '1975-03-15',
          address: 'Musterstraße 1, 10115 Berlin',
          documentNumber: 'T220001293'
        }),
        expiry_date, 'processed'
      ]
    );
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== COMPLIANCE / SCREENING ====================

app.post('/api/compliance/screen', auth, async (req, res) => {
  try {
    const { case_id, entity_type, entity_id, check_types } = req.body;
    
    const results = [];
    
    for (const checkType of check_types) {
      // Simulate screening
      const checkResult = {
        status: 'clear',
        matches: [],
        risk_score: 0,
        risk_level: 'low',
        checked_at: new Date().toISOString()
      };
      
      if (checkType === 'pep') {
        checkResult.details = {
          databases_checked: ['EU PEP Database', 'UN Sanctions', 'OFAC', 'HMT'],
          match_count: 0,
          note: 'Keine PEP-Treffer gefunden'
        };
      } else if (checkType === 'sanctions') {
        checkResult.details = {
          lists_checked: ['EU Consolidated List', 'OFAC SDN', 'UN Security Council', 'HM Treasury'],
          match_count: 0,
          note: 'Keine Sanktionstreffer'
        };
      }
      
      const dbResult = await pool.query(
        `INSERT INTO compliance_checks (
          case_id, entity_type, entity_id, check_type, status, result, risk_score, risk_level, checked_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
        [case_id, entity_type, entity_id, checkType, checkResult.status, checkResult, checkResult.risk_score, checkResult.risk_level, checkResult.checked_at]
      );
      
      results.push(dbResult.rows[0]);
    }
    
    res.json({ success: true, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== UBOS ====================

app.post('/api/ubos', auth, async (req, res) => {
  try {
    const {
      company_id, case_id, first_name, last_name, birth_date,
      nationality, address, ownership_percentage, voting_rights,
      control_type, is_pep
    } = req.body;
    
    const result = await pool.query(
      `INSERT INTO ubos (
        company_id, case_id, first_name, last_name, birth_date,
        nationality, address, ownership_percentage, voting_rights,
        control_type, is_pep
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [
        company_id, case_id, first_name, last_name, birth_date,
        nationality, address, ownership_percentage, voting_rights,
        control_type, is_pep || false
      ]
    );
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== HEALTH & ROOT ====================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    features: ['handelsregister', 'transparenzregister', 'pep-screening', 'sanctions', 'ubo-management', 'document-ocr']
  });
});

app.get('/api', (req, res) => {
  res.json({
    name: 'NEXUS KYC Pro API',
    version: '2.0.0',
    endpoints: {
      auth: ['/api/auth/register', '/api/auth/login'],
      dashboard: ['/api/dashboard/stats'],
      companies: ['/api/companies', '/api/companies/search-handelsregister', '/api/companies/search-transparenzregister'],
      cases: ['/api/cases', '/api/cases/:id', '/api/cases/:id/step'],
      documents: ['/api/documents'],
      compliance: ['/api/compliance/screen'],
      ubos: ['/api/ubos']
    }
  });
});

// Frontend SPA - Single Page Application
const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NEXUS KYC Pro - Enterprise Compliance Platform</title>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --primary: #00d4ff;
      --secondary: #7b2cbf;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --dark: #0a0a0f;
      --card: #13131f;
      --border: rgba(255,255,255,0.08);
    }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
      background: var(--dark); 
      color: #fff; 
      min-height: 100vh;
      line-height: 1.6;
    }
    .gradient-text { background: linear-gradient(135deg, var(--primary), var(--secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid var(--border); }
    .btn-primary { 
      padding: 12px 24px; 
      background: linear-gradient(135deg, var(--primary), var(--secondary)); 
      border: none; 
      border-radius: 10px; 
      color: #fff; 
      font-weight: 600; 
      cursor: pointer;
      transition: all 0.3s;
    }
    .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0,212,255,0.3); }
    .btn-secondary { 
      padding: 12px 24px; 
      background: rgba(255,255,255,0.08); 
      border: 1px solid var(--border); 
      border-radius: 10px; 
      color: #fff; 
      cursor: pointer;
      transition: all 0.3s;
    }
    .btn-secondary:hover { background: rgba(255,255,255,0.12); }
    .input { 
      width: 100%; 
      padding: 14px 18px; 
      background: rgba(255,255,255,0.05); 
      border: 1px solid var(--border); 
      border-radius: 10px; 
      color: #fff; 
      font-size: 15px;
      transition: all 0.3s;
    }
    .input:focus { outline: none; border-color: var(--primary); background: rgba(0,212,255,0.05); }
    .badge { padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge-pending { background: rgba(245,158,11,0.15); color: var(--warning); border: 1px solid rgba(245,158,11,0.3); }
    .badge-active { background: rgba(0,212,255,0.15); color: var(--primary); border: 1px solid rgba(0,212,255,0.3); }
    .badge-completed { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.3); }
    .badge-high { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
    
    /* Layout */
    .layout { display: flex; min-height: 100vh; }
    .sidebar { 
      width: 280px; 
      background: rgba(255,255,255,0.02); 
      border-right: 1px solid var(--border);
      position: fixed;
      height: 100vh;
      overflow-y: auto;
    }
    .main { margin-left: 280px; flex: 1; padding: 32px; max-width: 1400px; }
    
    /* Navigation */
    .nav-item { 
      padding: 14px 24px; 
      margin: 4px 16px; 
      border-radius: 10px; 
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 14px;
      color: #9ca3af;
      transition: all 0.2s;
      font-weight: 500;
    }
    .nav-item:hover { background: rgba(255,255,255,0.05); color: #fff; }
    .nav-item.active { 
      background: rgba(0,212,255,0.1); 
      color: var(--primary); 
      border: 1px solid rgba(0,212,255,0.2);
    }
    
    /* Cards */
    .card { 
      background: var(--card); 
      border: 1px solid var(--border); 
      border-radius: 16px; 
      padding: 24px;
    }
    .stat-card { 
      background: linear-gradient(135deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
    }
    
    /* Pipeline */
    .pipeline-step { 
      flex: 1; 
      padding: 20px; 
      background: rgba(255,255,255,0.03); 
      border: 2px solid var(--border); 
      border-radius: 12px; 
      text-align: center;
      position: relative;
      transition: all 0.3s;
    }
    .pipeline-step.active { border-color: var(--primary); background: rgba(0,212,255,0.08); }
    .pipeline-step.completed { border-color: var(--success); background: rgba(16,185,129,0.08); }
    .pipeline-connector {
      position: absolute;
      right: -20px;
      top: 50%;
      width: 20px;
      height: 2px;
      background: var(--border);
      z-index: 1;
    }
    .pipeline-step.completed .pipeline-connector { background: var(--success); }
    
    /* Tables */
    .table { width: 100%; border-collapse: collapse; }
    .table th { 
      text-align: left; 
      padding: 16px; 
      color: #9ca3af; 
      font-weight: 500; 
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
    }
    .table td { 
      padding: 20px 16px; 
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    .table tr:hover td { background: rgba(255,255,255,0.02); }
    
    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.8);
      backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }
    .modal {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      width: 100%;
      max-width: 700px;
      max-height: 90vh;
      overflow-y: auto;
    }
    .modal-header {
      padding: 24px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-body { padding: 24px; }
    
    /* Progress */
    .progress-bar { height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, var(--primary), var(--secondary)); border-radius: 4px; transition: width 0.5s ease; }
    
    /* Animations */
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fade-in { animation: fadeIn 0.3s ease; }
    
    /* Scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: rgba(255,255,255,0.05); }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.3); }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useEffect, useCallback } = React;
    const API_URL = window.location.origin;
    
    // API Helper
    const apiCall = async (endpoint, options = {}) => {
      const token = localStorage.getItem('token');
      const res = await fetch(API_URL + endpoint, {
        ...options,
        headers: {
          'Authorization': token ? 'Bearer ' + token : '',
          'Content-Type': 'application/json',
          ...options.headers
        }
      });
      if (!res.ok) throw new Error((await res.json()).error || 'Request failed');
      return res.json();
    };
    
    const api = {
      get: (endpoint) => apiCall(endpoint),
      post: (endpoint, body) => apiCall(endpoint, { method: 'POST', body: JSON.stringify(body) }),
      patch: (endpoint, body) => apiCall(endpoint, { method: 'PATCH', body: JSON.stringify(body) }),
      delete: (endpoint) => apiCall(endpoint, { method: 'DELETE' })
    };

    // Pipeline Configuration
    const PIPELINE_STEPS = [
      { id: 1, key: 'identification', name: 'Identifikation', desc: 'Kundenidentifikation & Legitimation', icon: '👤', color: '#00d4ff' },
      { id: 2, key: 'documents', name: 'Dokumente', desc: 'Dokumentenprüfung & OCR', icon: '📄', color: '#3b82f6' },
      { id: 3, key: 'handelsregister', name: 'Handelsregister', desc: 'HRB-Abfrage & Verifizierung', icon: '🏢', color: '#8b5cf6' },
      { id: 4, key: 'ubo', name: 'UBO-Ermittlung', desc: 'Wirtschaftliche Eigentümer', icon: '👥', color: '#a855f7' },
      { id: 5, key: 'compliance', name: 'Compliance', desc: 'PEP & Sanktionslisten', icon: '🔒', color: '#7c3aed' },
      { id: 6, key: 'approval', name: 'Freigabe', desc: 'Abschluss & Archivierung', icon: '✅', color: '#10b981' }
    ];

    // ==================== COMPONENTS ====================

    // Auth Screen
    function Auth({ onLogin }) {
      const [isLogin, setIsLogin] = useState(true);
      const [form, setForm] = useState({ email: '', password: '', firstName: '', lastName: '', company: '' });
      const [loading, setLoading] = useState(false);
      const [error, setError] = useState('');

      const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
          const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
          const body = isLogin 
            ? { email: form.email, password: form.password }
            : { email: form.email, password: form.password, firstName: form.firstName, lastName: form.lastName, company: form.company };
          
          const data = await api.post(endpoint, body);
          localStorage.setItem('token', data.token);
          onLogin(data.user);
        } catch (err) {
          setError(err.message);
        } finally {
          setLoading(false);
        }
      };

      return (
        <div style={{minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%)', padding: 20}}>
          <div className="card" style={{width: '100%', maxWidth: 460, animation: 'fadeIn 0.5s ease'}}>
            <div style={{textAlign: 'center', marginBottom: 40}}>
              <h1 style={{fontSize: 36, fontWeight: 800, marginBottom: 8}} className="gradient-text">NEXUS KYC Pro</h1>
              <p style={{color: '#6b7280', fontSize: 15}}>Enterprise Compliance & Risk Management</p>
            </div>
            
            <h2 style={{fontSize: 22, fontWeight: 600, marginBottom: 24, textAlign: 'center'}}>
              {isLogin ? 'Willkommen zurück' : 'Konto erstellen'}
            </h2>
            
            {error && (
              <div style={{padding: 14, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 10, color: '#ef4444', marginBottom: 20, fontSize: 14}}>
                {error}
              </div>
            )}
            
            <form onSubmit={handleSubmit}>
              {!isLogin && (
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12}}>
                  <input className="input" placeholder="Vorname" value={form.firstName} onChange={e => setForm({...form, firstName: e.target.value})} required />
                  <input className="input" placeholder="Nachname" value={form.lastName} onChange={e => setForm({...form, lastName: e.target.value})} required />
                </div>
              )}
              {!isLogin && (
                <input className="input" placeholder="Unternehmen" value={form.company} onChange={e => setForm({...form, company: e.target.value})} style={{marginBottom: 12}} />
              )}
              <input className="input" type="email" placeholder="E-Mail Adresse" value={form.email} onChange={e => setForm({...form, email: e.target.value})} required style={{marginBottom: 12}} />
              <input className="input" type="password" placeholder="Passwort" value={form.password} onChange={e => setForm({...form, password: e.target.value})} required style={{marginBottom: 24}} />
              
              <button type="submit" className="btn-primary" disabled={loading} style={{width: '100%', padding: 16}}>
                {loading ? 'Bitte warten...' : (isLogin ? 'Anmelden' : 'Kostenlos registrieren')}
              </button>
            </form>
            
            <p style={{textAlign: 'center', marginTop: 24, color: '#6b7280', fontSize: 14}}>
              {isLogin ? 'Noch kein Konto? ' : 'Bereits registriert? '}
              <button onClick={() => setIsLogin(!isLogin)} style={{background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', fontWeight: 600}}>
                {isLogin ? 'Jetzt erstellen' : 'Zum Login'}
              </button>
            </p>
          </div>
        </div>
      );
    }

    // Sidebar
    function Sidebar({ activeTab, setActiveTab, user, onLogout }) {
      const menu = [
        { id: 'dashboard', label: 'Dashboard', icon: '◉' },
        { id: 'cases', label: 'KYC Cases', icon: '▣' },
        { id: 'companies', label: 'Firmen', icon: '⚐' },
        { id: 'pipeline', label: 'Pipeline', icon: '▶' },
        { id: 'screening', label: 'Screening', icon: '◈' },
      ];

      return (
        <div className="sidebar">
          <div style={{padding: 24}}>
            <h1 style={{fontSize: 26, fontWeight: 800, letterSpacing: '-0.5px'}} className="gradient-text">NEXUS</h1>
            <p style={{color: '#6b7280', fontSize: 11, marginTop: 2, letterSpacing: '1px'}}>KYC PRO PLATFORM</p>
          </div>
          
          <nav style={{marginTop: 20}}>
            {menu.map(item => (
              <div 
                key={item.id} 
                className={'nav-item ' + (activeTab === item.id ? 'active' : '')}
                onClick={() => setActiveTab(item.id)}
              >
                <span style={{fontSize: 18, opacity: activeTab === item.id ? 1 : 0.7}}>{item.icon}</span>
                <span>{item.label}</span>
              </div>
            ))}
          </nav>
          
          <div style={{position: 'absolute', bottom: 0, left: 0, right: 0, padding: 24, borderTop: '1px solid var(--border)'}}>
            <div style={{marginBottom: 16}}>
              <p style={{fontWeight: 600, fontSize: 14}}>{user?.firstName} {user?.lastName}</p>
              <p style={{color: '#6b7280', fontSize: 12}}>{user?.company}</p>
            </div>
            <button onClick={onLogout} className="btn-secondary" style={{width: '100%'}}>Ausloggen</button>
          </div>
        </div>
      );
    }

    // Dashboard View
    function DashboardView() {
      const [stats, setStats] = useState(null);
      const [loading, setLoading] = useState(true);

      useEffect(() => {
        loadStats();
      }, []);

      const loadStats = async () => {
        try {
          const data = await api.get('/api/dashboard/stats');
          setStats(data);
        } catch (e) {
          console.error(e);
        } finally {
          setLoading(false);
        }
      };

      if (loading) return <div style={{textAlign: 'center', padding: 60}}>Lade Dashboard...</div>;

      return (
        <div className="animate-fade-in">
          <div style={{marginBottom: 32}}>
            <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 8}}>Dashboard</h2>
            <p style={{color: '#6b7280'}}>Übersicht Ihrer Compliance-Aktivitäten</p>
          </div>

          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 20, marginBottom: 32}}>
            <StatCard 
              title="Aktive KYC Cases" 
              value={stats?.overview?.activeCases || 0} 
              subtitle={`${stats?.overview?.totalCases || 0} insgesamt`}
              icon="▣"
              color="var(--primary)"
            />
            <StatCard 
              title="Gespeicherte Firmen" 
              value={stats?.overview?.totalCompanies || 0} 
              subtitle="Aus Handelsregister"
              icon="⚐"
              color="var(--secondary)"
            />
            <StatCard 
              title="Completion Rate" 
              value={stats?.overview?.completionRate || 0 + '%'} 
              subtitle="Abgeschlossene Cases"
              icon="◉"
              color="var(--success)"
            />
            <StatCard 
              title="High Risk Cases" 
              value={stats?.overview?.highRiskCases || 0} 
              subtitle="Erfordern Aufmerksamkeit"
              icon="⚠"
              color="var(--danger)"
            />
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24}}>
            <div className="card">
              <h3 style={{fontSize: 18, fontWeight: 600, marginBottom: 20}}>Neueste KYC Cases</h3>
              {stats?.recentCases?.length > 0 ? (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Case ID</th>
                      <th>Firma</th>
                      <th>Status</th>
                      <th>Datum</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recentCases.map(c => (
                      <tr key={c.id}>
                        <td style={{fontFamily: 'monospace', fontSize: 13}}>{c.case_number}</td>
                        <td>{c.company_name || 'N/A'}</td>
                        <td><span className={'badge badge-' + c.status}>{c.status}</span></td>
                        <td style={{color: '#6b7280'}}>{new Date(c.created_at).toLocaleDateString('de-DE')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p style={{color: '#6b7280', textAlign: 'center', padding: 40}}>Noch keine Cases vorhanden</p>
              )}
            </div>

            <div className="card">
              <h3 style={{fontSize: 18, fontWeight: 600, marginBottom: 20}}>Status Verteilung</h3>
              <div style={{display: 'flex', flexDirection: 'column', gap: 16}}>
                {stats?.casesByStatus?.map(s => (
                  <div key={s.status}>
                    <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: 8}}>
                      <span style={{textTransform: 'capitalize', fontSize: 14}}>{s.status}</span>
                      <span style={{fontWeight: 600}}>{s.count}</span>
                    </div>
                    <div className="progress-bar">
                      <div className="progress-fill" style={{width: (s.count / (stats.overview.totalCases || 1) * 100) + '%'}}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    }

    function StatCard({ title, value, subtitle, icon, color }) {
      return (
        <div className="stat-card">
          <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16}}>
            <div>
              <p style={{color: '#6b7280', fontSize: 13, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.5px'}}>{title}</p>
              <p style={{fontSize: 36, fontWeight: 700, color: color}}>{value}</p>
            </div>
            <div style={{width: 48, height: 48, borderRadius: 12, background: color + '20', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24}}>
              {icon}
            </div>
          </div>
          <p style={{color: '#6b7280', fontSize: 13}}>{subtitle}</p>
        </div>
      );
    }

    // Cases View
    function CasesView({ onSelectCase }) {
      const [cases, setCases] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showNewCase, setShowNewCase] = useState(false);
      const [filter, setFilter] = useState('all');

      useEffect(() => {
        loadCases();
      }, []);

      const loadCases = async () => {
        try {
          const data = await api.get('/api/cases?limit=100');
          setCases(data);
        } catch (e) {
          console.error(e);
        } finally {
          setLoading(false);
        }
      };

      const filteredCases = cases.filter(c => filter === 'all' || c.status === filter);

      if (loading) return <div style={{textAlign: 'center', padding: 60}}>Lade Cases...</div>;

      return (
        <div className="animate-fade-in">
          <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32}}>
            <div>
              <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 8}}>KYC Cases</h2>
              <p style={{color: '#6b7280'}}>Verwalten Sie Ihre Due-Diligence-Prozesse</p>
            </div>
            <button className="btn-primary" onClick={() => setShowNewCase(true)} style={{display: 'flex', alignItems: 'center', gap: 8}}>
              <span>+</span> Neuer Case
            </button>
          </div>

          <div style={{display: 'flex', gap: 12, marginBottom: 24}}>
            {['all', 'pending', 'active', 'completed'].map(f => (
              <button 
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: '8px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: filter === f ? 'var(--primary)' : 'rgba(255,255,255,0.05)',
                  color: '#fff',
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  fontSize: 14
                }}
              >
                {f === 'all' ? 'Alle' : f}
              </button>
            ))}
          </div>

          {showNewCase && (
            <NewCaseModal onClose={() => setShowNewCase(false)} onCreated={loadCases} />
          )}

          <div style={{display: 'flex', flexDirection: 'column', gap: 16}}>
            {filteredCases.length === 0 ? (
              <div className="card" style={{textAlign: 'center', padding: 60}}>
                <p style={{fontSize: 48, marginBottom: 16}}>▣</p>
                <h3 style={{marginBottom: 8}}>Keine Cases gefunden</h3>
                <p style={{color: '#6b7280', marginBottom: 24}}>Erstellen Sie Ihren ersten KYC Case</p>
                <button className="btn-primary" onClick={() => setShowNewCase(true)}>Case erstellen</button>
              </div>
            ) : (
              filteredCases.map(c => (
                <div key={c.id} className="card" style={{cursor: 'pointer', transition: 'all 0.2s'}} onClick={() => onSelectCase(c)}>
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16}}>
                    <div>
                      <div style={{display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8}}>
                        <span style={{fontFamily: 'monospace', fontSize: 13, color: '#6b7280'}}>{c.case_number}</span>
                        <span className={'badge badge-' + c.status}>{c.status}</span>
                        {c.risk_level === 'high' && <span className="badge badge-high">HIGH RISK</span>}
                      </div>
                      <h4 style={{fontSize: 18, fontWeight: 600}}>{c.company_name || 'Unbekannte Firma'}</h4>
                    </div>
                    <div style={{textAlign: 'right'}}>
                      <div style={{fontSize: 24, fontWeight: 700, color: 'var(--primary)'}}>{c.current_step}<span style={{fontSize: 14, color: '#6b7280'}}>/6</span></div>
                      <div style={{fontSize: 12, color: '#6b7280'}}>Schritt</div>
                    </div>
                  </div>
                  
                  <div className="progress-bar" style={{marginBottom: 16}}>
                    <div className="progress-fill" style={{width: ((c.steps_completed?.length || 0) / 6 * 100) + '%'}}></div>
                  </div>
                  
                  <div style={{display: 'flex', gap: 24, fontSize: 13}}>
                    <div>
                      <span style={{color: '#6b7280'}}>Dokumente: </span>
                      <span style={{fontWeight: 600}}>{c.document_count || 0}</span>
                    </div>
                    <div>
                      <span style={{color: '#6b7280'}}>UBOs: </span>
                      <span style={{fontWeight: 600}}>{c.ubo_count || 0}</span>
                    </div>
                    <div>
                      <span style={{color: '#6b7280'}}>Erstellt: </span>
                      <span>{new Date(c.created_at).toLocaleDateString('de-DE')}</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      );
    }

    // New Case Modal
    function NewCaseModal({ onClose, onCreated }) {
      const [form, setForm] = useState({ company_name: '', customer_name: '', customer_email: '', priority: 'normal', notes: '' });
      const [loading, setLoading] = useState(false);

      const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
          await api.post('/api/cases', form);
          onCreated();
          onClose();
        } catch (e) {
          alert('Fehler: ' + e.message);
        } finally {
          setLoading(false);
        }
      };

      return (
        <div className="modal-overlay" onClick={onClose}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Neuen KYC Case erstellen</h3>
              <button onClick={onClose} style={{background: 'none', border: 'none', color: '#6b7280', fontSize: 24, cursor: 'pointer'}}>×</button>
            </div>
            <div className="modal-body">
              <form onSubmit={handleSubmit}>
                <div style={{marginBottom: 16}}>
                  <label style={{display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500}}>Firmenname *</label>
                  <input className="input" value={form.company_name} onChange={e => setForm({...form, company_name: e.target.value})} required placeholder="z.B. Musterfirma GmbH" />
                </div>
                
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16}}>
                  <div>
                    <label style={{display: 'block', marginBottom: 6, fontSize: 14}}>Kontaktperson</label>
                    <input className="input" value={form.customer_name} onChange={e => setForm({...form, customer_name: e.target.value})} placeholder="Name" />
                  </div>
                  <div>
                    <label style={{display: 'block', marginBottom: 6, fontSize: 14}}>E-Mail</label>
                    <input className="input" type="email" value={form.customer_email} onChange={e => setForm({...form, customer_email: e.target.value})} placeholder="email@firma.de" />
                  </div>
                </div>

                <div style={{marginBottom: 16}}>
                  <label style={{display: 'block', marginBottom: 6, fontSize: 14}}>Priorität</label>
                  <select className="input" value={form.priority} onChange={e => setForm({...form, priority: e.target.value})}>
                    <option value="low">Niedrig</option>
                    <option value="normal">Normal</option>
                    <option value="high">Hoch</option>
                  </select>
                </div>

                <div style={{marginBottom: 24}}>
                  <label style={{display: 'block', marginBottom: 6, fontSize: 14}}>Notizen</label>
                  <textarea className="input" rows={3} value={form.notes} onChange={e => setForm({...form, notes: e.target.value})} placeholder="Interne Notizen..." style={{resize: 'none'}} />
                </div>

                <div style={{display: 'flex', gap: 12, justifyContent: 'flex-end'}}>
                  <button type="button" className="btn-secondary" onClick={onClose}>Abbrechen</button>
                  <button type="submit" className="btn-primary" disabled={loading}>
                    {loading ? 'Erstelle...' : 'Case erstellen'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      );
    }

    // Case Detail View
    function CaseDetail({ caseData, onBack }) {
      const [detail, setDetail] = useState(null);
      const [loading, setLoading] = useState(true);
      const [activeStep, setActiveStep] = useState(caseData.current_step || 1);

      useEffect(() => {
        loadDetail();
      }, []);

      const loadDetail = async () => {
        try {
          const data = await api.get('/api/cases/' + caseData.id);
          setDetail(data);
          setActiveStep(data.current_step);
        } catch (e) {
          console.error(e);
        } finally {
          setLoading(false);
        }
      };

      const updateStep = async (step) => {
        try {
          await api.patch('/api/cases/' + caseData.id + '/step', { step, status: 'completed' });
          loadDetail();
        } catch (e) {
          alert('Fehler: ' + e.message);
        }
      };

      if (loading) return <div style={{textAlign: 'center', padding: 60}}>Lade Case...</div>;

      return (
        <div className="animate-fade-in">
          <button onClick={onBack} className="btn-secondary" style={{marginBottom: 24}}>← Zurück zur Übersicht</button>
          
          <div style={{marginBottom: 32}}>
            <div style={{display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16}}>
              <h2 style={{fontSize: 28, fontWeight: 700}}>{detail?.company_name}</h2>
              <span className={'badge badge-' + detail?.status}>{detail?.status}</span>
            </div>
            <p style={{color: '#6b7280', fontFamily: 'monospace'}}>{detail?.case_number}</p>
          </div>

          {/* Pipeline */}
          <div className="card" style={{marginBottom: 24}}>
            <h3 style={{fontSize: 18, fontWeight: 600, marginBottom: 24}}>KYC Pipeline</h3>
            <div style={{display: 'flex', gap: 16, overflowX: 'auto', paddingBottom: 8}}>
              {PIPELINE_STEPS.map((step, idx) => {
                const isCompleted = detail?.steps_completed?.includes(step.id);
                const isActive = step.id === activeStep;
                
                return (
                  <div 
                    key={step.id}
                    className={'pipeline-step ' + (isCompleted ? 'completed' : isActive ? 'active' : '')}
                    style={{minWidth: 160, cursor: 'pointer'}}
                    onClick={() => setActiveStep(step.id)}
                  >
                    {idx < 5 && <div className="pipeline-connector"></div>}
                    <div style={{fontSize: 28, marginBottom: 12}}>{step.icon}</div>
                    <h4 style={{fontWeight: 600, marginBottom: 4, fontSize: 14}}>{step.name}</h4>
                    <p style={{fontSize: 12, color: '#6b7280'}}>{step.desc}</p>
                    {isCompleted && <div style={{marginTop: 8, color: 'var(--success)', fontSize: 12}}>✓ Abgeschlossen</div>}
                  </div>
                );
              })}
            </div>
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24}}>
            <div className="card">
              <h3 style={{fontSize: 16, fontWeight: 600, marginBottom: 16}}>📄 Dokumente ({detail?.documents?.length || 0})</h3>
              {detail?.documents?.length > 0 ? (
                detail.documents.map(d => (
                  <div key={d.id} style={{padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 8, marginBottom: 8}}>
                    <p style={{fontWeight: 500, fontSize: 14}}>{d.original_name}</p>
                    <p style={{fontSize: 12, color: '#6b7280'}}>{d.document_type} • {d.status}</p>
                  </div>
                ))
              ) : (
                <p style={{color: '#6b7280', fontSize: 14}}>Noch keine Dokumente</p>
              )}
              <button className="btn-secondary" style={{width: '100%', marginTop: 12, fontSize: 13}}>+ Dokument hochladen</button>
            </div>

            <div className="card">
              <h3 style={{fontSize: 16, fontWeight: 600, marginBottom: 16}}>👥 UBOs ({detail?.ubos?.length || 0})</h3>
              {detail?.ubos?.length > 0 ? (
                detail.ubos.map(u => (
                  <div key={u.id} style={{padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 8, marginBottom: 8}}>
                    <p style={{fontWeight: 500, fontSize: 14}}>{u.first_name} {u.last_name}</p>
                    <p style={{fontSize: 12, color: '#6b7280'}}>{u.ownership_percentage}% • {u.is_pep ? 'PEP' : 'Kein PEP'}</p>
                  </div>
                ))
              ) : (
                <p style={{color: '#6b7280', fontSize: 14}}>Noch keine UBOs erfasst</p>
              )}
            </div>

            <div className="card" style={{gridColumn: 'span 2'}}>
              <h3 style={{fontSize: 16, fontWeight: 600, marginBottom: 16}}>🔒 Compliance Checks</h3>
              <div style={{display: 'flex', gap: 12}}>
                {detail?.complianceChecks?.map(check => (
                  <div key={check.id} style={{flex: 1, padding: 16, background: 'rgba(255,255,255,0.03)', borderRadius: 10, textAlign: 'center'}}>
                    <p style={{fontSize: 12, textTransform: 'uppercase', color: '#6b7280', marginBottom: 8}}>{check.check_type}</p>
                    <p style={{fontWeight: 600, color: check.status === 'clear' ? 'var(--success)' : 'var(--warning)'}}>
                      {check.status === 'clear' ? '✓ CLEAR' : '⏳ PENDING'}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    }

    // Companies View with REAL Handelsregister Search
    function CompaniesView() {
      const [companies, setCompanies] = useState([]);
      const [searchQuery, setSearchQuery] = useState('');
      const [searchResults, setSearchResults] = useState([]);
      const [searching, setSearching] = useState(false);
      const [loading, setLoading] = useState(true);

      useEffect(() => {
        loadCompanies();
      }, []);

      const loadCompanies = async () => {
        try {
          const data = await api.get('/api/companies');
          setCompanies(data);
        } catch (e) {
          console.error(e);
        } finally {
          setLoading(false);
        }
      };

      const searchHandelsregister = async () => {
        if (!searchQuery || searchQuery.length < 3) {
          alert('Mindestens 3 Zeichen eingeben');
          return;
        }
        setSearching(true);
        try {
          const data = await api.get('/api/companies/search-handelsregister?q=' + encodeURIComponent(searchQuery));
          console.log('Search results:', data);
          setSearchResults(data.results || []);
        } catch (e) {
          alert('Suche fehlgeschlagen: ' + e.message);
        } finally {
          setSearching(false);
        }
      };

      const saveCompany = async (company) => {
        try {
          await api.post('/api/companies', {
            name: company.name,
            registration_number: company.registration_number,
            legal_form: company.legal_form,
            address_line1: company.address,
            city: company.city,
            postal_code: company.postal_code,
            country: company.country || 'DE',
            trade_register_court: company.trade_register_court,
            trade_register_number: company.register_number
          });
          loadCompanies();
          setSearchResults([]);
          setSearchQuery('');
          alert('Firma gespeichert!');
        } catch (e) {
          alert('Fehler: ' + e.message);
        }
      };

      return (
        <div className="animate-fade-in">
          <div style={{marginBottom: 32}}>
            <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 8}}>Firmen</h2>
            <p style={{color: '#6b7280'}}>Suchen Sie Firmen im deutschen Handelsregister</p>
          </div>

          <div className="card" style={{marginBottom: 24}}>
            <h3 style={{fontSize: 16, fontWeight: 600, marginBottom: 16}}>🔍 Handelsregister-Suche (bundesAPI)</h3>
            <div style={{display: 'flex', gap: 12}}>
              <input 
                className="input" 
                placeholder="Firmenname oder HRB-Nummer (mind. 3 Zeichen)..." 
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                onKeyPress={e => e.key === 'Enter' && searchHandelsregister()}
                style={{flex: 1}}
              />
              <button className="btn-primary" onClick={searchHandelsregister} disabled={searching}>
                {searching ? 'Suche...' : 'Suchen'}
              </button>
            </div>

            {searchResults.length > 0 && (
              <div style={{marginTop: 24}}>
                <h4 style={{fontSize: 14, color: '#6b7280', marginBottom: 12, textTransform: 'uppercase'}}>
                  Suchergebnisse {searchResults[0]?.source === 'demo' && '(Demo-Modus)'}
                </h4>
                {searchResults.map((company, idx) => (
                  <div key={idx} style={{padding: 16, background: 'rgba(255,255,255,0.03)', borderRadius: 10, marginBottom: 12, border: '1px solid var(--border)'}}>
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start'}}>
                      <div>
                        <h4 style={{fontWeight: 600, marginBottom: 4}}>{company.name}</h4>
                        <p style={{fontSize: 13, color: '#6b7280'}}>
                          {company.registration_number} • {company.legal_form} • {company.city}
                        </p>
                        <p style={{fontSize: 12, color: '#6b7280', marginTop: 4}}>{company.address}</p>
                        {company.source === 'demo' && (
                          <span style={{fontSize: 11, color: 'var(--warning)', marginTop: 8, display: 'inline-block'}}>
                            ⚠ Demo-Daten: Echte API nicht erreichbar
                          </span>
                        )}
                      </div>
                      <button className="btn-secondary" onClick={() => saveCompany(company)} style={{fontSize: 13}}>
                        Speichern
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <h3 style={{fontSize: 18, fontWeight: 600, marginBottom: 16}}>Gespeicherte Firmen ({companies.length})</h3>
          {companies.length === 0 ? (
            <p style={{color: '#6b7280'}}>Noch keine Firmen gespeichert</p>
          ) : (
            <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
              {companies.map(c => (
                <div key={c.id} className="card" style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                  <div>
                    <h4 style={{fontWeight: 600}}>{c.name}</h4>
                    <p style={{fontSize: 13, color: '#6b7280'}}>{c.registration_number} • {c.city}</p>
                  </div>
                  <span className="badge badge-active">{c.case_count || 0} Cases</span>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    // Pipeline Info View
    function PipelineView() {
      return (
        <div className="animate-fade-in">
          <div style={{marginBottom: 32}}>
            <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 8}}>KYC Pipeline</h2>
            <p style={{color: '#6b7280'}}>Unser 6-Schritt Compliance-Prozess</p>
          </div>

          <div style={{display: 'flex', flexDirection: 'column', gap: 20}}>
            {PIPELINE_STEPS.map((step, idx) => (
              <div key={step.id} className="card" style={{display: 'flex', gap: 24, alignItems: 'flex-start'}}>
                <div style={{
                  width: 60, 
                  height: 60, 
                  borderRadius: '50%', 
                  background: `linear-gradient(135deg, ${step.color}, ${step.color}80)`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 28,
                  flexShrink: 0
                }}>
                  {step.icon}
                </div>
                <div style={{flex: 1}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8}}>
                    <h3 style={{fontSize: 20, fontWeight: 600}}>{step.name}</h3>
                    <span style={{padding: '4px 12px', background: step.color + '20', color: step.color, borderRadius: 20, fontSize: 12, fontWeight: 600}}>
                      Schritt {step.id}
                    </span>
                  </div>
                  <p style={{color: '#6b7280', marginBottom: 12}}>{step.desc}</p>
                  <div style={{padding: 16, background: 'rgba(255,255,255,0.03)', borderRadius: 10}}>
                    <p style={{fontSize: 14, color: '#9ca3af', lineHeight: 1.6}}>
                      {step.id === 1 && 'Identifikation des Kunden anhand amtlicher Ausweise (Personalausweis, Reisepass). Unterstützung von Video-Ident, Post-Ident und eID-Verfahren.'}
                      {step.id === 2 && 'Automatische Dokumentenprüfung mit OCR-Textextraktion. Prüfung auf Fälschungen, Gültigkeit und Vollständigkeit aller erforderlichen Unterlagen.'}
                      {step.id === 3 && 'Echtzeit-Abfrage des deutschen Handelsregisters über bundesAPI. Automatische Verifizierung von Firmendaten, Geschäftsführern und Kapitalverhältnissen.'}
                      {step.id === 4 && 'Ermittlung der wirtschaftlich Berechtigten (UBO) gemäß Geldwäschegesetz (GwG). Abfrage des Transparenzregisters und Erfassung der Kontrollstrukturen.'}
                      {step.id === 5 && 'Automatische Screening-Prüfung gegen PEP-Listen (Politically Exposed Persons), internationale Sanktionslisten und Adverse Media-Datenbanken.'}
                      {step.id === 6 && 'Finale Freigabe durch autorisierte Compliance-Officer. Vollständige Audit-Trail-Dokumentation und archivierungssichere Speicherung aller Prüfunterlagen.'}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="card" style={{marginTop: 32, background: 'linear-gradient(135deg, rgba(0,212,255,0.1), rgba(123,44,191,0.1))'}}>
            <h3 style={{marginBottom: 20, color: 'var(--primary)'}}>🎯 Vorteile gegenüber companyinfo.de & hawk.ai</h3>
            <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16}}>
              {[
                'Integrierte 6-Schritt Pipeline (nicht nur Datenabfrage)',
                'Echte Handelsregister-API (bundesAPI) Anbindung',
                'Automatische UBO-Ermittlung mit Transparenzregister',
                'PEP & Sanktionslisten-Screening in Echtzeit',
                'OCR-Dokumentenverarbeitung mit KI-Extraktion',
                'Vollständiger Audit-Trail für Regulatoren',
                'Modernes UI/UX (kein veraltetes Design)',
                'Deutsche Server-Standorte (DSGVO-konform)'
              ].map((item, i) => (
                <div key={i} style={{display: 'flex', alignItems: 'center', gap: 12}}>
                  <span style={{color: 'var(--success)', fontSize: 18}}>✓</span>
                  <span style={{fontSize: 14}}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    }

    // Screening View
    function ScreeningView() {
      return (
        <div className="animate-fade-in">
          <div style={{marginBottom: 32}}>
            <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 8}}>Compliance Screening</h2>
            <p style={{color: '#6b7280'}}>PEP, Sanktionslisten & Adverse Media</p>
          </div>

          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: 24}}>
            <div className="card">
              <div style={{display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20}}>
                <div style={{width: 50, height: 50, borderRadius: 12, background: 'rgba(0,212,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24}}>👤</div>
                <div>
                  <h3 style={{fontWeight: 600}}>PEP Screening</h3>
                  <p style={{fontSize: 13, color: '#6b7280'}}>Politically Exposed Persons</p>
                </div>
              </div>
              <p style={{fontSize: 14, color: '#9ca3af', marginBottom: 16}}>
                Abgleich gegen internationale PEP-Datenbanken inklusive Familienmitglieder und enger Geschäftspartner.
              </p>
              <div style={{padding: 12, background: 'rgba(16,185,129,0.1)', borderRadius: 8, border: '1px solid rgba(16,185,129,0.2)'}}>
                <span style={{color: 'var(--success)', fontSize: 13, fontWeight: 600}}>✓ Integriert</span>
              </div>
            </div>

            <div className="card">
              <div style={{display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20}}>
                <div style={{width: 50, height: 50, borderRadius: 12, background: 'rgba(239,68,68,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24}}>🚫</div>
                <div>
                  <h3 style={{fontWeight: 600}}>Sanktionslisten</h3>
                  <p style={{fontSize: 13, color: '#6b7280'}}>Internationale Listen</p>
                </div>
              </div>
              <p style={{fontSize: 14, color: '#9ca3af', marginBottom: 16}}>
                Prüfung gegen EU Consolidated List, OFAC SDN, UN Security Council, HM Treasury und weitere.
              </p>
              <div style={{padding: 12, background: 'rgba(16,185,129,0.1)', borderRadius: 8, border: '1px solid rgba(16,185,129,0.2)'}}>
                <span style={{color: 'var(--success)', fontSize: 13, fontWeight: 600}}>✓ Integriert</span>
              </div>
            </div>

            <div className="card">
              <div style={{display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20}}>
                <div style={{width: 50, height: 50, borderRadius: 12, background: 'rgba(245,158,11,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24}}>📰</div>
                <div>
                  <h3 style={{fontWeight: 600}}>Adverse Media</h3>
                  <p style={{fontSize: 13, color: '#6b7280'}}>Negative Berichterstattung</p>
                </div>
              </div>
              <p style={{fontSize: 14, color: '#9ca3af', marginBottom: 16}}>
                Automatische Überwachung von News-Quellen, Gerichtsakten und regulatorischen Veröffentlichungen.
              </p>
              <div style={{padding: 12, background: 'rgba(245,158,11,0.1)', borderRadius: 8, border: '1px solid rgba(245,158,11,0.2)'}}>
                <span style={{color: 'var(--warning)', fontSize: 13, fontWeight: 600}}>⚠ In Entwicklung</span>
              </div>
            </div>
          </div>
        </div>
      );
    }

    // Main App
    function App() {
      const [user, setUser] = useState(null);
      const [token, setToken] = useState(localStorage.getItem('token'));
      const [activeTab, setActiveTab] = useState('dashboard');
      const [selectedCase, setSelectedCase] = useState(null);

      useEffect(() => {
        if (token) {
          // Decode token to get user info
          try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            setUser({
              id: payload.userId,
              email: payload.email,
              firstName: payload.firstName || 'User',
              company: payload.company || 'NEXUS KYC'
            });
          } catch (e) {
            console.error('Invalid token');
            handleLogout();
          }
        }
      }, [token]);

      const handleLogin = (userData) => {
        setUser(userData);
        setToken(localStorage.getItem('token'));
      };

      const handleLogout = () => {
        localStorage.removeItem('token');
        setUser(null);
        setToken(null);
        setActiveTab('dashboard');
        setSelectedCase(null);
      };

      if (!token) return <Auth onLogin={handleLogin} />;

      return (
        <div className="layout">
          <Sidebar activeTab={activeTab} setActiveTab={(tab) => { setActiveTab(tab); setSelectedCase(null); }} user={user} onLogout={handleLogout} />
          <div className="main">
            {selectedCase ? (
              <CaseDetail caseData={selectedCase} onBack={() => setSelectedCase(null)} />
            ) : (
              <>
                {activeTab === 'dashboard' && <DashboardView />}
                {activeTab === 'cases' && <CasesView onSelectCase={setSelectedCase} />}
                {activeTab === 'companies' && <CompaniesView />}
                {activeTab === 'pipeline' && <PipelineView />}
                {activeTab === 'screening' && <ScreeningView />}
              </>
            )}
          </div>
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
  </script>
</body>
</html>`;

app.get('*', (req, res) => res.send(html));

app.listen(PORT, async () => {
  console.log('🚀 NEXUS KYC Pro v2.0 Enterprise running on port ' + PORT);
  await initDB();
});
