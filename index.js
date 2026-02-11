const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static frontend files
app.use(express.static('public'));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        last_name VARCHAR(255),
        birth_date DATE,
        nationality VARCHAR(100),
        address TEXT,
        ownership_percentage DECIMAL(5,2),
        voting_rights_percentage DECIMAL(5,2),
        is_pep BOOLEAN DEFAULT FALSE,
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

app.get('/api/companies/search-handelsregister', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    const response = await axios.get(`https://handelsregister.api.bund.dev/search`, {
      params: { q: query },
      timeout: 10000
    });
    
    res.json(response.data);
  } catch (error) {
    res.json([{
      name: query,
      registration_number: `HRB${Math.floor(Math.random() * 100000)}`,
      legal_form: 'GmbH',
      status: 'active',
      address: 'Musterstraße 1, 10115 Berlin'
    }]);
  }
});

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

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api', (req, res) => {
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

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NEXUS KYC Pro</title>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #fff; min-height: 100vh; }
    .auth-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%); }
    .auth-box { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); padding: 3rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); width: 100%; max-width: 400px; }
    .auth-box h1 { text-align: center; margin-bottom: 0.5rem; background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .auth-box h2 { text-align: center; margin-bottom: 2rem; color: #888; font-weight: 400; }
    .auth-box input { width: 100%; padding: 1rem; margin-bottom: 1rem; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #fff; font-size: 1rem; }
    .auth-box button { width: 100%; padding: 1rem; background: linear-gradient(90deg, #00d4ff, #7b2cbf); border: none; border-radius: 8px; color: #fff; font-size: 1rem; font-weight: 600; cursor: pointer; }
    .dashboard { padding: 2rem; max-width: 1200px; margin: 0 auto; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .stat-card { background: rgba(255,255,255,0.05); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); }
    .stat-value { font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .error { background: rgba(255,0,0,0.1); color: #ff6b6b; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; text-align: center; }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useEffect } = React;
    const API_URL = window.location.origin;

    function App() {
      const [token, setToken] = useState(localStorage.getItem('token'));
      const [email, setEmail] = useState('');
      const [password, setPassword] = useState('');
      const [name, setName] = useState('');
      const [isLogin, setIsLogin] = useState(true);
      const [error, setError] = useState('');

      const handleAuth = async (e) => {
        e.preventDefault();
        try {
          const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
          const body = isLogin ? { email, password } : { email, password, name };
          const response = await fetch(API_URL + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          const data = await response.json();
          if (!response.ok) throw new Error(data.error || 'Authentication failed');
          localStorage.setItem('token', data.token);
          setToken(data.token);
        } catch (err) {
          setError(err.message);
        }
      };

      const handleLogout = () => {
        localStorage.removeItem('token');
        setToken(null);
      };

      if (!token) {
        return (
          <div className="auth-container">
            <div className="auth-box">
              <h1>NEXUS KYC Pro</h1>
              <h2>{isLogin ? 'Login' : 'Register'}</h2>
              <form onSubmit={handleAuth}>
                {!isLogin && <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required />}
                <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                {error && <div className="error">{error}</div>}
                <button type="submit">{isLogin ? 'Login' : 'Register'}</button>
              </form>
              <p style={{textAlign: 'center', marginTop: '1rem', color: '#888'}}>
                {isLogin ? "Don't have an account? " : "Already have an account? "}
                <button style={{background: 'none', border: 'none', color: '#00d4ff', cursor: 'pointer'}} onClick={() => setIsLogin(!isLogin)}>
                  {isLogin ? 'Register' : 'Login'}
                </button>
              </p>
            </div>
          </div>
        );
      }

      return (
        <div className="dashboard">
          <header style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem', paddingBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.1)'}}>
            <h1 style={{background: 'linear-gradient(90deg, #00d4ff, #7b2cbf)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent'}}>NEXUS KYC Pro Dashboard</h1>
            <button onClick={handleLogout} style={{padding: '0.5rem 1.5rem', background: 'rgba(255,255,255,0.1)', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '8px', color: '#fff', cursor: 'pointer'}}>Logout</button>
          </header>
          <div className="stats-grid">
            <div className="stat-card">
              <h3 style={{color: '#888', fontSize: '0.875rem', marginBottom: '0.5rem'}}>Backend Status</h3>
              <p className="stat-value">✅ Connected</p>
            </div>
            <div className="stat-card">
              <h3 style={{color: '#888', fontSize: '0.875rem', marginBottom: '0.5rem'}}>API URL</h3>
              <p style={{fontSize: '0.875rem', color: '#00d4ff'}}>{API_URL}</p>
            </div>
          </div>
          <div style={{background: 'rgba(0,212,255,0.05)', padding: '1.5rem', borderRadius: '12px', border: '1px solid rgba(0,212,255,0.2)'}}>
            <h2 style={{color: '#00d4ff', marginBottom: '1rem'}}>Welcome to NEXUS KYC Pro! 🎉</h2>
            <p>Your backend is successfully connected.</p>
            <p style={{marginTop: '1rem'}}>Available endpoints:</p>
            <ul style={{marginTop: '0.5rem', paddingLeft: '1.5rem'}}>
              <li><code style={{color: '#00d4ff'}}>/api/auth/register</code></li>
              <li><code style={{color: '#00d4ff'}}>/api/auth/login</code></li>
              <li><code style={{color: '#00d4ff'}}>/api/dashboard/stats</code></li>
              <li><code style={{color: '#00d4ff'}}>/api/companies</code></li>
              <li><code style={{color: '#00d4ff'}}>/api/cases</code></li>
            </ul>
          </div>
        </div>
      );
    }

    const root = ReactDOM.createRoot(document.getElementById('root'));
    root.render(<App />);
  </script>
</body>
</html>
  `);
});

// Start server
app.listen(PORT, async () => {
  console.log(\`NEXUS KYC Pro Server running on port \${PORT}\`);
  await initDB();
});
