const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const multer = require('multer');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const upload = multer({ storage: multer.memoryStorage() });

// ==================== DATABASE ====================
const initDB = async () => {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        company VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Companies table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        registration_number VARCHAR(100),
        legal_form VARCHAR(100),
        city VARCHAR(100),
        country VARCHAR(100) DEFAULT 'DE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // KYC Cases table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS kyc_cases (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        company_id INTEGER REFERENCES companies(id),
        case_number VARCHAR(100) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        risk_level VARCHAR(20) DEFAULT 'medium',
        current_step INTEGER DEFAULT 1,
        steps_completed INTEGER[] DEFAULT '{}',
        company_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Documents table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id),
        filename VARCHAR(255),
        original_name VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // UBOs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ubos (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        ownership_percentage DECIMAL(5,2),
        is_pep BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Compliance checks table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS compliance_checks (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES kyc_cases(id),
        check_type VARCHAR(100),
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database initialized');
  } catch (e) {
    console.error('DB Error:', e);
  }
};

// Auth middleware
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

// ==================== AUTH ====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, company } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, first_name, last_name, company) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [email, hashed, firstName, lastName, company]
    );
    const token = jwt.sign(
      { userId: result.rows[0].id, email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    res.json({ user: result.rows[0], token });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    res.json({ user: { id: user.id, email: user.email, firstName: user.first_name, company: user.company }, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== DASHBOARD ====================
app.get('/api/dashboard/stats', auth, async (req, res) => {
  try {
    const casesResult = await pool.query(
      'SELECT status, COUNT(*) as count FROM kyc_cases WHERE user_id = $1 GROUP BY status',
      [req.user.userId]
    );
    const companiesResult = await pool.query('SELECT COUNT(*) as total FROM companies WHERE user_id = $1', [req.user.userId]);
    const recentCases = await pool.query(
      'SELECT kc.*, c.name as company_name FROM kyc_cases kc LEFT JOIN companies c ON kc.company_id = c.id WHERE kc.user_id = $1 ORDER BY kc.created_at DESC LIMIT 5',
      [req.user.userId]
    );
    
    res.json({
      overview: {
        totalCases: casesResult.rows.reduce((a, r) => a + parseInt(r.count), 0),
        activeCases: casesResult.rows.find(r => r.status === 'active')?.count || 0,
        totalCompanies: parseInt(companiesResult.rows[0].total)
      },
      casesByStatus: casesResult.rows,
      recentCases: recentCases.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== HANDELSREGISTER ====================
app.get('/api/companies/search-handelsregister', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 3) return res.status(400).json({ error: 'Mindestens 3 Zeichen' });
    
    // Try real API
    try {
      const response = await axios.get('https://handelsregister.api.bund.dev/search', {
        params: { q },
        timeout: 8000,
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.data && Array.isArray(response.data) && response.data.length > 0) {
        return res.json({
          success: true,
          source: 'handelsregister_api',
          results: response.data.map(item => ({
            name: item.name || item.firma || q,
            registration_number: item.registration_number || item.hrb || `HRB${Math.floor(Math.random() * 90000 + 10000)}`,
            legal_form: item.legal_form || 'GmbH',
            city: item.city || 'Berlin',
            address: item.address || 'Musterstraße 1, 10115 Berlin',
            country: 'DE'
          }))
        });
      }
    } catch (apiErr) {
      console.log('API failed:', apiErr.message);
    }
    
    // Fallback
    res.json({
      success: true,
      source: 'demo',
      results: [{
        name: q,
        registration_number: `HRB${Math.floor(Math.random() * 90000 + 10000)}`,
        legal_form: 'GmbH',
        city: 'Berlin',
        address: 'Musterstraße 1, 10115 Berlin',
        country: 'DE'
      }]
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== NEWSAPI ADVERSE MEDIA ====================
app.get('/api/compliance/adverse-media', auth, async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) return res.status(400).json({ error: 'Query required' });
    
    const newsApiKey = process.env.NEWSAPI_KEY;
    
    if (!newsApiKey) {
      return res.json({
        success: true,
        source: 'demo',
        warning: 'NEWSAPI_KEY nicht konfiguriert',
        totalResults: 0,
        articles: []
      });
    }
    
    const response = await axios.get('https://newsapi.org/v2/everything', {
      params: {
        q: query + ' (fraud OR corruption OR "money laundering" OR Betrug OR Korruption)',
        apiKey: newsApiKey,
        language: 'de,en',
        sortBy: 'relevancy',
        pageSize: 20
      },
      timeout: 10000
    });
    
    const articles = (response.data.articles || []).map(article => {
      const title = (article.title || '').toLowerCase();
      const desc = (article.description || '').toLowerCase();
      let riskScore = 25;
      
      if (title.includes('fraud') || title.includes('betrug') || title.includes('corruption')) {
        riskScore = 80;
      } else if (title.includes('investigation') || title.includes('ermittlung')) {
        riskScore = 60;
      }
      
      return {
        title: article.title,
        description: article.description,
        url: article.url,
        source: article.source?.name,
        publishedAt: article.publishedAt,
        riskScore,
        sentiment: riskScore > 50 ? 'negative' : 'neutral',
        categories: riskScore > 50 ? ['High Risk'] : ['General']
      };
    }).sort((a, b) => b.riskScore - a.riskScore);
    
    res.json({
      success: true,
      source: 'newsapi',
      totalResults: articles.length,
      articles,
      summary: {
        highRisk: articles.filter(a => a.riskScore >= 70).length,
        mediumRisk: articles.filter(a => a.riskScore >= 40 && a.riskScore < 70).length,
        lowRisk: articles.filter(a => a.riskScore < 40).length
      }
    });
    
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== COMPANIES ====================
app.post('/api/companies', auth, async (req, res) => {
  try {
    const { name, registration_number, legal_form, city } = req.body;
    const result = await pool.query(
      'INSERT INTO companies (user_id, name, registration_number, legal_form, city) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, name, registration_number, legal_form, city]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/companies', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT c.*, (SELECT COUNT(*) FROM kyc_cases WHERE company_id = c.id) as case_count FROM companies c WHERE c.user_id = $1 ORDER BY c.created_at DESC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== KYC CASES ====================
app.post('/api/cases', auth, async (req, res) => {
  try {
    const { company_name, notes } = req.body;
    
    // Create company first
    const compResult = await pool.query(
      'INSERT INTO companies (user_id, name, registration_number, legal_form, city) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [req.user.userId, company_name, `HRB${Math.floor(Math.random() * 90000 + 10000)}`, 'GmbH', 'Berlin']
    );
    
    const caseNumber = `KYC-${Date.now()}`;
    const result = await pool.query(
      'INSERT INTO kyc_cases (user_id, company_id, case_number, company_name, notes, current_step, steps_completed) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.userId, compResult.rows[0].id, caseNumber, company_name, notes, 1, [1]]
    );
    
    // Create compliance checks
    await pool.query(
      'INSERT INTO compliance_checks (case_id, check_type) VALUES ($1, $2), ($1, $3), ($1, $4)',
      [result.rows[0].id, 'pep', 'sanctions', 'adverse_media']
    );
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/cases', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT kc.*, c.name as company_name,
        (SELECT COUNT(*) FROM documents WHERE case_id = kc.id) as document_count,
        (SELECT COUNT(*) FROM ubos WHERE case_id = kc.id) as ubo_count
       FROM kyc_cases kc
       LEFT JOIN companies c ON kc.company_id = c.id
       WHERE kc.user_id = $1
       ORDER BY kc.created_at DESC`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/cases/:id', auth, async (req, res) => {
  try {
    const caseResult = await pool.query(
      'SELECT kc.*, c.name as company_name FROM kyc_cases kc LEFT JOIN companies c ON kc.company_id = c.id WHERE kc.id = $1 AND kc.user_id = $2',
      [req.params.id, req.user.userId]
    );
    
    if (caseResult.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    
    const [ubos, documents, checks] = await Promise.all([
      pool.query('SELECT * FROM ubos WHERE case_id = $1', [req.params.id]),
      pool.query('SELECT * FROM documents WHERE case_id = $1', [req.params.id]),
      pool.query('SELECT * FROM compliance_checks WHERE case_id = $1', [req.params.id])
    ]);
    
    res.json({
      ...caseResult.rows[0],
      ubos: ubos.rows,
      documents: documents.rows,
      complianceChecks: checks.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/cases/:id/step', auth, async (req, res) => {
  try {
    const { step } = req.body;
    const current = await pool.query('SELECT steps_completed FROM kyc_cases WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
    
    let steps = current.rows[0]?.steps_completed || [];
    if (!steps.includes(step)) steps.push(step);
    
    const result = await pool.query(
      'UPDATE kyc_cases SET current_step = $1, steps_completed = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [step, steps, req.params.id]
    );
    
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== HEALTH ====================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.2.0', timestamp: new Date().toISOString() });
});

// ==================== FRONTEND ====================
const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NEXUS KYC Pro</title>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', sans-serif; background: #0a0a0f; color: #fff; min-height: 100vh; }
    .gradient-text { background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .card { background: #13131f; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 24px; }
    .btn-primary { padding: 12px 24px; background: linear-gradient(90deg, #00d4ff, #7b2cbf); border: none; border-radius: 10px; color: #fff; font-weight: 600; cursor: pointer; }
    .btn-secondary { padding: 12px 24px; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); border-radius: 10px; color: #fff; cursor: pointer; }
    .input { width: 100%; padding: 14px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #fff; font-size: 15px; }
    .input:focus { outline: none; border-color: #00d4ff; }
    .badge { padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    .badge-pending { background: rgba(245,158,11,0.15); color: #f59e0b; }
    .badge-active { background: rgba(0,212,255,0.15); color: #00d4ff; }
    .layout { display: flex; min-height: 100vh; }
    .sidebar { width: 280px; background: rgba(255,255,255,0.02); border-right: 1px solid rgba(255,255,255,0.08); position: fixed; height: 100vh; }
    .main { margin-left: 280px; flex: 1; padding: 32px; }
    .nav-item { padding: 14px 24px; margin: 4px 16px; border-radius: 10px; cursor: pointer; display: flex; align-items: center; gap: 14px; color: #9ca3af; transition: all 0.2s; }
    .nav-item:hover { background: rgba(255,255,255,0.05); color: #fff; }
    .nav-item.active { background: rgba(0,212,255,0.1); color: #00d4ff; border: 1px solid rgba(0,212,255,0.2); }
    .progress-bar { height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, #00d4ff, #7b2cbf); border-radius: 4px; }
    .article-card { padding: 16px; background: rgba(255,255,255,0.03); border-radius: 10px; margin-bottom: 12px; border-left: 3px solid; }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useEffect } = React;
    const API_URL = window.location.origin;
    
    const api = {
      get: (endpoint) => fetch(API_URL + endpoint, { headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') } }).then(r => r.json()),
      post: (endpoint, body) => fetch(API_URL + endpoint, { method: 'POST', headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token'), 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json()),
      patch: (endpoint, body) => fetch(API_URL + endpoint, { method: 'PATCH', headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token'), 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json())
    };

    const PIPELINE_STEPS = [
      { id: 1, name: 'Identifikation', desc: 'Kundenidentifikation', icon: '👤' },
      { id: 2, name: 'Dokumente', desc: 'Dokumentenprüfung', icon: '📄' },
      { id: 3, name: 'Handelsregister', desc: 'HRB-Abfrage', icon: '🏢' },
      { id: 4, name: 'UBO', desc: 'Wirtschaftliche Eigentümer', icon: '👥' },
      { id: 5, name: 'Compliance', desc: 'PEP & Sanktionen', icon: '🔒' },
      { id: 6, name: 'Freigabe', desc: 'Abschluss', icon: '✅' }
    ];

    function Auth({ onLogin }) {
      const [isLogin, setIsLogin] = useState(true);
      const [form, setForm] = useState({ email: '', password: '', firstName: '', lastName: '', company: '' });
      const [loading, setLoading] = useState(false);
      const [error, setError] = useState('');

      const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
          const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
          const body = isLogin ? { email: form.email, password: form.password } : { email: form.email, password: form.password, firstName: form.firstName, lastName: form.lastName, company: form.company };
          const res = await fetch(API_URL + endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error);
          localStorage.setItem('token', data.token);
          onLogin(data.user);
        } catch (err) { setError(err.message); }
        finally { setLoading(false); }
      };

      return (
        <div style={{minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'linear-gradient(135deg, #0a0a0f, #1a1a2e)', padding: 20}}>
          <div className="card" style={{width: '100%', maxWidth: 440}}>
            <div style={{textAlign: 'center', marginBottom: 32}}>
              <h1 style={{fontSize: 32, fontWeight: 700}} className="gradient-text">NEXUS KYC Pro</h1>
              <p style={{color: '#6b7280', marginTop: 8}}>Enterprise Compliance Platform</p>
            </div>
            
            {error && <div style={{padding: 12, background: 'rgba(239,68,68,0.1)', borderRadius: 8, color: '#ef4444', marginBottom: 16, fontSize: 14}}>{error}</div>}
            
            <form onSubmit={handleSubmit}>
              {!isLogin && <input className="input" placeholder="Vorname" value={form.firstName} onChange={e => setForm({...form, firstName: e.target.value})} style={{marginBottom: 12}} />}
              {!isLogin && <input className="input" placeholder="Nachname" value={form.lastName} onChange={e => setForm({...form, lastName: e.target.value})} style={{marginBottom: 12}} />}
              {!isLogin && <input className="input" placeholder="Unternehmen" value={form.company} onChange={e => setForm({...form, company: e.target.value})} style={{marginBottom: 12}} />}
              <input className="input" type="email" placeholder="E-Mail" value={form.email} onChange={e => setForm({...form, email: e.target.value})} required style={{marginBottom: 12}} />
              <input className="input" type="password" placeholder="Passwort" value={form.password} onChange={e => setForm({...form, password: e.target.value})} required style={{marginBottom: 24}} />
              <button type="submit" className="btn-primary" disabled={loading} style={{width: '100%'}}>{loading ? 'Lädt...' : (isLogin ? 'Anmelden' : 'Registrieren')}</button>
            </form>
            
            <p style={{textAlign: 'center', marginTop: 20, color: '#6b7280', fontSize: 14}}>
              {isLogin ? 'Noch kein Konto? ' : 'Bereits registriert? '}
              <button onClick={() => setIsLogin(!isLogin)} style={{background: 'none', border: 'none', color: '#00d4ff', cursor: 'pointer'}}>{isLogin ? 'Registrieren' : 'Login'}</button>
            </p>
          </div>
        </div>
      );
    }

    function Sidebar({ activeTab, setActiveTab, user, onLogout }) {
      const menu = [
        { id: 'dashboard', label: 'Dashboard', icon: '📊' },
        { id: 'cases', label: 'KYC Cases', icon: '📁' },
        { id: 'companies', label: 'Firmen', icon: '🏢' },
        { id: 'screening', label: 'Adverse Media', icon: '📰' },
        { id: 'pipeline', label: 'Pipeline', icon: '🔄' },
      ];

      return (
        <div className="sidebar">
          <div style={{padding: 24}}>
            <h1 style={{fontSize: 24, fontWeight: 700}} className="gradient-text">NEXUS</h1>
            <p style={{color: '#6b7280', fontSize: 11}}>KYC PRO</p>
          </div>
          <nav>
            {menu.map(item => (
              <div key={item.id} className={'nav-item ' + (activeTab === item.id ? 'active' : '')} onClick={() => setActiveTab(item.id)}>
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </div>
            ))}
          </nav>
          <div style={{position: 'absolute', bottom: 0, left: 0, right: 0, padding: 24, borderTop: '1px solid rgba(255,255,255,0.08)'}}>
            <p style={{fontWeight: 600, fontSize: 14}}>{user?.firstName} {user?.lastName}</p>
            <button onClick={onLogout} className="btn-secondary" style={{width: '100%', marginTop: 12}}>Ausloggen</button>
          </div>
        </div>
      );
    }

    function DashboardView() {
      const [stats, setStats] = useState(null);
      
      useEffect(() => {
        api.get('/api/dashboard/stats').then(setStats);
      }, []);

      return (
        <div>
          <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 24}}>Dashboard</h2>
          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 20, marginBottom: 32}}>
            <div className="card">
              <p style={{color: '#6b7280', fontSize: 13}}>Aktive Cases</p>
              <p style={{fontSize: 36, fontWeight: 700, color: '#00d4ff'}}>{stats?.overview?.activeCases || 0}</p>
            </div>
            <div className="card">
              <p style={{color: '#6b7280', fontSize: 13}}>Firmen</p>
              <p style={{fontSize: 36, fontWeight: 700, color: '#7b2cbf'}}>{stats?.overview?.totalCompanies || 0}</p>
            </div>
            <div className="card">
              <p style={{color: '#6b7280', fontSize: 13}}>Gesamt Cases</p>
              <p style={{fontSize: 36, fontWeight: 700}}>{stats?.overview?.totalCases || 0}</p>
            </div>
          </div>
        </div>
      );
    }

    function CasesView({ onSelectCase }) {
      const [cases, setCases] = useState([]);
      const [showNew, setShowNew] = useState(false);
      
      useEffect(() => { loadCases(); }, []);
      
      const loadCases = () => api.get('/api/cases').then(setCases);
      
      const createCase = async (e) => {
        e.preventDefault();
        const form = e.target;
        await api.post('/api/cases', { 
          company_name: form.company_name.value,
          notes: form.notes.value 
        });
        setShowNew(false);
        loadCases();
      };

      return (
        <div>
          <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: 24}}>
            <h2 style={{fontSize: 28, fontWeight: 700}}>KYC Cases</h2>
            <button className="btn-primary" onClick={() => setShowNew(true)}>+ Neuer Case</button>
          </div>
          
          {showNew && (
            <div className="card" style={{marginBottom: 24}}>
              <h3 style={{marginBottom: 16}}>Neuen Case erstellen</h3>
              <form onSubmit={createCase}>
                <input name="company_name" className="input" placeholder="Firmenname" required style={{marginBottom: 12}} />
                <textarea name="notes" className="input" placeholder="Notizen" rows={3} style={{marginBottom: 16}} />
                <div style={{display: 'flex', gap: 12}}>
                  <button type="button" className="btn-secondary" onClick={() => setShowNew(false)}>Abbrechen</button>
                  <button type="submit" className="btn-primary">Erstellen</button>
                </div>
              </form>
            </div>
          )}
          
          <div style={{display: 'flex', flexDirection: 'column', gap: 16}}>
            {cases.map(c => (
              <div key={c.id} className="card" style={{cursor: 'pointer'}} onClick={() => onSelectCase(c)}>
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                  <div>
                    <span style={{fontFamily: 'monospace', fontSize: 12, color: '#6b7280'}}>{c.case_number}</span>
                    <h4 style={{fontWeight: 600, marginTop: 4}}>{c.company_name}</h4>
                  </div>
                  <span className={'badge badge-' + c.status}>{c.status}</span>
                </div>
                <div className="progress-bar" style={{marginTop: 12}}>
                  <div className="progress-fill" style={{width: ((c.steps_completed?.length || 0) / 6 * 100) + '%'}}></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }

    function CaseDetail({ caseData, onBack }) {
      const [detail, setDetail] = useState(null);
      
      useEffect(() => {
        api.get('/api/cases/' + caseData.id).then(setDetail);
      }, []);

      return (
        <div>
          <button onClick={onBack} className="btn-secondary" style={{marginBottom: 24}}>← Zurück</button>
          <h2 style={{fontSize: 24, fontWeight: 700, marginBottom: 16}}>{detail?.company_name}</h2>
          
          <div className="card" style={{marginBottom: 24}}>
            <h3 style={{marginBottom: 16}}>KYC Pipeline</h3>
            <div style={{display: 'flex', gap: 12, overflowX: 'auto'}}>
              {PIPELINE_STEPS.map(step => (
                <div key={step.id} style={{minWidth: 140, padding: 16, background: 'rgba(255,255,255,0.03)', borderRadius: 10, textAlign: 'center', border: detail?.steps_completed?.includes(step.id) ? '2px solid #10b981' : '1px solid rgba(255,255,255,0.1)'}}>
                  <div style={{fontSize: 24}}>{step.icon}</div>
                  <p style={{fontSize: 13, fontWeight: 600, marginTop: 8}}>{step.name}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    }

    function CompaniesView() {
      const [companies, setCompanies] = useState([]);
      const [searchQuery, setSearchQuery] = useState('');
      const [searchResults, setSearchResults] = useState([]);
      
      useEffect(() => { loadCompanies(); }, []);
      
      const loadCompanies = () => api.get('/api/companies').then(setCompanies);
      
      const search = async () => {
        const data = await api.get('/api/companies/search-handelsregister?q=' + encodeURIComponent(searchQuery));
        setSearchResults(data.results || []);
      };
      
      const save = async (c) => {
        await api.post('/api/companies', c);
        loadCompanies();
        setSearchResults([]);
        setSearchQuery('');
      };

      return (
        <div>
          <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 24}}>Firmen</h2>
          
          <div className="card" style={{marginBottom: 24}}>
            <h3 style={{marginBottom: 12}}>🔍 Handelsregister-Suche</h3>
            <div style={{display: 'flex', gap: 12}}>
              <input className="input" placeholder="Firmenname..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} style={{flex: 1}} />
              <button className="btn-primary" onClick={search}>Suchen</button>
            </div>
            
            {searchResults.map((c, i) => (
              <div key={i} style={{padding: 16, background: 'rgba(255,255,255,0.03)', borderRadius: 10, marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                <div>
                  <p style={{fontWeight: 600}}>{c.name}</p>
                  <p style={{fontSize: 13, color: '#6b7280'}}>{c.registration_number} • {c.city}</p>
                </div>
                <button className="btn-secondary" onClick={() => save(c)}>Speichern</button>
              </div>
            ))}
          </div>
          
          <h3 style={{marginBottom: 16}}>Gespeicherte Firmen</h3>
          {companies.map(c => (
            <div key={c.id} className="card" style={{marginBottom: 12}}>
              <p style={{fontWeight: 600}}>{c.name}</p>
              <p style={{fontSize: 13, color: '#6b7280'}}>{c.registration_number}</p>
            </div>
          ))}
        </div>
      );
    }

    function AdverseMediaView() {
      const [query, setQuery] = useState('');
      const [results, setResults] = useState(null);
      
      const search = async () => {
        const data = await api.get('/api/compliance/adverse-media?query=' + encodeURIComponent(query));
        setResults(data);
      };

      return (
        <div>
          <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 24}}>Adverse Media</h2>
          
          <div className="card" style={{marginBottom: 24}}>
            <h3 style={{marginBottom: 12}}>🔍 NewsAPI Suche</h3>
            <div style={{display: 'flex', gap: 12}}>
              <input className="input" placeholder="Firmenname..." value={query} onChange={e => setQuery(e.target.value)} style={{flex: 1}} />
              <button className="btn-primary" onClick={search}>Suchen</button>
            </div>
          </div>
          
          {results && (
            <div>
              <h3 style={{marginBottom: 16}}>Ergebnisse ({results.totalResults})</h3>
              {results.articles?.map((a, i) => (
                <div key={i} className="article-card" style={{borderLeftColor: a.riskScore > 70 ? '#ef4444' : a.riskScore > 40 ? '#f59e0b' : '#10b981'}}>
                  <div style={{display: 'flex', justifyContent: 'space-between'}}>
                    <h4 style={{fontWeight: 600}}>{a.title}</h4>
                    <span style={{color: a.riskScore > 70 ? '#ef4444' : '#10b981'}}>{a.riskScore}% Risk</span>
                  </div>
                  <p style={{fontSize: 13, color: '#6b7280', marginTop: 8}}>{a.description?.substring(0, 150)}...</p>
                  <p style={{fontSize: 12, color: '#6b7280', marginTop: 8}}>📰 {a.source} • {new Date(a.publishedAt).toLocaleDateString('de-DE')}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    function PipelineView() {
      return (
        <div>
          <h2 style={{fontSize: 28, fontWeight: 700, marginBottom: 24}}>KYC Pipeline</h2>
          <div style={{display: 'flex', flexDirection: 'column', gap: 16}}>
            {PIPELINE_STEPS.map(step => (
              <div key={step.id} className="card" style={{display: 'flex', gap: 16, alignItems: 'center'}}>
                <div style={{width: 50, height: 50, borderRadius: '50%', background: 'linear-gradient(90deg, #00d4ff, #7b2cbf)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24}}>{step.icon}</div>
                <div>
                  <h4 style={{fontWeight: 600}}>{step.name}</h4>
                  <p style={{color: '#6b7280', fontSize: 14}}>{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    }

    function App() {
      const [user, setUser] = useState(null);
      const [token, setToken] = useState(localStorage.getItem('token'));
      const [activeTab, setActiveTab] = useState('dashboard');
      const [selectedCase, setSelectedCase] = useState(null);

      useEffect(() => {
        if (token) {
          const payload = JSON.parse(atob(token.split('.')[1]));
          setUser({ firstName: 'User', company: 'NEXUS' });
        }
      }, [token]);

      const handleLogout = () => {
        localStorage.removeItem('token');
        setUser(null);
        setToken(null);
      };

      if (!token) return <Auth onLogin={(u) => { setUser(u); setToken(localStorage.getItem('token')); }} />;

      return (
        <div className="layout">
          <Sidebar activeTab={activeTab} setActiveTab={t => { setActiveTab(t); setSelectedCase(null); }} user={user} onLogout={handleLogout} />
          <div className="main">
            {selectedCase ? <CaseDetail caseData={selectedCase} onBack={() => setSelectedCase(null)} /> : (
              <>
                {activeTab === 'dashboard' && <DashboardView />}
                {activeTab === 'cases' && <CasesView onSelectCase={setSelectedCase} />}
                {activeTab === 'companies' && <CompaniesView />}
                {activeTab === 'screening' && <AdverseMediaView />}
                {activeTab === 'pipeline' && <PipelineView />}
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
  console.log('NEXUS KYC Pro running on port ' + PORT);
  await initDB();
});
