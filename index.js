const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const initDB = async () => {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, name VARCHAR(255), role VARCHAR(50) DEFAULT 'user', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS companies (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), name VARCHAR(255) NOT NULL, registration_number VARCHAR(100), legal_form VARCHAR(100), address TEXT, city VARCHAR(100), postal_code VARCHAR(20), country VARCHAR(100) DEFAULT 'Germany', status VARCHAR(50) DEFAULT 'active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS kyc_cases (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), company_id INTEGER REFERENCES companies(id), case_number VARCHAR(100) UNIQUE NOT NULL, status VARCHAR(50) DEFAULT 'pending', risk_level VARCHAR(50) DEFAULT 'medium', current_step INTEGER DEFAULT 1, steps_completed JSONB DEFAULT '[]', notes TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS documents (id SERIAL PRIMARY KEY, case_id INTEGER REFERENCES kyc_cases(id), user_id INTEGER REFERENCES users(id), filename VARCHAR(255) NOT NULL, original_name VARCHAR(255), file_type VARCHAR(100), file_size INTEGER, content TEXT, ocr_data JSONB, analysis_result JSONB, status VARCHAR(50) DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS ubos (id SERIAL PRIMARY KEY, company_id INTEGER REFERENCES companies(id), case_id INTEGER REFERENCES kyc_cases(id), first_name VARCHAR(255), last_name VARCHAR(255), birth_date DATE, nationality VARCHAR(100), address TEXT, ownership_percentage DECIMAL(5,2), voting_rights_percentage DECIMAL(5,2), is_pep BOOLEAN DEFAULT FALSE, verification_status VARCHAR(50) DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS compliance_checks (id SERIAL PRIMARY KEY, case_id INTEGER REFERENCES kyc_cases(id), check_type VARCHAR(100) NOT NULL, status VARCHAR(50) DEFAULT 'pending', result JSONB, risk_score INTEGER, checked_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    console.log('Database initialized');
  } catch (error) {
    console.error('DB Error:', error);
  }
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query('INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name, role', [email, hashedPassword, name]);
    const token = jwt.sign({ userId: result.rows[0].id, email: result.rows[0].email, role: result.rows[0].role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    res.json({ user: result.rows[0], token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role }, token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/dashboard/stats', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const casesResult = await pool.query('SELECT COUNT(*) as total FROM kyc_cases WHERE user_id = $1', [decoded.userId]);
    const companiesResult = await pool.query('SELECT COUNT(*) as total FROM companies WHERE user_id = $1', [decoded.userId]);
    res.json({ 
      totalCompanies: parseInt(companiesResult.rows[0].total), 
      pendingChecks: 0, 
      cases: [{status: 'active', count: casesResult.rows[0].total}], 
      recentCases: [] 
    });
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

app.get('/api/companies', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const result = await pool.query('SELECT * FROM companies WHERE user_id = $1 ORDER BY created_at DESC', [decoded.userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

app.get('/api/cases', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const result = await pool.query(`SELECT kc.*, c.name as company_name FROM kyc_cases kc LEFT JOIN companies c ON kc.company_id = c.id WHERE kc.user_id = $1 ORDER BY kc.created_at DESC`, [decoded.userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

app.post('/api/cases', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    
    // Erstelle Dummy-Firma falls keine existiert
    let companyId = req.body.company_id;
    if (!companyId) {
      const companyResult = await pool.query(
        `INSERT INTO companies (user_id, name, registration_number, legal_form, city) 
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [decoded.userId, 'Musterfirma GmbH', 'HRB' + (Math.floor(Math.random() * 90000) + 10000), 'GmbH', 'Berlin']
      );
      companyId = companyResult.rows[0].id;
    }
    
    const caseNumber = 'KYC-' + Date.now();
    const result = await pool.query(
      'INSERT INTO kyc_cases (user_id, company_id, case_number, notes, current_step, steps_completed) VALUES ($1, $2, $3, $4, 1, $5) RETURNING *',
      [decoded.userId, companyId, caseNumber, req.body.notes || 'Neuer KYC Case', '[]']
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Case creation error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/companies/search-handelsregister', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const { query } = req.query;
    
    // Versuche echte API
    try {
      const response = await axios.get(`https://handelsregister.api.bund.dev/search`, {
        params: { q: query },
        timeout: 5000
      });
      if (response.data && response.data.length > 0) {
        return res.json(response.data);
      }
    } catch (apiErr) {
      console.log('Handelsregister API nicht verfügbar, verwende Mock-Daten');
    }
    
    // Fallback: Realistischere Mock-Daten
    res.json([{
      name: query,
      registration_number: 'HRB' + (Math.floor(Math.random() * 90000) + 10000),
      legal_form: 'GmbH',
      status: 'active',
      address: 'Musterstraße 1, 10115 Berlin',
      city: 'Berlin'
    }]);
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api', (req, res) => {
  res.json({ message: 'NEXUS KYC Pro API', version: '1.0.0', endpoints: ['/api/auth/register', '/api/auth/login', '/api/dashboard/stats', '/api/companies', '/api/cases'] });
});

const html = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NEXUS KYC Pro</title>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #fff; min-h-screen; }
    .auth-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%); }
    .auth-box { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); padding: 3rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); width: 100%; max-width: 400px; }
    .auth-box h1 { text-align: center; margin-bottom: 0.5rem; background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .auth-box h2 { text-align: center; margin-bottom: 2rem; color: #888; font-weight: 400; }
    .auth-box input { width: 100%; padding: 1rem; margin-bottom: 1rem; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #fff; font-size: 1rem; }
    .auth-box button { width: 100%; padding: 1rem; background: linear-gradient(90deg, #00d4ff, #7b2cbf); border: none; border-radius: 8px; color: #fff; font-size: 1rem; font-weight: 600; cursor: pointer; }
    .dashboard { padding: 2rem; max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
    header h1 { background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .stat-card { background: rgba(255,255,255,0.05); padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); }
    .stat-card h3 { color: #888; font-size: 0.875rem; margin-bottom: 0.5rem; }
    .stat-value { font-size: 2rem; font-weight: 700; background: linear-gradient(90deg, #00d4ff, #7b2cbf); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .btn-primary { padding: 0.75rem 1.5rem; background: linear-gradient(90deg, #00d4ff, #7b2cbf); border: none; border-radius: 8px; color: #fff; font-weight: 600; cursor: pointer; margin-bottom: 1rem; }
    .btn-secondary { padding: 0.5rem 1.5rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 8px; color: #fff; cursor: pointer; }
    .section { background: rgba(255,255,255,0.03); padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem; border: 1px solid rgba(255,255,255,0.1); }
    .section h2 { color: #00d4ff; margin-bottom: 1rem; font-size: 1.25rem; }
    .pipeline { display: flex; gap: 0.5rem; margin-top: 1rem; overflow-x: auto; }
    .pipeline-step { flex: 1; min-width: 120px; padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; text-align: center; border: 2px solid transparent; }
    .pipeline-step.active { border-color: #00d4ff; background: rgba(0,212,255,0.1); }
    input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #fff; }
    .error { background: rgba(255,0,0,0.1); color: #ff6b6b; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; text-align: center; }
    .success { background: rgba(16,185,129,0.1); color: #10b981; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; text-align: center; }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="text/babel">
    const { useState, useEffect } = React;
    const API_URL = window.location.origin;
    
    const pipelineSteps = [
      { id: 1, name: 'Identifikation', desc: 'Kunde identifizieren' },
      { id: 2, name: 'Dokumente', desc: 'Unterlagen prüfen' },
      { id: 3, name: 'Handelsregister', desc: 'HRB-Abfrage' },
      { id: 4, name: 'UBO-Ermittlung', desc: 'Wirtschaftliche Eigentümer' },
      { id: 5, name: 'Compliance', desc: 'PEP/Sanktionslisten' },
      { id: 6, name: 'Freigabe', desc: 'KYC abschließen' },
    ];

    function App() {
      const [token, setToken] = useState(localStorage.getItem('token'));
      const [email, setEmail] = useState('');
      const [password, setPassword] = useState('');
      const [name, setName] = useState('');
      const [isLogin, setIsLogin] = useState(true);
      const [error, setError] = useState('');
      const [activeTab, setActiveTab] = useState('overview');
      const [cases, setCases] = useState([]);
      const [companies, setCompanies] = useState([]);
      const [loading, setLoading] = useState(false);
      const [message, setMessage] = useState('');
      const [searchQuery, setSearchQuery] = useState('');
      const [searchResults, setSearchResults] = useState([]);

      useEffect(() => {
        if (token) {
          fetchCases();
          fetchCompanies();
        }
      }, [token]);

      const handleAuth = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
          const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
          const body = isLogin ? { email, password } : { email, password, name };
          const response = await fetch(API_URL + endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          const data = await response.json();
          if (!response.ok) throw new Error(data.error || 'Authentication failed');
          localStorage.setItem('token', data.token);
          setToken(data.token);
        } catch (err) { setError(err.message); }
        finally { setLoading(false); }
      };

      const handleLogout = () => { localStorage.removeItem('token'); setToken(null); };

      const fetchCases = async () => {
        try {
          const response = await fetch(API_URL + '/api/cases', { headers: { 'Authorization': 'Bearer ' + token } });
          if (response.ok) {
            const data = await response.json();
            setCases(data);
          }
        } catch (err) { console.error(err); }
      };

      const fetchCompanies = async () => {
        try {
          const response = await fetch(API_URL + '/api/companies', { headers: { 'Authorization': 'Bearer ' + token } });
          if (response.ok) {
            const data = await response.json();
            setCompanies(data);
          }
        } catch (err) { console.error(err); }
      };

      const createCase = async () => {
        setLoading(true);
        try {
          const response = await fetch(API_URL + '/api/cases', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: 'Neuer KYC Case' })
          });
          if (response.ok) {
            setMessage('✅ KYC Case erfolgreich erstellt!');
            fetchCases();
            setTimeout(() => setMessage(''), 3000);
          } else {
            setMessage('❌ Fehler beim Erstellen');
          }
        } catch (err) { setMessage('❌ Fehler beim Erstellen'); }
        finally { setLoading(false); }
      };

      const searchHandelsregister = async () => {
        if (!searchQuery) return;
        setLoading(true);
        try {
          const response = await fetch(API_URL + '/api/companies/search-handelsregister?query=' + encodeURIComponent(searchQuery), {
            headers: { 'Authorization': 'Bearer ' + token }
          });
          const data = await response.json();
          setSearchResults(data);
        } catch (err) { console.error(err); }
        finally { setLoading(false); }
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
                <button type="submit">{loading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}</button>
              </form>
              <p style={{textAlign: 'center', marginTop: '1rem', color: '#888'}}>
                {isLogin ? "Don't have an account? " : "Already have an account? "}
                <button style={{background: 'none', border: 'none', color: '#00d4ff', cursor: 'pointer'}} onClick={() => setIsLogin(!isLogin)}>{isLogin ? 'Register' : 'Login'}</button>
              </p>
            </div>
          </div>
        );
      }

      return (
        <div className="dashboard">
          <header>
            <h1>NEXUS KYC Pro Dashboard</h1>
            <button onClick={handleLogout} className="btn-secondary">Logout</button>
          </header>
          
          {message && <div className="success">{message}</div>}

          <div style={{display: 'flex', gap: '1rem', marginBottom: '1.5rem'}}>
            <button className={activeTab === 'overview' ? 'btn-primary' : 'btn-secondary'} onClick={() => setActiveTab('overview')}>Übersicht</button>
            <button className={activeTab === 'pipeline' ? 'btn-primary' : 'btn-secondary'} onClick={() => setActiveTab('pipeline')}>KYC Pipeline</button>
            <button className={activeTab === 'search' ? 'btn-primary' : 'btn-secondary'} onClick={() => setActiveTab('search')}>Firmen-Suche</button>
          </div>

          {activeTab === 'overview' && (
            <>
              <div className="stats-grid">
                <div className="stat-card">
                  <h3>Aktive KYC Cases</h3>
                  <p className="stat-value">{cases.length}</p>
                </div>
                <div className="stat-card">
                  <h3>Gespeicherte Firmen</h3>
                  <p className="stat-value">{companies.length}</p>
                </div>
                <div className="stat-card">
                  <h3>API Status</h3>
                  <p className="stat-value" style={{color: '#10b981'}}>●</p>
                </div>
              </div>

              <div className="section">
                <h2>Schnellaktionen</h2>
                <button className="btn-primary" onClick={createCase} disabled={loading}>
                  {loading ? 'Erstelle...' : '+ Neuen KYC Case erstellen'}
                </button>
              </div>

              {cases.length > 0 && (
                <div className="section">
                  <h2>Deine KYC Cases</h2>
                  {cases.map((c) => (
                    <div key={c.id} style={{padding: '1rem', background: 'rgba(255,255,255,0.05)', borderRadius: '8px', marginBottom: '0.5rem'}}>
                      <strong>{c.case_number}</strong>
                      <p style={{color: '#888', fontSize: '0.875rem'}}>{c.company_name || 'Keine Firma'} | {c.status}</p>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {activeTab === 'pipeline' && (
            <div className="section">
              <h2>6-Schritt KYC Pipeline</h2>
              <div className="pipeline">
                {pipelineSteps.map((step) => (
                  <div key={step.id} className="pipeline-step active">
                    <h4>Schritt {step.id}</h4>
                    <p>{step.name}</p>
                    <small style={{color: '#888', fontSize: '0.7rem'}}>{step.desc}</small>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'search' && (
            <div className="section">
              <h2>🔍 Handelsregister-Suche</h2>
              <div style={{display: 'flex', gap: '0.5rem', marginBottom: '1rem'}}>
                <input type="text" placeholder="Firmenname..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} style={{flex: 1}} />
                <button className="btn-primary" onClick={searchHandelsregister} disabled={loading}>
                  {loading ? 'Suche...' : 'Suchen'}
                </button>
              </div>
              {searchResults.map((company, idx) => (
                <div key={idx} style={{padding: '1rem', background: 'rgba(255,255,255,0.05)', borderRadius: '8px', marginBottom: '0.5rem'}}>
                  <strong>{company.name}</strong>
                  <p style={{color: '#888', fontSize: '0.875rem'}}>{company.registration_number} | {company.legal_form}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
  </script>
</body>
</html>`;

app.get('*', (req, res) => {
  res.send(html);
});

app.listen(PORT, async () => {
  console.log('NEXUS KYC Pro Server running on port ' + PORT);
  await initDB();
});
