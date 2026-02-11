import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = 'https://nexus-kyc-pro-production.up.railway.app';

interface DashboardStats {
  totalCompanies: number;
  pendingChecks: number;
  cases: { status: string; count: string }[];
  recentCases: any[];
}

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [isLogin, setIsLogin] = useState(true);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Login / Register
  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const body = isLogin 
        ? { email, password }
        : { email, password, name };

      const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      localStorage.setItem('token', data.token);
      setToken(data.token);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Fetch Dashboard Stats
  const fetchStats = async () => {
    if (!token) return;
    
    try {
      const response = await fetch(`${API_URL}/api/dashboard/stats`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  // Logout
  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setStats(null);
  };

  useEffect(() => {
    if (token) {
      fetchStats();
    }
  }, [token]);

  // Login/Register Screen
  if (!token) {
    return (
      <div className="auth-container">
        <div className="auth-box">
          <h1>NEXUS KYC Pro</h1>
          <h2>{isLogin ? 'Login' : 'Register'}</h2>
          
          <form onSubmit={handleAuth}>
            {!isLogin && (
              <input
                type="text"
                placeholder="Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            )}
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            
            {error && <div className="error">{error}</div>}
            
            <button type="submit" disabled={loading}>
              {loading ? 'Loading...' : (isLogin ? 'Login' : 'Register')}
            </button>
          </form>
          
          <p>
            {isLogin ? "Don't have an account? " : "Already have an account? "}
            <button className="link-btn" onClick={() => setIsLogin(!isLogin)}>
              {isLogin ? 'Register' : 'Login'}
            </button>
          </p>
        </div>
      </div>
    );
  }

  // Dashboard Screen
  return (
    <div className="dashboard">
      <header>
        <h1>NEXUS KYC Pro Dashboard</h1>
        <button onClick={handleLogout} className="logout-btn">Logout</button>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Companies</h3>
          <p className="stat-value">{stats?.totalCompanies || 0}</p>
        </div>
        <div className="stat-card">
          <h3>Pending Checks</h3>
          <p className="stat-value">{stats?.pendingChecks || 0}</p>
        </div>
        <div className="stat-card">
          <h3>Active Cases</h3>
          <p className="stat-value">
            {stats?.cases?.find(c => c.status === 'active')?.count || 0}
          </p>
        </div>
      </div>

      <div className="section">
        <h2>API Connected ✅</h2>
        <p>Your backend is live at: <code>{API_URL}</code></p>
        <p>All endpoints are working!</p>
      </div>

      <div className="endpoints">
        <h3>Available Endpoints:</h3>
        <ul>
          <li><code>POST /api/auth/register</code> - User registration</li>
          <li><code>POST /api/auth/login</code> - User login</li>
          <li><code>GET /api/dashboard/stats</code> - Dashboard statistics</li>
          <li><code>GET /api/companies</code> - List companies</li>
          <li><code>POST /api/cases</code> - Create KYC case</li>
          <li><code>POST /api/documents</code> - Upload documents</li>
          <li><code>POST /api/compliance/check</code> - Run compliance checks</li>
        </ul>
      </div>
    </div>
  );
}

export default App;
