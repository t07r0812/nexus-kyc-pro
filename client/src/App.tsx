import { useState, useEffect } from 'react'
import axios from 'axios'

const API_URL = 'https://nexus-kyc-pro-production.up.railway.app'

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' }
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

interface User {
  id: number
  email: string
  name: string
}

function Auth({ onLogin }: { onLogin: (user: User, token: string) => void }) {
  const [isLogin, setIsLogin] = useState(true)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const payload = isLogin ? { email, password } : { email, password, name }
      const response = await api.post(endpoint, payload)
      const { user, token } = response.data
      
      localStorage.setItem('token', token)
      onLogin(user, token)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Fehler aufgetreten')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-nexus-dark via-[#0f0f1a] to-[#1a1a2e]">
      <div className="glass-card p-8 w-full max-w-md">
        <h1 className="text-3xl font-bold text-center mb-2 gradient-text">NEXUS KYC Pro</h1>
        <p className="text-gray-400 text-center mb-8">Enterprise Compliance Platform</p>
        
        <h2 className="text-xl font-semibold mb-6 text-center">
          {isLogin ? 'Willkommen zurück' : 'Konto erstellen'}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          {!isLogin && (
            <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} className="input-field" required />
          )}
          <input type="email" placeholder="E-Mail" value={email} onChange={(e) => setEmail(e.target.value)} className="input-field" required />
          <input type="password" placeholder="Passwort" value={password} onChange={(e) => setPassword(e.target.value)} className="input-field" required />

          {error && <div className="p-3 bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 text-sm">{error}</div>}

          <button type="submit" disabled={loading} className="w-full btn-primary disabled:opacity-50">
            {loading ? 'Lädt...' : (isLogin ? 'Einloggen' : 'Registrieren')}
          </button>
        </form>

        <p className="mt-6 text-center text-gray-400">
          {isLogin ? 'Noch kein Konto? ' : 'Bereits registriert? '}
          <button onClick={() => setIsLogin(!isLogin)} className="text-nexus-accent hover:underline">
            {isLogin ? 'Jetzt registrieren' : 'Zum Login'}
          </button>
        </p>
      </div>
    </div>
  )
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [activeTab, setActiveTab] = useState<'overview' | 'pipeline' | 'search'>('overview')
  const [cases, setCases] = useState<any[]>([])
  const [companies, setCompanies] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<any[]>([])

  useEffect(() => {
    fetchCases()
    fetchCompanies()
  }, [])

  const fetchCases = async () => {
    try {
      const response = await api.get('/api/cases')
      setCases(response.data)
    } catch (err) { console.error(err) }
  }

  const fetchCompanies = async () => {
    try {
      const response = await api.get('/api/companies')
      setCompanies(response.data)
    } catch (err) { console.error(err) }
  }

  const createCase = async () => {
    setLoading(true)
    try {
      await api.post('/api/cases', { company_id: 1, notes: 'Neuer KYC Case' })
      setMessage('✅ KYC Case erstellt!')
      fetchCases()
      setTimeout(() => setMessage(''), 3000)
    } catch (err) {
      setMessage('❌ Fehler beim Erstellen')
    } finally {
      setLoading(false)
    }
  }

  const searchHandelsregister = async () => {
    if (!searchQuery) return
    setLoading(true)
    try {
      const response = await api.get(`/api/companies/search-handelsregister?query=${encodeURIComponent(searchQuery)}`)
      setSearchResults(response.data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const pipelineSteps = [
    { id: 1, name: 'Identifikation', desc: 'Kunde identifizieren' },
    { id: 2, name: 'Dokumente', desc: 'Unterlagen prüfen' },
    { id: 3, name: 'Handelsregister', desc: 'HRB-Abfrage' },
    { id: 4, name: 'UBO-Ermittlung', desc: 'Wirtschaftliche Eigentümer' },
    { id: 5, name: 'Compliance', desc: 'PEP/Sanktionslisten' },
    { id: 6, name: 'Freigabe', desc: 'KYC abschließen' },
  ]

  return (
    <div className="min-h-screen bg-nexus-dark">
      <header className="border-b border-white/10 bg-nexus-dark/80 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold gradient-text">NEXUS KYC Pro</h1>
          <button onClick={onLogout} className="btn-secondary text-sm">Ausloggen</button>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-6">
        <div className="flex gap-4 mb-8">
          {['overview', 'pipeline', 'search'].map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab as any)}
              className={`px-6 py-3 rounded-xl font-medium transition-colors ${activeTab === tab ? 'bg-nexus-accent/20 text-nexus-accent border border-nexus-accent/30' : 'text-gray-400 hover:text-white'}`}>
              {tab === 'overview' ? 'Übersicht' : tab === 'pipeline' ? 'KYC Pipeline' : 'Firmen-Suche'}
            </button>
          ))}
        </div>

        {message && <div className="mb-6 p-4 bg-green-500/20 border border-green-500/30 rounded-xl text-green-400">{message}</div>}

        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="glass-card p-6">
                <h3 className="text-gray-400 text-sm mb-2">Aktive KYC Cases</h3>
                <p className="text-4xl font-bold gradient-text">{cases.length}</p>
              </div>
              <div className="glass-card p-6">
                <h3 className="text-gray-400 text-sm mb-2">Gespeicherte Firmen</h3>
                <p className="text-4xl font-bold gradient-text">{companies.length}</p>
              </div>
              <div className="glass-card p-6">
                <h3 className="text-gray-400 text-sm mb-2">API Status</h3>
                <p className="text-4xl font-bold text-green-400">●</p>
              </div>
            </div>

            <div className="glass-card p-6">
              <h2 className="text-xl font-semibold mb-4 text-nexus-accent">Schnellaktionen</h2>
              <button onClick={createCase} disabled={loading} className="btn-primary disabled:opacity-50">
                {loading ? 'Erstelle...' : '+ Neuen KYC Case erstellen'}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'pipeline' && (
          <div className="space-y-6">
            <div className="glass-card p-6">
              <h2 className="text-2xl font-bold mb-2 gradient-text">6-Schritt KYC Pipeline</h2>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mt-6">
                {pipelineSteps.map((step) => (
                  <div key={step.id} className="glass-card p-4 text-center border-2 border-nexus-accent/30 bg-nexus-accent/5">
                    <div className="text-2xl font-bold text-nexus-accent mb-2">{step.id}</div>
                    <h4 className="font-semibold text-sm mb-1">{step.name}</h4>
                    <p className="text-xs text-gray-400">{step.desc}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="glass-card p-6 bg-gradient-to-r from-nexus-accent/10 to-nexus-purple/10">
              <h3 className="text-lg font-semibold mb-4 text-nexus-accent">🎯 Vorteile gegenüber companyinfo.de</h3>
              <ul className="space-y-2 text-gray-300">
                <li>✓ Visuelle 6-Schritt Pipeline (companyinfo.de hat keine!)</li>
                <li>✓ Integrierte UBO-Ermittlung</li>
                <li>✓ Automatische PEP/Sanktionslisten-Prüfung</li>
                <li>✓ Dokumenten-Management mit OCR</li>
              </ul>
            </div>
          </div>
        )}

        {activeTab === 'search' && (
          <div className="glass-card p-6">
            <h2 className="text-xl font-semibold mb-4">🔍 Handelsregister-Suche</h2>
            <div className="flex gap-4">
              <input type="text" placeholder="Firmenname oder HRB-Nummer..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="input-field flex-1" />
              <button onClick={searchHandelsregister} disabled={loading} className="btn-primary disabled:opacity-50">
                {loading ? 'Suche...' : 'Suchen'}
              </button>
            </div>
            {searchResults.length > 0 && (
              <div className="mt-6 space-y-3">
                {searchResults.map((company, idx) => (
                  <div key={idx} className="p-4 bg-white/5 rounded-xl border border-white/10">
                    <p className="font-semibold">{company.name}</p>
                    <p className="text-sm text-gray-400">{company.registration_number} | {company.legal_form}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function App() {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'))

  const handleLogin = (userData: User, authToken: string) => {
    setUser(userData)
    setToken(authToken)
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    setUser(null)
    setToken(null)
  }

  if (!token) return <Auth onLogin={handleLogin} />
  return <Dashboard onLogout={handleLogout} />
}

export default App
