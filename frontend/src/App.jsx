import { useState } from 'react'

function App() {
  const [url, setUrl]           = useState('')
  const [loading, setLoading]   = useState(false)
  const [results, setResults]   = useState(null)
  const [error, setError]       = useState(null)

  const handleScan = async () => {
    if (!url) return
    setLoading(true)
    setError(null)
    setResults(null)
    try {
      const resp = await fetch('http://localhost:5500/scan', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ url }),
      })
      const data = await resp.json()
      setResults(data)
    } catch (err) {
      setError('Failed to connect to backend. Is Flask running on port 5500?')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (sev) => {
    if (sev === 'Critical') return '#DC2626'
    if (sev === 'High')     return '#EA580C'
    if (sev === 'Medium')   return '#CA8A04'
    if (sev === 'Low')      return '#16A34A'
    return '#6B7280'
  }

  return (
    <div style={{ fontFamily: 'Calibri, sans-serif', maxWidth: '1100px',
                  margin: '0 auto', padding: '2rem' }}>

      {/* Header */}
      <div style={{ background: '#1B3A6B', color: 'white',
                    padding: '1.5rem 2rem', borderRadius: '8px',
                    marginBottom: '2rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.8rem' }}>
          🔍 AI Vulnerability Scanner
        </h1>
        <p style={{ margin: '0.4rem 0 0', color: '#93C5FD', fontSize: '0.95rem' }}>
          NIT6150 Advanced Project · Group 2 · NMIT
        </p>
      </div>

      {/* Scan Input */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem' }}>
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="Enter target URL e.g. http://localhost:3000"
          style={{ flex: 1, padding: '0.7rem 1rem', fontSize: '1rem',
                   border: '2px solid #CBD5E1', borderRadius: '6px' }}
        />
        <button
          onClick={handleScan}
          disabled={loading}
          style={{ padding: '0.7rem 2rem', background: loading ? '#94A3B8' : '#1B3A6B',
                   color: 'white', border: 'none', borderRadius: '6px',
                   fontSize: '1rem', cursor: loading ? 'not-allowed' : 'pointer' }}
        >
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: '#FFF1F2', border: '1px solid #DC2626',
                      color: '#DC2626', padding: '1rem', borderRadius: '6px',
                      marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '3rem',
                      color: '#1B3A6B', fontSize: '1.1rem' }}>
          ⏳ Scanning {url} — this may take 2-3 minutes...
        </div>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)',
                        gap: '1rem', marginBottom: '2rem' }}>
            {[
              { label: 'Total',    value: results.summary?.total,    color: '#1B3A6B' },
              { label: 'Critical', value: results.summary?.critical, color: '#DC2626' },
              { label: 'High',     value: results.summary?.high,     color: '#EA580C' },
              { label: 'Medium',   value: results.summary?.medium,   color: '#CA8A04' },
              { label: 'Low',      value: results.summary?.low,      color: '#16A34A' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ background: 'white', border: `2px solid ${color}`,
                                        borderRadius: '8px', padding: '1rem',
                                        textAlign: 'center' }}>
                <div style={{ fontSize: '2rem', fontWeight: 'bold', color }}>{value ?? 0}</div>
                <div style={{ color: '#64748B', fontSize: '0.9rem' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Risk Level */}
          {results.risk && (
            <div style={{ background: '#1B3A6B', color: 'white', padding: '1rem 1.5rem',
                          borderRadius: '8px', marginBottom: '2rem',
                          display: 'flex', justifyContent: 'space-between',
                          alignItems: 'center' }}>
              <span style={{ fontSize: '1rem' }}>Overall Risk Level</span>
              <span style={{ fontSize: '1.4rem', fontWeight: 'bold',
                             color: getSeverityColor(results.risk.level) }}>
                {results.risk.level}
              </span>
              <span style={{ color: '#93C5FD', fontSize: '0.9rem' }}>
                Score: {results.risk.score} · Method: {results.risk.method}
              </span>
            </div>
          )}

          {/* Policy */}
          {results.policy && (
            <div style={{ background: '#FFF7ED', border: '1px solid #EA580C',
                          borderRadius: '8px', padding: '1rem 1.5rem',
                          marginBottom: '2rem' }}>
              <strong style={{ color: '#C2410C' }}>Policy Decision: </strong>
              <span>{results.policy.action} — {results.policy.description}</span>
            </div>
          )}

          {/* Findings Table */}
          <h3 style={{ color: '#1B3A6B' }}>
            Findings ({results.findings?.length ?? 0})
          </h3>
          <table style={{ width: '100%', borderCollapse: 'collapse',
                          marginBottom: '2rem' }}>
            <thead>
              <tr style={{ background: '#1B3A6B', color: 'white' }}>
                {['Severity', 'Type', 'URL', 'Detail'].map(h => (
                  <th key={h} style={{ padding: '10px 12px', textAlign: 'left' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(results.findings ?? []).map((f, i) => (
                <tr key={i} style={{ background: i % 2 === 0 ? '#F8FAFC' : 'white',
                                     borderBottom: '1px solid #E2E8F0' }}>
                  <td style={{ padding: '8px 12px' }}>
                    <span style={{ background: getSeverityColor(f.severity),
                                   color: 'white', padding: '2px 8px',
                                   borderRadius: '4px', fontSize: '0.85rem',
                                   fontWeight: 'bold' }}>
                      {f.severity}
                    </span>
                  </td>
                  <td style={{ padding: '8px 12px', fontSize: '0.9rem' }}>{f.type}</td>
                  <td style={{ padding: '8px 12px', fontSize: '0.8rem',
                               color: '#1E40AF', wordBreak: 'break-all',
                               maxWidth: '300px' }}>{f.url}</td>
                  <td style={{ padding: '8px 12px', fontSize: '0.85rem',
                               color: '#475569' }}>{f.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Errors */}
          {results.errors?.length > 0 && (
            <div style={{ background: '#FFF1F2', border: '1px solid #DC2626',
                          borderRadius: '8px', padding: '1rem', marginBottom: '1rem' }}>
              <strong style={{ color: '#DC2626' }}>Scanner Errors:</strong>
              {results.errors.map((e, i) => (
                <div key={i} style={{ color: '#DC2626', fontSize: '0.85rem' }}>{e}</div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default App