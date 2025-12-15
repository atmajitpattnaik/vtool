import { useState } from 'react'

function AnalysisView({ analysis }) {
    const [showTab, setShowTab] = useState('vulnerabilities')

    if (!analysis) {
        return (
            <div className="empty-state">
                <div className="empty-icon">🔍</div>
                <div className="empty-title">No Analysis Data</div>
                <div className="empty-description">
                    Upload files and run analysis to see results here.
                </div>
            </div>
        )
    }

    const { false_positives, true_vulnerabilities, summary, metadata } = analysis

    const getSeverityBadge = (severity) => {
        const classes = {
            CRITICAL: 'badge badge-critical',
            HIGH: 'badge badge-high',
            MEDIUM: 'badge badge-medium',
            LOW: 'badge badge-low'
        }
        return classes[severity?.toUpperCase()] || 'badge badge-info'
    }

    const getReasonLabel = (reason) => {
        const labels = {
            VERSION_MISMATCH: 'Version Mismatch',
            NON_REACHABLE: 'Non-Reachable',
            ENV_MISMATCH: 'Environment Mismatch',
            UNUSED_TRANSITIVE: 'Unused Transitive',
            DEV_ONLY: 'Dev Only'
        }
        return labels[reason] || reason
    }

    return (
        <div className="analysis-section slide-up">
            {/* Stats Overview */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-value">{metadata?.total_vulnerabilities_scanned || 0}</div>
                    <div className="stat-label">Total Scanned</div>
                </div>
                <div className="stat-card">
                    <div className="stat-value success">{false_positives?.length || 0}</div>
                    <div className="stat-label">False Positives</div>
                </div>
                <div className="stat-card">
                    <div className="stat-value" style={{ color: 'var(--severity-high)' }}>
                        {true_vulnerabilities?.length || 0}
                    </div>
                    <div className="stat-label">True Vulnerabilities</div>
                </div>
                <div className="stat-card">
                    <div className="stat-value">{summary?.false_positive_rate || 0}%</div>
                    <div className="stat-label">FP Rate</div>
                </div>
            </div>

            {/* Severity Breakdown */}
            {summary?.severity_breakdown && (
                <div className="stats-grid" style={{ marginBottom: '2rem' }}>
                    <div className="stat-card">
                        <div className="stat-value critical">{summary.severity_breakdown.critical || 0}</div>
                        <div className="stat-label">Critical</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value high">{summary.severity_breakdown.high || 0}</div>
                        <div className="stat-label">High</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value medium">{summary.severity_breakdown.medium || 0}</div>
                        <div className="stat-label">Medium</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-value low">{summary.severity_breakdown.low || 0}</div>
                        <div className="stat-label">Low</div>
                    </div>
                </div>
            )}

            {/* Risk Alert */}
            {summary?.requires_immediate_action && (
                <div className="alert alert-error" style={{ marginBottom: '1.5rem' }}>
                    <span className="alert-icon">🚨</span>
                    <div className="alert-content">
                        <div className="alert-title">Immediate Action Required</div>
                        <div>Critical or high severity vulnerabilities detected that need immediate attention.</div>
                    </div>
                </div>
            )}

            {/* Tabs for Vulnerabilities / False Positives */}
            <div className="tabs">
                <button
                    className={`tab ${showTab === 'vulnerabilities' ? 'active' : ''}`}
                    onClick={() => setShowTab('vulnerabilities')}
                >
                    ⚠️ True Vulnerabilities ({true_vulnerabilities?.length || 0})
                </button>
                <button
                    className={`tab ${showTab === 'false-positives' ? 'active' : ''}`}
                    onClick={() => setShowTab('false-positives')}
                >
                    ✅ False Positives ({false_positives?.length || 0})
                </button>
            </div>

            {/* True Vulnerabilities Table */}
            {showTab === 'vulnerabilities' && (
                <div className="card">
                    {true_vulnerabilities?.length > 0 ? (
                        <div className="table-container">
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>CVE ID</th>
                                        <th>Dependency</th>
                                        <th>Severity</th>
                                        <th>CVSS</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {true_vulnerabilities.map((vuln, idx) => (
                                        <tr key={idx}>
                                            <td>
                                                <a
                                                    href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    style={{ color: 'var(--accent-secondary)', textDecoration: 'none' }}
                                                >
                                                    {vuln.cve_id}
                                                </a>
                                            </td>
                                            <td>
                                                <code style={{
                                                    background: 'var(--bg-tertiary)',
                                                    padding: '0.2rem 0.5rem',
                                                    borderRadius: '4px',
                                                    fontSize: '0.85rem'
                                                }}>
                                                    {vuln.dependency}
                                                </code>
                                            </td>
                                            <td>
                                                <span className={getSeverityBadge(vuln.severity)}>
                                                    {vuln.severity}
                                                </span>
                                            </td>
                                            <td>{vuln.cvss_score?.toFixed(1) || 'N/A'}</td>
                                            <td style={{ maxWidth: '300px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                                {vuln.description?.substring(0, 150)}
                                                {vuln.description?.length > 150 ? '...' : ''}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <div className="empty-icon">🎉</div>
                            <div className="empty-title">No Actionable Vulnerabilities</div>
                            <div className="empty-description">
                                All identified vulnerabilities were classified as false positives.
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* False Positives Table */}
            {showTab === 'false-positives' && (
                <div className="card">
                    {false_positives?.length > 0 ? (
                        <div className="table-container">
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>CVE ID</th>
                                        <th>Dependency</th>
                                        <th>Reason</th>
                                        <th>Confidence</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {false_positives.map((fp, idx) => (
                                        <tr key={idx}>
                                            <td>
                                                <code style={{ fontSize: '0.85rem' }}>{fp.cve_id}</code>
                                            </td>
                                            <td>
                                                <code style={{
                                                    background: 'var(--bg-tertiary)',
                                                    padding: '0.2rem 0.5rem',
                                                    borderRadius: '4px',
                                                    fontSize: '0.85rem'
                                                }}>
                                                    {fp.dependency}
                                                </code>
                                            </td>
                                            <td>
                                                <span className="badge badge-success">
                                                    {getReasonLabel(fp.reason)}
                                                </span>
                                            </td>
                                            <td>
                                                <span className="badge badge-info">{fp.confidence}</span>
                                            </td>
                                            <td style={{ maxWidth: '300px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                                {fp.details?.substring(0, 150)}
                                                {fp.details?.length > 150 ? '...' : ''}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <div className="empty-icon">📋</div>
                            <div className="empty-title">No False Positives Detected</div>
                            <div className="empty-description">
                                All vulnerabilities appear to be genuine based on our analysis.
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Metadata */}
            <div className="card" style={{ marginTop: '1.5rem' }}>
                <div className="card-header">
                    <div className="card-title">📋 Analysis Metadata</div>
                </div>
                <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                    gap: '1rem',
                    fontSize: '0.9rem'
                }}>
                    <div>
                        <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Project</div>
                        <div>{metadata?.project_name || 'Unknown'}</div>
                    </div>
                    <div>
                        <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Analysis Time</div>
                        <div>{new Date(metadata?.analysis_timestamp).toLocaleString()}</div>
                    </div>
                    <div>
                        <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Tool Version</div>
                        <div>{metadata?.tool_version || '1.0.0'}</div>
                    </div>
                    <div>
                        <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Risk Score</div>
                        <div style={{
                            color: summary?.risk_score > 50 ? 'var(--severity-high)' : 'var(--success)'
                        }}>
                            {summary?.risk_score || 0}/100
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default AnalysisView
