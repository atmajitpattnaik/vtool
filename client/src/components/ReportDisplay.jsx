function ReportDisplay({ report }) {
    if (!report) {
        return (
            <div className="empty-state">
                <div className="empty-icon">📊</div>
                <div className="empty-title">No Report Generated</div>
                <div className="empty-description">
                    Run analysis and generate an AI report to see it here.
                </div>
            </div>
        )
    }

    // Convert markdown-like content to HTML
    const formatContent = (content) => {
        if (!content) return ''

        let html = content

        // Headers
        html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>')
        html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>')
        html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>')

        // Bold
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')

        // Italic
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>')

        // Code blocks
        html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')

        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>')

        // Tables - simple conversion
        const tableRegex = /\|(.+)\|\n\|[-|]+\|\n((?:\|.+\|\n?)+)/g
        html = html.replace(tableRegex, (match, header, body) => {
            const headerCells = header.split('|').filter(c => c.trim())
            const headerRow = `<tr>${headerCells.map(c => `<th>${c.trim()}</th>`).join('')}</tr>`

            const bodyRows = body.trim().split('\n').map(row => {
                const cells = row.split('|').filter(c => c.trim())
                return `<tr>${cells.map(c => `<td>${c.trim()}</td>`).join('')}</tr>`
            }).join('')

            return `<table>${headerRow}${bodyRows}</table>`
        })

        // Lists
        html = html.replace(/^\- (.*$)/gim, '<li>$1</li>')
        html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')

        // Numbered lists
        html = html.replace(/^\d+\. (.*$)/gim, '<li>$1</li>')

        // Blockquotes
        html = html.replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>')

        // Line breaks
        html = html.replace(/\n\n/g, '</p><p>')
        html = html.replace(/\n/g, '<br>')

        // Wrap in paragraphs if needed
        if (!html.startsWith('<')) {
            html = `<p>${html}</p>`
        }

        return html
    }

    return (
        <div className="slide-up">
            {/* Report Header */}
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                        <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            🤖 AI-Generated Security Report
                        </h2>
                        <p style={{ margin: '0.5rem 0 0', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                            Generated on {new Date(report.generated_at).toLocaleString()}
                            {report.model !== 'fallback' && ` • Model: ${report.model}`}
                        </p>
                    </div>

                    {report.model === 'fallback' && (
                        <div className="badge badge-warning" style={{ padding: '0.5rem 1rem' }}>
                            ⚠️ Basic Report (AI unavailable)
                        </div>
                    )}
                </div>
            </div>

            {/* Report Content */}
            <div className="report-container">
                <div
                    className="report-content"
                    dangerouslySetInnerHTML={{ __html: formatContent(report.content) }}
                />
            </div>

            {/* Token Usage */}
            {report.tokens_used > 0 && (
                <div style={{
                    marginTop: '1rem',
                    textAlign: 'right',
                    color: 'var(--text-muted)',
                    fontSize: '0.8rem'
                }}>
                    Tokens used: {report.tokens_used.toLocaleString()}
                </div>
            )}
        </div>
    )
}

export default ReportDisplay
