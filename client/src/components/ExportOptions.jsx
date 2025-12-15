import { useState } from 'react'

function ExportOptions({ analysis, report }) {
    const [exporting, setExporting] = useState(null)

    const exportToJson = () => {
        setExporting('json')

        try {
            const exportData = {
                analysis,
                report: report ? {
                    content: report.content,
                    generated_at: report.generated_at,
                    model: report.model
                } : null,
                exported_at: new Date().toISOString()
            }

            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
            downloadBlob(blob, `vulnerability-report-${getDateString()}.json`)
        } catch (err) {
            console.error('Export error:', err)
            alert('Failed to export JSON: ' + err.message)
        } finally {
            setExporting(null)
        }
    }

    const exportToHtml = () => {
        setExporting('html')

        try {
            const htmlContent = generateHtmlReport(analysis, report)
            const blob = new Blob([htmlContent], { type: 'text/html' })
            downloadBlob(blob, `vulnerability-report-${getDateString()}.html`)
        } catch (err) {
            console.error('Export error:', err)
            alert('Failed to export HTML: ' + err.message)
        } finally {
            setExporting(null)
        }
    }

    const exportToPdf = async () => {
        setExporting('pdf')

        try {
            // Dynamic import of html2pdf
            const html2pdf = (await import('html2pdf.js')).default

            const element = document.createElement('div')
            element.innerHTML = generateHtmlReport(analysis, report, true)
            element.style.padding = '20px'
            document.body.appendChild(element)

            const opt = {
                margin: 0.5,
                filename: `vulnerability-report-${getDateString()}.pdf`,
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 2 },
                jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' }
            }

            await html2pdf().set(opt).from(element).save()
            document.body.removeChild(element)
        } catch (err) {
            console.error('PDF export error:', err)
            alert('Failed to export PDF: ' + err.message)
        } finally {
            setExporting(null)
        }
    }

    const downloadBlob = (blob, filename) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    const getDateString = () => {
        return new Date().toISOString().split('T')[0]
    }

    const generateHtmlReport = (analysis, report, forPdf = false) => {
        const { false_positives, true_vulnerabilities, summary, metadata } = analysis

        const styles = forPdf ? `
      body { font-family: Arial, sans-serif; color: #333; line-height: 1.6; }
      h1 { color: #1a1a2e; border-bottom: 2px solid #8b5cf6; padding-bottom: 10px; }
      h2 { color: #8b5cf6; margin-top: 30px; }
      table { width: 100%; border-collapse: collapse; margin: 20px 0; }
      th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
      th { background: #f5f5f5; }
      .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
      .critical { background: #fee2e2; color: #dc2626; }
      .high { background: #ffedd5; color: #ea580c; }
      .medium { background: #fef9c3; color: #ca8a04; }
      .low { background: #dcfce7; color: #16a34a; }
      .stat-box { display: inline-block; padding: 15px 25px; margin: 5px; background: #f5f5f5; border-radius: 8px; text-align: center; }
      .stat-number { font-size: 28px; font-weight: bold; }
    ` : `
      body { font-family: 'Inter', sans-serif; background: #0a0a0f; color: #f4f4f5; padding: 40px; line-height: 1.6; }
      h1 { color: #f4f4f5; border-bottom: 2px solid #8b5cf6; padding-bottom: 10px; }
      h2 { color: #8b5cf6; margin-top: 30px; }
      table { width: 100%; border-collapse: collapse; margin: 20px 0; background: #16161f; }
      th, td { border: 1px solid #2a2a35; padding: 12px; text-align: left; }
      th { background: #1a1a25; color: #a1a1aa; }
      .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
      .critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
      .high { background: rgba(249, 115, 22, 0.15); color: #f97316; }
      .medium { background: rgba(234, 179, 8, 0.15); color: #eab308; }
      .low { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
      .stat-box { display: inline-block; padding: 20px 30px; margin: 8px; background: #16161f; border: 1px solid #2a2a35; border-radius: 12px; text-align: center; }
      .stat-number { font-size: 32px; font-weight: bold; background: linear-gradient(135deg, #f4f4f5, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
      a { color: #06b6d4; }
    `

        return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Analysis Report - ${metadata?.project_name || 'Unknown'}</title>
  <style>${styles}</style>
</head>
<body>
  <h1>🛡️ Vulnerability Analysis Report</h1>
  
  <p><strong>Project:</strong> ${metadata?.project_name || 'Unknown'}<br>
  <strong>Generated:</strong> ${new Date().toLocaleString()}<br>
  <strong>Tool Version:</strong> ${metadata?.tool_version || '1.0.0'}</p>
  
  <h2>📊 Summary</h2>
  <div>
    <div class="stat-box">
      <div class="stat-number">${metadata?.total_vulnerabilities_scanned || 0}</div>
      <div>Total Scanned</div>
    </div>
    <div class="stat-box">
      <div class="stat-number" style="color: #22c55e;">${false_positives?.length || 0}</div>
      <div>False Positives</div>
    </div>
    <div class="stat-box">
      <div class="stat-number" style="color: #f97316;">${true_vulnerabilities?.length || 0}</div>
      <div>True Vulnerabilities</div>
    </div>
  </div>
  
  <h2>⚠️ True Vulnerabilities</h2>
  ${true_vulnerabilities?.length > 0 ? `
  <table>
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
      ${true_vulnerabilities.map(v => `
        <tr>
          <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank">${v.cve_id}</a></td>
          <td><code>${v.dependency}</code></td>
          <td><span class="badge ${v.severity?.toLowerCase()}">${v.severity}</span></td>
          <td>${v.cvss_score?.toFixed(1) || 'N/A'}</td>
          <td>${v.description?.substring(0, 150) || ''}${v.description?.length > 150 ? '...' : ''}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
  ` : '<p>No actionable vulnerabilities found.</p>'}
  
  <h2>✅ False Positives</h2>
  ${false_positives?.length > 0 ? `
  <table>
    <thead>
      <tr>
        <th>CVE ID</th>
        <th>Dependency</th>
        <th>Reason</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
      ${false_positives.map(fp => `
        <tr>
          <td>${fp.cve_id}</td>
          <td><code>${fp.dependency}</code></td>
          <td>${fp.reason}</td>
          <td>${fp.details?.substring(0, 150) || ''}${fp.details?.length > 150 ? '...' : ''}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
  ` : '<p>No false positives identified.</p>'}
  
  ${report?.content ? `
  <h2>🤖 AI Analysis</h2>
  <div style="white-space: pre-wrap;">${report.content}</div>
  ` : ''}
  
  <hr style="margin-top: 40px; border-color: #2a2a35;">
  <p style="color: #71717a; font-size: 12px;">
    Generated by VulnShield v1.0.0 • Automated Vulnerability Noise Reduction & Reporting System
  </p>
</body>
</html>
    `
    }

    return (
        <div className="export-options">
            <button
                className="btn btn-secondary"
                onClick={exportToJson}
                disabled={exporting === 'json'}
            >
                {exporting === 'json' ? '⏳ Exporting...' : '📄 Export JSON'}
            </button>

            <button
                className="btn btn-secondary"
                onClick={exportToHtml}
                disabled={exporting === 'html'}
            >
                {exporting === 'html' ? '⏳ Exporting...' : '🌐 Export HTML'}
            </button>

            <button
                className="btn btn-secondary"
                onClick={exportToPdf}
                disabled={exporting === 'pdf'}
            >
                {exporting === 'pdf' ? '⏳ Generating PDF...' : '📑 Export PDF'}
            </button>
        </div>
    )
}

export default ExportOptions
