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
      body { font-family: Arial, sans-serif; color: #025064; line-height: 1.6; background: #EEF2F5; padding: 24px; }
      h1 { color: #025064; border-bottom: 2px solid #317D9B; padding-bottom: 10px; }
      h2 { color: #317D9B; margin-top: 30px; }
      table { width: 100%; border-collapse: collapse; margin: 20px 0; background: #EEF2F5; }
      th, td { border: 1px solid rgba(2, 80, 100, 0.18); padding: 10px; text-align: left; color: #025064; }
      th { background: rgba(49, 125, 155, 0.08); }
      .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; color: #025064; background: rgba(2, 80, 100, 0.12); }
      .critical { background: rgba(2, 80, 100, 0.12); color: #025064; }
      .high { background: rgba(49, 125, 155, 0.12); color: #317D9B; }
      .medium { background: rgba(2, 80, 100, 0.08); color: #025064; }
      .low { background: rgba(49, 125, 155, 0.08); color: #317D9B; }
      .stat-box { display: inline-block; padding: 15px 25px; margin: 5px; background: #EEF2F5; border-radius: 8px; text-align: center; border: 1px solid rgba(2, 80, 100, 0.18); }
      .stat-number { font-size: 28px; font-weight: bold; color: #025064; }
      a { color: #317D9B; }
    ` : `
      body { font-family: 'Inter', sans-serif; background: #EEF2F5; color: #025064; padding: 40px; line-height: 1.6; }
      h1 { color: #025064; border-bottom: 2px solid #317D9B; padding-bottom: 10px; }
      h2 { color: #317D9B; margin-top: 30px; }
      table { width: 100%; border-collapse: collapse; margin: 20px 0; background: #EEF2F5; }
      th, td { border: 1px solid rgba(2, 80, 100, 0.18); padding: 12px; text-align: left; color: #025064; }
      th { background: rgba(49, 125, 155, 0.08); color: #025064; }
      .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; color: #025064; background: rgba(2, 80, 100, 0.12); }
      .critical { background: rgba(2, 80, 100, 0.12); color: #025064; }
      .high { background: rgba(49, 125, 155, 0.12); color: #317D9B; }
      .medium { background: rgba(2, 80, 100, 0.08); color: #025064; }
      .low { background: rgba(49, 125, 155, 0.08); color: #317D9B; }
      .stat-box { display: inline-block; padding: 20px 30px; margin: 8px; background: #EEF2F5; border: 1px solid rgba(2, 80, 100, 0.18); border-radius: 12px; text-align: center; }
      .stat-number { font-size: 32px; font-weight: bold; color: #025064; }
      a { color: #317D9B; }
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
      <div class="stat-number" style="color: #317D9B;">${false_positives?.length || 0}</div>
      <div>False Positives</div>
    </div>
    <div class="stat-box">
      <div class="stat-number" style="color: #025064;">${true_vulnerabilities?.length || 0}</div>
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
  
  <hr style="margin-top: 40px; border-color: rgba(2, 80, 100, 0.18);">
  <p style="color: rgba(2, 80, 100, 0.65); font-size: 12px;">
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
