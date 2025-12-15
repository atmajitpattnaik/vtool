import { useState } from 'react'
import FileUpload from './components/FileUpload'
import AnalysisView from './components/AnalysisView'
import ReportDisplay from './components/ReportDisplay'
import ExportOptions from './components/ExportOptions'

function App() {
    const [files, setFiles] = useState({
        owaspReport: null,
        dependencyManifest: null
    })
    const [analysisResult, setAnalysisResult] = useState(null)
    const [llmReport, setLlmReport] = useState(null)
    const [isAnalyzing, setIsAnalyzing] = useState(false)
    const [isGeneratingReport, setIsGeneratingReport] = useState(false)
    const [error, setError] = useState(null)
    const [activeTab, setActiveTab] = useState('upload')

    const handleFileChange = (type, file) => {
        setFiles(prev => ({ ...prev, [type]: file }))
        setError(null)
    }

    const handleAnalyze = async () => {
        if (!files.owaspReport) {
            setError('Please upload an OWASP Dependency-Check report')
            return
        }

        setIsAnalyzing(true)
        setError(null)

        try {
            const formData = new FormData()
            formData.append('owaspReport', files.owaspReport)
            if (files.dependencyManifest) {
                formData.append('dependencyManifest', files.dependencyManifest)
            }

            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            })

            const parseJsonSafe = async (res) => {
                const text = await res.text()
                try {
                    return JSON.parse(text || '{}')
                } catch {
                    return { raw: text }
                }
            }

            if (!response.ok) {
                const errData = await parseJsonSafe(response)
                throw new Error(errData?.error || errData?.message || 'Analysis failed')
            }

            const data = await parseJsonSafe(response)
            setAnalysisResult(data.analysis)
            setActiveTab('analysis')
        } catch (err) {
            console.error('Analysis error:', err)
            setError(err.message)
        } finally {
            setIsAnalyzing(false)
        }
    }

    const handleGenerateReport = async () => {
        if (!analysisResult) {
            setError('Please run analysis first')
            return
        }

        setIsGeneratingReport(true)
        setError(null)

        try {
            const response = await fetch('/api/generate-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ analysis: analysisResult })
            })

            const parseJsonSafe = async (res) => {
                const text = await res.text()
                try {
                    return JSON.parse(text || '{}')
                } catch {
                    return { raw: text }
                }
            }

            if (!response.ok) {
                const errData = await parseJsonSafe(response)
                throw new Error(errData?.error || errData?.message || 'Report generation failed')
            }

            const data = await parseJsonSafe(response)
            setLlmReport(data.report)
            setActiveTab('report')
        } catch (err) {
            console.error('Report generation error:', err)
            setError(err.message)
        } finally {
            setIsGeneratingReport(false)
        }
    }

    const handleReset = () => {
        setFiles({ owaspReport: null, dependencyManifest: null })
        setAnalysisResult(null)
        setLlmReport(null)
        setError(null)
        setActiveTab('upload')
    }

    return (
        <div className="app">
            <header className="header">
                <div className="header-content">
                    <div className="logo">
                        <div className="logo-icon">🛡️</div>
                        <div>
                            <div className="logo-text">VulnShield</div>
                            <div className="header-subtitle">Vulnerability Noise Reduction System</div>
                        </div>
                    </div>
                    {analysisResult && (
                        <button className="btn btn-ghost" onClick={handleReset}>
                            ← New Analysis
                        </button>
                    )}
                </div>
            </header>

            <main className="main-content">
                {error && (
                    <div className="alert alert-error fade-in">
                        <span className="alert-icon">⚠️</span>
                        <div className="alert-content">
                            <div className="alert-title">Error</div>
                            <div>{error}</div>
                        </div>
                    </div>
                )}

                {/* Navigation Tabs */}
                <div className="tabs">
                    <button
                        className={`tab ${activeTab === 'upload' ? 'active' : ''}`}
                        onClick={() => setActiveTab('upload')}
                    >
                        📤 Upload Files
                    </button>
                    <button
                        className={`tab ${activeTab === 'analysis' ? 'active' : ''}`}
                        onClick={() => setActiveTab('analysis')}
                        disabled={!analysisResult}
                    >
                        🔍 Analysis Results
                    </button>
                    <button
                        className={`tab ${activeTab === 'report' ? 'active' : ''}`}
                        onClick={() => setActiveTab('report')}
                        disabled={!llmReport}
                    >
                        📊 AI Report
                    </button>
                </div>

                {/* Upload Tab */}
                {activeTab === 'upload' && (
                    <div className="fade-in">
                        <FileUpload
                            files={files}
                            onFileChange={handleFileChange}
                        />

                        <div style={{ marginTop: '2rem', textAlign: 'center' }}>
                            <button
                                className="btn btn-primary btn-lg"
                                onClick={handleAnalyze}
                                disabled={!files.owaspReport || isAnalyzing}
                            >
                                {isAnalyzing ? (
                                    <>
                                        <span className="spinner" style={{ width: 20, height: 20 }}></span>
                                        Analyzing...
                                    </>
                                ) : (
                                    <>🔬 Analyze Vulnerabilities</>
                                )}
                            </button>

                            {isAnalyzing && (
                                <div className="loading-subtext" style={{ marginTop: '1rem' }}>
                                    Parsing reports and running reachability analysis...
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* Analysis Tab */}
                {activeTab === 'analysis' && analysisResult && (
                    <div className="fade-in">
                        <AnalysisView analysis={analysisResult} />

                        <div style={{ marginTop: '2rem', textAlign: 'center' }}>
                            <button
                                className="btn btn-primary btn-lg"
                                onClick={handleGenerateReport}
                                disabled={isGeneratingReport}
                            >
                                {isGeneratingReport ? (
                                    <>
                                        <span className="spinner" style={{ width: 20, height: 20 }}></span>
                                        Generating AI Report...
                                    </>
                                ) : (
                                    <>🤖 Generate AI Report</>
                                )}
                            </button>

                            {isGeneratingReport && (
                                <div className="loading-subtext" style={{ marginTop: '1rem' }}>
                                    AI is analyzing findings and generating recommendations...
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* Report Tab */}
                {activeTab === 'report' && llmReport && (
                    <div className="fade-in">
                        <ReportDisplay report={llmReport} />
                        <ExportOptions
                            analysis={analysisResult}
                            report={llmReport}
                        />
                    </div>
                )}
            </main>

            <footer className="footer">
                <div>
                    VulnShield v1.0.0 • Automated Vulnerability Noise Reduction & Reporting System
                </div>
            </footer>
        </div>
    )
}

export default App
