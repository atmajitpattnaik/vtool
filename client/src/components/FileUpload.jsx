import { useState, useRef } from 'react'

function FileUpload({ files, onFileChange }) {
    const [dragOver, setDragOver] = useState({ owasp: false, manifest: false })
    const owaspInputRef = useRef(null)
    const manifestInputRef = useRef(null)

    const handleDragOver = (e, type) => {
        e.preventDefault()
        setDragOver(prev => ({ ...prev, [type]: true }))
    }

    const handleDragLeave = (e, type) => {
        e.preventDefault()
        setDragOver(prev => ({ ...prev, [type]: false }))
    }

    const handleDrop = (e, type) => {
        e.preventDefault()
        setDragOver(prev => ({ ...prev, [type]: false }))

        const droppedFile = e.dataTransfer.files[0]
        if (droppedFile) {
            const key = type === 'owasp' ? 'owaspReport' : 'dependencyManifest'
            onFileChange(key, droppedFile)
        }
    }

    const handleFileSelect = (e, type) => {
        const selectedFile = e.target.files[0]
        if (selectedFile) {
            const key = type === 'owasp' ? 'owaspReport' : 'dependencyManifest'
            onFileChange(key, selectedFile)
        }
    }

    const handleRemoveFile = (e, type) => {
        e.stopPropagation()
        const key = type === 'owasp' ? 'owaspReport' : 'dependencyManifest'
        onFileChange(key, null)

        // Reset input
        if (type === 'owasp' && owaspInputRef.current) {
            owaspInputRef.current.value = ''
        } else if (manifestInputRef.current) {
            manifestInputRef.current.value = ''
        }
    }

    const formatFileSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B'
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
    }

    return (
        <div className="upload-section">
            {/* OWASP Report Upload */}
            <div
                className={`upload-zone ${dragOver.owasp ? 'drag-over' : ''} ${files.owaspReport ? 'has-file' : ''}`}
                onDragOver={(e) => handleDragOver(e, 'owasp')}
                onDragLeave={(e) => handleDragLeave(e, 'owasp')}
                onDrop={(e) => handleDrop(e, 'owasp')}
                onClick={() => owaspInputRef.current?.click()}
            >
                <input
                    type="file"
                    ref={owaspInputRef}
                    accept=".json,.xml,.html,.htm"
                    onChange={(e) => handleFileSelect(e, 'owasp')}
                    style={{ display: 'none' }}
                />

                <div className="upload-icon">
                    {files.owaspReport ? '✅' : '📄'}
                </div>

                <div className="upload-title">
                    OWASP Dependency-Check Report
                </div>
                <div className="upload-subtitle">
                    {files.owaspReport
                        ? 'Click to replace file'
                        : 'Drag & drop or click to upload (JSON or XML)'
                    }
                </div>

                {files.owaspReport && (
                    <div className="upload-file-info">
                        <span>📎</span>
                        <span className="upload-file-name">{files.owaspReport.name}</span>
                        <span>({formatFileSize(files.owaspReport.size)})</span>
                        <button
                            className="upload-remove"
                            onClick={(e) => handleRemoveFile(e, 'owasp')}
                            title="Remove file"
                        >
                            ✕
                        </button>
                    </div>
                )}
            </div>

            {/* Dependency Manifest Upload */}
            <div
                className={`upload-zone ${dragOver.manifest ? 'drag-over' : ''} ${files.dependencyManifest ? 'has-file' : ''}`}
                onDragOver={(e) => handleDragOver(e, 'manifest')}
                onDragLeave={(e) => handleDragLeave(e, 'manifest')}
                onDrop={(e) => handleDrop(e, 'manifest')}
                onClick={() => manifestInputRef.current?.click()}
            >
                <input
                    type="file"
                    ref={manifestInputRef}
                    accept=".json,.xml,.txt,.html,.htm"
                    onChange={(e) => handleFileSelect(e, 'manifest')}
                    style={{ display: 'none' }}
                />

                <div className="upload-icon">
                    {files.dependencyManifest ? '✅' : '📦'}
                </div>

                <div className="upload-title">
                    Dependency Manifest
                    <span style={{
                        fontSize: '0.75rem',
                        color: 'var(--text-muted)',
                        marginLeft: '0.5rem'
                    }}>
                        (Optional)
                    </span>
                </div>
                <div className="upload-subtitle">
                    {files.dependencyManifest
                        ? 'Click to replace file'
                        : 'package.json, pom.xml, or requirements.txt'
                    }
                </div>

                {files.dependencyManifest && (
                    <div className="upload-file-info">
                        <span>📎</span>
                        <span className="upload-file-name">{files.dependencyManifest.name}</span>
                        <span>({formatFileSize(files.dependencyManifest.size)})</span>
                        <button
                            className="upload-remove"
                            onClick={(e) => handleRemoveFile(e, 'manifest')}
                            title="Remove file"
                        >
                            ✕
                        </button>
                    </div>
                )}
            </div>

            {/* Info Card */}
            <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: '250px' }}>
                        <h3 style={{ marginBottom: '0.75rem', color: 'var(--accent-primary)' }}>
                            🔍 How It Works
                        </h3>
                        <ol style={{
                            paddingLeft: '1.25rem',
                            color: 'var(--text-secondary)',
                            fontSize: '0.9rem',
                            lineHeight: '1.8'
                        }}>
                            <li>Upload your OWASP Dependency-Check report</li>
                            <li>Optionally add your dependency manifest for better accuracy</li>
                            <li>Our system analyzes each vulnerability for reachability</li>
                            <li>False positives are identified with detailed reasoning</li>
                            <li>Generate an AI-powered report with remediation steps</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default FileUpload
