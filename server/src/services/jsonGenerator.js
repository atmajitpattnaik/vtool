/**
 * Generate JSON output following the defined schema
 * @param {Array} falsePositives - Array of false positive findings
 * @param {Array} trueVulnerabilities - Array of true vulnerabilities
 * @param {Object} metadata - Analysis metadata
 * @returns {Object} Structured JSON output
 */
export function generateJsonOutput(falsePositives, trueVulnerabilities, metadata = {}) {
    const enrichedMetadata = {
        analysis_timestamp: new Date().toISOString(),
        project_name: metadata.projectName || 'Unknown Project',
        tool_version: '1.0.0',
        owasp_report_name: metadata.owaspReportName || 'Unknown',
        total_vulnerabilities_scanned: falsePositives.length + trueVulnerabilities.length,
        false_positives_identified: falsePositives.length,
        true_vulnerabilities_found: trueVulnerabilities.length
    };

    const output = {
        false_positives: formatFalsePositives(falsePositives),
        true_vulnerabilities: formatTrueVulnerabilities(trueVulnerabilities),
        metadata: enrichedMetadata,
        analysis_metadata: enrichedMetadata,
        summary: generateSummary(falsePositives, trueVulnerabilities)
    };

    return output;
}

/**
 * Format false positives for output
 */
function formatFalsePositives(falsePositives) {
    return falsePositives.map(fp => ({
        cve_id: fp.cve_id,
        dependency: fp.dependency,
        reason: fp.reason,
        details: fp.details,
        confidence: fp.confidence
    }));
}

/**
 * Format true vulnerabilities for output
 */
function formatTrueVulnerabilities(vulnerabilities) {
    return vulnerabilities.map(vuln => ({
        cve_id: vuln.cve_id,
        dependency: vuln.dependency,
        severity: vuln.severity,
        cvss_score: vuln.cvss_score,
        description: vuln.description,
        recommended_fix: vuln.recommended_fix,
        references: vuln.references?.slice(0, 3) || [], // Limit references
        affected_versions: vuln.affected_versions || []
    }));
}

/**
 * Generate analysis summary
 */
function generateSummary(falsePositives, trueVulnerabilities) {
    const severityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };

    for (const vuln of trueVulnerabilities) {
        const severity = (vuln.severity || 'low').toLowerCase();
        if (severityCounts.hasOwnProperty(severity)) {
            severityCounts[severity]++;
        }
    }

    const fpReasonCounts = {};
    for (const fp of falsePositives) {
        const reason = fp.reason || 'UNKNOWN';
        fpReasonCounts[reason] = (fpReasonCounts[reason] || 0) + 1;
    }

    return {
        total_scanned: falsePositives.length + trueVulnerabilities.length,
        false_positive_rate: calculateFpRate(falsePositives.length, trueVulnerabilities.length),
        severity_breakdown: severityCounts,
        false_positive_reasons: fpReasonCounts,
        risk_score: calculateRiskScore(trueVulnerabilities),
        requires_immediate_action: severityCounts.critical > 0 || severityCounts.high > 0
    };
}

/**
 * Calculate false positive rate as percentage
 */
function calculateFpRate(fpCount, trueCount) {
    const total = fpCount + trueCount;
    if (total === 0) return 0;
    return Math.round((fpCount / total) * 100);
}

/**
 * Calculate overall risk score (0-100)
 */
function calculateRiskScore(vulnerabilities) {
    if (vulnerabilities.length === 0) return 0;

    let score = 0;
    const weights = {
        CRITICAL: 25,
        HIGH: 15,
        MEDIUM: 5,
        LOW: 1
    };

    for (const vuln of vulnerabilities) {
        const severity = (vuln.severity || 'LOW').toUpperCase();
        score += weights[severity] || 1;
    }

    // Cap at 100
    return Math.min(100, score);
}

/**
 * Validate JSON output against schema
 * @param {Object} output - Generated JSON output
 * @returns {Object} Validation result
 */
export function validateJsonOutput(output) {
    const errors = [];

    // Check required fields
    if (!output.false_positives || !Array.isArray(output.false_positives)) {
        errors.push('Missing or invalid false_positives array');
    }

    if (!output.true_vulnerabilities || !Array.isArray(output.true_vulnerabilities)) {
        errors.push('Missing or invalid true_vulnerabilities array');
    }

    if (!output.metadata) {
        errors.push('Missing metadata object');
    } else {
        if (!output.metadata.analysis_timestamp) {
            errors.push('Missing analysis_timestamp in metadata');
        }
        if (!output.metadata.project_name) {
            errors.push('Missing project_name in metadata');
        }
    }

    // Validate false positives structure
    for (const fp of output.false_positives || []) {
        if (!fp.cve_id) errors.push(`False positive missing cve_id`);
        if (!fp.dependency) errors.push(`False positive missing dependency`);
        if (!fp.reason) errors.push(`False positive missing reason`);
    }

    // Validate vulnerabilities structure
    for (const vuln of output.true_vulnerabilities || []) {
        if (!vuln.cve_id) errors.push(`Vulnerability missing cve_id`);
        if (!vuln.dependency) errors.push(`Vulnerability missing dependency`);
        if (!vuln.severity) errors.push(`Vulnerability missing severity`);
    }

    return {
        valid: errors.length === 0,
        errors
    };
}
