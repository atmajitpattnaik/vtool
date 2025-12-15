/**
 * Map CVSS score to severity level
 * @param {number} cvssScore - CVSS score (0.0 - 10.0)
 * @returns {string} Severity level: LOW, MEDIUM, HIGH, CRITICAL
 */
export function mapCvssToSeverity(cvssScore) {
    const score = parseFloat(cvssScore) || 0;

    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'UNKNOWN';
}

/**
 * Get severity color for UI display
 * @param {string} severity - Severity level
 * @returns {string} Hex color code
 */
export function getSeverityColor(severity) {
    const colors = {
        CRITICAL: '#dc2626', // Red
        HIGH: '#ea580c',     // Orange
        MEDIUM: '#ca8a04',   // Yellow
        LOW: '#16a34a',      // Green
        UNKNOWN: '#6b7280'   // Gray
    };

    return colors[severity?.toUpperCase()] || colors.UNKNOWN;
}

/**
 * Get severity weight for sorting
 * @param {string} severity - Severity level
 * @returns {number} Weight (higher = more severe)
 */
export function getSeverityWeight(severity) {
    const weights = {
        CRITICAL: 4,
        HIGH: 3,
        MEDIUM: 2,
        LOW: 1,
        UNKNOWN: 0
    };

    return weights[severity?.toUpperCase()] || 0;
}

/**
 * Sort vulnerabilities by severity (most severe first)
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {Array} Sorted array
 */
export function sortBySeverity(vulnerabilities) {
    return [...vulnerabilities].sort((a, b) => {
        const weightA = getSeverityWeight(a.severity);
        const weightB = getSeverityWeight(b.severity);

        if (weightB !== weightA) {
            return weightB - weightA;
        }

        // Secondary sort by CVSS score
        const scoreA = parseFloat(a.cvssScore ?? a.cvss_score ?? 0);
        const scoreB = parseFloat(b.cvssScore ?? b.cvss_score ?? 0);
        return scoreB - scoreA;
    });
}
