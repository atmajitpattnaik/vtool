import xml2js from 'xml2js';
import { mapCvssToSeverity } from '../utils/severityMapper.js';

/**
 * Parse OWASP Dependency-Check report (JSON or XML format)
 * @param {string} content - File content
 * @param {string} filename - Original filename for format detection
 * @returns {Object} Normalized vulnerability data
 */
export async function parseOwaspReport(content, filename) {
    try {
        const lowerName = filename.toLowerCase();
        const trimmed = content.trim();
        const isXml = lowerName.endsWith('.xml') || trimmed.startsWith('<?xml');
        const isHtml = lowerName.endsWith('.html') || lowerName.endsWith('.htm') || trimmed.toLowerCase().startsWith('<!doctype html') || trimmed.toLowerCase().startsWith('<html');

        if (isXml) {
            return await parseXmlReport(content);
        }

        if (isHtml) {
            return parseHtmlReport(content);
        }

        return parseJsonReport(content);
    } catch (err) {
        throw new Error(`Unable to parse OWASP report "${filename}": ${err.message}`);
    }
}

/**
 * Parse OWASP JSON report
 */
function parseJsonReport(content) {
    const data = JSON.parse(content);
    const vulnerabilities = [];

    // Handle different JSON structures
    const dependencies = data.dependencies || data.dependency || [];

    for (const dep of dependencies) {
        const depName = dep.fileName || dep.name || 'Unknown';
        const depVersion = extractVersion(dep);
        const vulns = dep.vulnerabilities || [];

        for (const vuln of vulns) {
            const cvssScore = extractCvssScore(vuln);

            vulnerabilities.push({
                cveId: vuln.name || vuln.cve || vuln.id || 'Unknown',
                dependency: depName,
                version: depVersion,
                reportedVersion: depVersion,
                cvssScore: cvssScore,
                severity: mapCvssToSeverity(cvssScore),
                description: vuln.description || '',
                references: extractReferences(vuln),
                source: vuln.source || 'NVD',
                vulnerableSoftware: vuln.vulnerableSoftware || [],
                filePath: dep.filePath || dep.path || ''
            });
        }
    }

    return {
        vulnerabilities,
        scanInfo: {
            reportDate: data.reportDate || data.scanInfo?.analysisTimestamp || new Date().toISOString(),
            engineVersion: data.version || data.scanInfo?.engineVersion || 'Unknown',
            dataSource: data.scanInfo?.dataSource || 'NVD'
        },
        projectInfo: {
            name: data.projectInfo?.name || 'Unknown Project',
            reportFormat: 'JSON'
        }
    };
}

/**
 * Parse OWASP XML report
 */
async function parseXmlReport(content) {
    const parser = new xml2js.Parser({
        explicitArray: false,
        ignoreAttrs: false,
        mergeAttrs: true
    });

    const data = await parser.parseStringPromise(content);
    const vulnerabilities = [];

    // Navigate XML structure
    const analysis = data.analysis || data;
    const dependencies = analysis.dependencies?.dependency || [];
    const depArray = Array.isArray(dependencies) ? dependencies : [dependencies];

    for (const dep of depArray) {
        if (!dep) continue;

        const depName = dep.fileName || dep.name || 'Unknown';
        const depVersion = extractVersionFromXml(dep);

        const vulns = dep.vulnerabilities?.vulnerability || [];
        const vulnArray = Array.isArray(vulns) ? vulns : [vulns];

        for (const vuln of vulnArray) {
            if (!vuln) continue;

            const cvssScore = extractCvssScoreFromXml(vuln);

            vulnerabilities.push({
                cveId: vuln.name || vuln.cve || 'Unknown',
                dependency: depName,
                version: depVersion,
                reportedVersion: depVersion,
                cvssScore: cvssScore,
                severity: mapCvssToSeverity(cvssScore),
                description: vuln.description || '',
                references: extractReferencesFromXml(vuln),
                source: vuln.source || 'NVD',
                vulnerableSoftware: extractVulnerableSoftwareFromXml(vuln),
                filePath: dep.filePath || ''
            });
        }
    }

    // Extract scan info
    const scanInfo = analysis.scanInfo || {};
    const projectInfo = analysis.projectInfo || {};

    return {
        vulnerabilities,
        scanInfo: {
            reportDate: scanInfo.analysisTimestamp || new Date().toISOString(),
            engineVersion: scanInfo.engineVersion || 'Unknown',
            dataSource: 'NVD'
        },
        projectInfo: {
            name: projectInfo.name || 'Unknown Project',
            reportFormat: 'XML'
        }
    };
}

/**
 * Parse OWASP HTML report (best-effort extraction)
 */
function parseHtmlReport(content) {
    const vulnerabilities = [];
    const cveRegex = /CVE-\d{4}-\d+/gi;
    const seen = new Set();
    let match;

    while ((match = cveRegex.exec(content)) !== null) {
        const cve = match[0].toUpperCase();
        if (seen.has(cve)) continue;
        seen.add(cve);
        vulnerabilities.push({
            cveId: cve,
            dependency: 'Unknown',
            version: 'Unknown',
            reportedVersion: 'Unknown',
            cvssScore: 0,
            severity: 'UNKNOWN',
            description: 'Parsed from HTML report; detailed fields unavailable in HTML export.',
            references: [],
            source: 'NVD',
            vulnerableSoftware: [],
            filePath: ''
        });
    }

    return {
        vulnerabilities,
        scanInfo: {
            reportDate: new Date().toISOString(),
            engineVersion: 'Unknown',
            dataSource: 'NVD'
        },
        projectInfo: {
            name: 'Unknown Project',
            reportFormat: 'HTML'
        }
    };
}

/**
 * Extract version from JSON dependency
 */
function extractVersion(dep) {
    if (dep.version) return dep.version;

    // Try to extract from filename
    const fileName = dep.fileName || dep.name || '';
    const versionMatch = fileName.match(/[-_](\d+\.\d+(?:\.\d+)?(?:[-.][\w.]+)?)/);
    return versionMatch ? versionMatch[1] : 'Unknown';
}

/**
 * Extract version from XML dependency
 */
function extractVersionFromXml(dep) {
    if (dep.version) return dep.version;

    // Check identifiers
    const identifiers = dep.identifiers?.identifier || [];
    const idArray = Array.isArray(identifiers) ? identifiers : [identifiers];

    for (const id of idArray) {
        if (id && id.name) {
            const versionMatch = id.name.match(/:(\d+\.\d+(?:\.\d+)?(?:[-.][\w.]+)?)/);
            if (versionMatch) return versionMatch[1];
        }
    }

    // Try filename
    const fileName = dep.fileName || '';
    const versionMatch = fileName.match(/[-_](\d+\.\d+(?:\.\d+)?(?:[-.][\w.]+)?)/);
    return versionMatch ? versionMatch[1] : 'Unknown';
}

/**
 * Extract CVSS score from JSON vulnerability
 */
function extractCvssScore(vuln) {
    // Try CVSSv3 first
    if (vuln.cvssv3?.baseScore) return parseFloat(vuln.cvssv3.baseScore);
    if (vuln.cvssV3?.baseScore) return parseFloat(vuln.cvssV3.baseScore);

    // Fall back to CVSSv2
    if (vuln.cvssv2?.score) return parseFloat(vuln.cvssv2.score);
    if (vuln.cvssV2?.score) return parseFloat(vuln.cvssV2.score);

    // Direct score
    if (vuln.cvssScore) return parseFloat(vuln.cvssScore);
    if (vuln.score) return parseFloat(vuln.score);

    return 0;
}

/**
 * Extract CVSS score from XML vulnerability
 */
function extractCvssScoreFromXml(vuln) {
    // Try CVSSv3 first
    if (vuln.cvssv3?.baseScore) return parseFloat(vuln.cvssv3.baseScore);
    if (vuln.cvssV3?.baseScore) return parseFloat(vuln.cvssV3.baseScore);

    // Fall back to CVSSv2
    if (vuln.cvssv2?.score) return parseFloat(vuln.cvssv2.score);
    if (vuln.cvssV2?.score) return parseFloat(vuln.cvssV2.score);

    // Check severity attribute
    if (vuln.severity) {
        const severityMap = { LOW: 3.0, MEDIUM: 5.5, HIGH: 8.0, CRITICAL: 9.5 };
        return severityMap[vuln.severity.toUpperCase()] || 5.0;
    }

    return 0;
}

/**
 * Extract references from JSON vulnerability
 */
function extractReferences(vuln) {
    const refs = vuln.references || [];
    if (Array.isArray(refs)) {
        return refs.map(r => r.url || r.source || r).filter(Boolean);
    }
    return [];
}

/**
 * Extract references from XML vulnerability
 */
function extractReferencesFromXml(vuln) {
    const refs = vuln.references?.reference || [];
    const refArray = Array.isArray(refs) ? refs : [refs];
    return refArray.map(r => r?.url || r?.source || r).filter(Boolean);
}

/**
 * Extract vulnerable software from XML
 */
function extractVulnerableSoftwareFromXml(vuln) {
    const software = vuln.vulnerableSoftware?.software || [];
    const softArray = Array.isArray(software) ? software : [software];
    return softArray.filter(Boolean);
}
