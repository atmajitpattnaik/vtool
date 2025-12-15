import { normalizePackageName, versionsMatch } from '../parsers/manifestParser.js';

/**
 * False positive reason codes
 */
export const FalsePositiveReasons = {
    VERSION_MISMATCH: 'VERSION_MISMATCH',
    NON_REACHABLE: 'NON_REACHABLE',
    ENV_MISMATCH: 'ENV_MISMATCH',
    UNUSED_TRANSITIVE: 'UNUSED_TRANSITIVE',
    DEV_ONLY: 'DEV_ONLY'
};

/**
 * Human-readable descriptions for false positive reasons
 */
const ReasonDescriptions = {
    VERSION_MISMATCH: 'The reported vulnerable version does not match the actual installed version',
    NON_REACHABLE: 'The vulnerable code path is not reachable from the application',
    ENV_MISMATCH: 'The vulnerability only affects environments or configurations not used by this project',
    UNUSED_TRANSITIVE: 'This is a transitive dependency that is not actually used by the application',
    DEV_ONLY: 'This dependency is only used in development and not included in production builds'
};

/**
 * Detect false positives in vulnerability findings
 * @param {Object} owaspData - Parsed OWASP report data
 * @param {Object} manifestData - Parsed dependency manifest data
 * @param {Object} reachabilityResults - Results from reachability analysis
 * @returns {Array} Array of false positive findings
 */
export async function detectFalsePositives(owaspData, manifestData, reachabilityResults) {
    const falsePositives = [];

    for (const vuln of owaspData.vulnerabilities) {
        const fpResult = analyzeVulnerability(vuln, manifestData, reachabilityResults);

        if (fpResult.isFalsePositive) {
            falsePositives.push({
                cve_id: vuln.cveId,
                dependency: formatDependency(vuln.dependency, vuln.version),
                reason: fpResult.reason,
                details: fpResult.details,
                confidence: fpResult.confidence,
                originalVuln: vuln
            });
        }
    }

    return falsePositives;
}

/**
 * Analyze a single vulnerability for false positive indicators
 */
function analyzeVulnerability(vuln, manifestData, reachabilityResults) {
    const result = {
        isFalsePositive: false,
        reason: null,
        details: '',
        confidence: 'LOW'
    };

    // Check 1: Version mismatch
    const versionCheck = checkVersionMismatch(vuln, manifestData);
    if (versionCheck.isFalsePositive) {
        return versionCheck;
    }

    // Check 2: Environment mismatch
    const envCheck = checkEnvironmentMismatch(vuln, manifestData);
    if (envCheck.isFalsePositive) {
        return envCheck;
    }

    // Check 2: Development-only dependency
    const devCheck = checkDevOnlyDependency(vuln, manifestData, reachabilityResults);
    if (devCheck.isFalsePositive) {
        return devCheck;
    }

    // Check 3: Non-reachable dependency
    const reachabilityCheck = checkReachability(vuln, reachabilityResults);
    if (reachabilityCheck.isFalsePositive) {
        return reachabilityCheck;
    }

    // Check 4: Unused transitive dependency
    const transitiveCheck = checkUnusedTransitive(vuln, manifestData, reachabilityResults);
    if (transitiveCheck.isFalsePositive) {
        return transitiveCheck;
    }

    return result;
}

/**
 * Check for version mismatch between reported and actual versions
 */
function checkVersionMismatch(vuln, manifestData) {
    const result = {
        isFalsePositive: false,
        reason: FalsePositiveReasons.VERSION_MISMATCH,
        details: '',
        confidence: 'LOW'
    };

    if (!manifestData) return result;

    const depName = extractPackageName(vuln.dependency);
    const manifestDeps = manifestData.dependencies || {};

    // Find the dependency in manifest
    for (const [name, info] of Object.entries(manifestDeps)) {
        if (normalizePackageName(name) === normalizePackageName(depName)) {
            const actualVersion = typeof info === 'object' ? info.version : info;
            const reportedVersion = vuln.version || vuln.reportedVersion;

            if (actualVersion && reportedVersion && !versionsMatch(actualVersion, reportedVersion)) {
                // Check if actual version is higher (likely patched)
                if (isHigherVersion(actualVersion, reportedVersion)) {
                    result.isFalsePositive = true;
                    result.confidence = 'HIGH';
                    result.details = `Actual installed version (${actualVersion}) is newer than the reported vulnerable version (${reportedVersion}). The vulnerability may have been patched.`;
                } else {
                    result.isFalsePositive = true;
                    result.confidence = 'MEDIUM';
                    result.details = `Version mismatch: OWASP reported ${reportedVersion}, but manifest shows ${actualVersion}.`;
                }
                return result;
            }
        }
    }

    return result;
}

/**
 * Check whether the vulnerability only affects an environment different from the current/project environment
 */
function checkEnvironmentMismatch(vuln, manifestData) {
    const result = {
        isFalsePositive: false,
        reason: FalsePositiveReasons.ENV_MISMATCH,
        details: '',
        confidence: 'LOW'
    };

    const description = (vuln.description || '').toLowerCase();
    const runtimePlatform = process.platform;

    const envSignals = [
        { keyword: 'windows', platforms: ['win32'] },
        { keyword: 'macos', platforms: ['darwin'] },
        { keyword: 'os x', platforms: ['darwin'] },
        { keyword: 'linux', platforms: ['linux'] },
        { keyword: 'android', platforms: ['android'] },
        { keyword: 'ios', platforms: ['ios'] }
    ];

    for (const signal of envSignals) {
        if (description.includes(signal.keyword)) {
            const matchesPlatform = signal.platforms.includes(runtimePlatform);
            if (!matchesPlatform) {
                result.isFalsePositive = true;
                result.confidence = 'MEDIUM';
                result.details = `Vulnerability is described as affecting ${signal.keyword} environments, but the current runtime platform is ${runtimePlatform}.`;
                return result;
            }
        }
    }

    // Language/runtime checks based on manifest type
    const manifestType = manifestData?.type;
    if (manifestType === 'npm' && description.includes('python')) {
        result.isFalsePositive = true;
        result.confidence = 'MEDIUM';
        result.details = 'Vulnerability targets Python environments, but the project manifest indicates a Node.js application.';
    }

    if (manifestType === 'pip' && description.includes('node')) {
        result.isFalsePositive = true;
        result.confidence = 'MEDIUM';
        result.details = 'Vulnerability targets Node.js environments, but the project manifest indicates a Python application.';
    }

    if (manifestType === 'maven' && description.includes('node')) {
        result.isFalsePositive = true;
        result.confidence = 'MEDIUM';
        result.details = 'Vulnerability targets Node.js ecosystems, but the project manifest indicates a JVM application.';
    }

    return result;
}

/**
 * Check if dependency is development-only
 */
function checkDevOnlyDependency(vuln, manifestData, reachabilityResults) {
    const result = {
        isFalsePositive: false,
        reason: FalsePositiveReasons.DEV_ONLY,
        details: '',
        confidence: 'LOW'
    };

    if (!manifestData) return result;

    const reachInfo = reachabilityResults?.reachabilityMap?.[vuln.cveId];

    if (reachInfo?.isDevDependency) {
        result.isFalsePositive = true;
        result.confidence = 'HIGH';
        result.details = `${vuln.dependency} is listed as a devDependency and is not included in production builds. This vulnerability does not affect production deployments.`;
        return result;
    }

    // Also check manifest directly
    const depName = extractPackageName(vuln.dependency);
    const devDeps = manifestData.devDependencies || {};
    const prodDeps = manifestData.productionDependencies || {};

    const isInDev = Object.keys(devDeps).some(name =>
        normalizePackageName(name) === normalizePackageName(depName)
    );
    const isInProd = Object.keys(prodDeps).some(name =>
        normalizePackageName(name) === normalizePackageName(depName)
    );

    if (isInDev && !isInProd) {
        result.isFalsePositive = true;
        result.confidence = 'HIGH';
        result.details = `${depName} is only listed in devDependencies. This vulnerability does not affect production deployments.`;
    }

    return result;
}

/**
 * Check reachability from analysis results
 */
function checkReachability(vuln, reachabilityResults) {
    const result = {
        isFalsePositive: false,
        reason: FalsePositiveReasons.NON_REACHABLE,
        details: '',
        confidence: 'LOW'
    };

    const reachInfo = reachabilityResults?.reachabilityMap?.[vuln.cveId];

    if (reachInfo && !reachInfo.isReachable) {
        result.isFalsePositive = true;
        result.confidence = reachInfo.confidence;
        result.details = reachInfo.reason || ReasonDescriptions.NON_REACHABLE;
    }

    return result;
}

/**
 * Check for unused transitive dependencies
 */
function checkUnusedTransitive(vuln, manifestData, reachabilityResults) {
    const result = {
        isFalsePositive: false,
        reason: FalsePositiveReasons.UNUSED_TRANSITIVE,
        details: '',
        confidence: 'LOW'
    };

    if (!manifestData) return result;

    const reachInfo = reachabilityResults?.reachabilityMap?.[vuln.cveId];

    // If it's not a direct dependency and we have low confidence it's used
    if (reachInfo && !reachInfo.isDirect && reachInfo.confidence !== 'HIGH') {
        const depName = extractPackageName(vuln.dependency);
        const allDeps = manifestData.dependencies || {};

        // Check if it's in the manifest at all
        const isInManifest = Object.keys(allDeps).some(name =>
            normalizePackageName(name) === normalizePackageName(depName)
        );

        if (!isInManifest) {
            result.isFalsePositive = true;
            result.confidence = 'MEDIUM';
            result.details = `${depName} is a transitive dependency not directly declared in the project. It may be pulled in by another dependency but might not be actively used.`;
        }
    }

    return result;
}

/**
 * Extract package name from dependency string
 */
function extractPackageName(dependency) {
    if (!dependency) return '';

    let name = dependency.replace(/\.(jar|war|zip|tar\.gz|tgz|whl|egg)$/i, '');

    if (name.includes(':')) {
        const parts = name.split(':');
        if (parts.length >= 2) return parts[1];
    }

    if (name.includes('@') && !name.startsWith('@')) {
        name = name.split('@')[0];
    }

    const versionPattern = /-\d+\.\d+(\.\d+)?([.-][\w.]+)?$/;
    name = name.replace(versionPattern, '');

    return name;
}

/**
 * Format dependency with version
 */
function formatDependency(dependency, version) {
    if (version && version !== 'Unknown') {
        return `${dependency}@${version}`;
    }
    return dependency;
}

/**
 * Compare versions to check if v1 is higher than v2
 */
function isHigherVersion(v1, v2) {
    if (!v1 || !v2) return false;

    const parts1 = v1.split('.').map(p => parseInt(p.replace(/\D/g, '')) || 0);
    const parts2 = v2.split('.').map(p => parseInt(p.replace(/\D/g, '')) || 0);

    const maxLen = Math.max(parts1.length, parts2.length);

    for (let i = 0; i < maxLen; i++) {
        const p1 = parts1[i] || 0;
        const p2 = parts2[i] || 0;

        if (p1 > p2) return true;
        if (p1 < p2) return false;
    }

    return false;
}
