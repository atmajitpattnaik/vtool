import { normalizePackageName } from '../parsers/manifestParser.js';

/**
 * Analyze reachability of vulnerable dependencies
 * Uses heuristic-based analysis to determine if vulnerable code paths are reachable
 * @param {Object} owaspData - Parsed OWASP report data
 * @param {Object} manifestData - Parsed dependency manifest data
 * @returns {Object} Reachability analysis results
 */
export async function analyzeReachability(owaspData, manifestData, callGraph = null) {
    const results = {
        directDependencies: [],
        transitiveDependencies: [],
        unreachableDependencies: [],
        reachabilityMap: {}
    };

    if (!manifestData) {
        // Without manifest, lean on call graph or path heuristics
        for (const vuln of owaspData.vulnerabilities) {
            const callGraphResult = assessCallGraphReachability(vuln, callGraph);
            const pathClassification = classifyPath(vuln.filePath);

            results.reachabilityMap[vuln.cveId] = {
                isReachable: callGraphResult?.isReachable ?? true,
                confidence: callGraphResult?.confidence || (pathClassification === 'non_prod' ? 'MEDIUM' : 'LOW'),
                reason: callGraphResult?.reason || (pathClassification === 'non_prod'
                    ? 'Vulnerability exists in non-production/test/example path'
                    : 'No manifest provided - reachability assumed'),
                isDirect: null,
                isDevDependency: null,
                pathClassification,
                callGraphEvidence: callGraphResult?.evidence || null
            };

            if (pathClassification === 'non_prod') {
                results.unreachableDependencies.push(vuln.dependency);
            }
        }
        return results;
    }

    const manifestDeps = manifestData.dependencies || {};
    const prodDeps = manifestData.productionDependencies || {};
    const devDeps = manifestData.devDependencies || {};

    for (const vuln of owaspData.vulnerabilities) {
        const depName = extractPackageName(vuln.dependency);

        // Check if dependency is in manifest
        const directMatch = findDependencyMatch(depName, manifestDeps);
        const prodMatch = findDependencyMatch(depName, prodDeps);
        const devMatch = findDependencyMatch(depName, devDeps);

        let reachabilityInfo = {
            isReachable: true,
            confidence: 'MEDIUM',
            reason: 'No reachability blockers detected',
            isDirect: false,
            isDevDependency: false,
            matchedDependency: null,
            callGraphEvidence: null,
            pathClassification: classifyPath(vuln.filePath)
        };

        if (directMatch) {
            reachabilityInfo.isDirect = true;
            reachabilityInfo.matchedDependency = directMatch.name;
            reachabilityInfo.actualVersion = directMatch.version;
        }

        // Call graph evidence (if provided)
        const callGraphResult = assessCallGraphReachability(vuln, callGraph);
        if (callGraphResult) {
            reachabilityInfo.callGraphEvidence = callGraphResult.evidence;
            reachabilityInfo.isReachable = callGraphResult.isReachable;
            reachabilityInfo.confidence = callGraphResult.confidence;
            reachabilityInfo.reason = callGraphResult.reason;
        }

        // Dev-only check
        if (devMatch && !prodMatch) {
            reachabilityInfo.isDevDependency = true;
            reachabilityInfo.isReachable = false;
            reachabilityInfo.confidence = 'HIGH';
            reachabilityInfo.reason = 'Development-only dependency - not included in production builds';
            results.unreachableDependencies.push(vuln.dependency);
        }

        // Direct production dependency
        if (!devMatch && prodMatch) {
            reachabilityInfo.isReachable = true;
            reachabilityInfo.confidence = 'HIGH';
            reachabilityInfo.reason = 'Direct production dependency - code is reachable';
            results.directDependencies.push(vuln.dependency);
        }

        // Non-direct dependency heuristic
        if (!directMatch) {
            reachabilityInfo.isDirect = false;
            reachabilityInfo.reason = 'Transitive dependency - may or may not be reachable';
            reachabilityInfo.isReachable = true;
            results.transitiveDependencies.push(vuln.dependency);
        }

        // Non-production/test paths reduce reachability
        if (reachabilityInfo.pathClassification === 'non_prod') {
            reachabilityInfo.isReachable = false;
            reachabilityInfo.confidence = 'HIGH';
            reachabilityInfo.reason = 'Vulnerability exists in non-production/test/example path';
            results.unreachableDependencies.push(vuln.dependency);
        }

        // Optional dependency not wired for production
        if (directMatch?.info?.isOptional && !prodMatch) {
            reachabilityInfo.isReachable = false;
            reachabilityInfo.confidence = 'MEDIUM';
            reachabilityInfo.reason = 'Optional dependency not included in production runtime';
            results.unreachableDependencies.push(vuln.dependency);
        }

        results.reachabilityMap[vuln.cveId] = reachabilityInfo;
    }

    return results;
}

/**
 * Classify file path to determine if it belongs to production or non-production code
 */
function classifyPath(filePath = '') {
    if (!filePath) return 'unknown';
    const lowered = filePath.toLowerCase();
    const nonProdMarkers = ['test', '__tests__', 'spec', '__mocks__', 'example', 'examples', 'demo', 'sample', 'fixture'];
    const isNonProd = nonProdMarkers.some(marker =>
        lowered.includes(`/${marker}/`) ||
        lowered.includes(`\\${marker}\\`) ||
        lowered.endsWith(`/${marker}`) ||
        lowered.endsWith(`\\${marker}`)
    );
    return isNonProd ? 'non_prod' : 'prod';
}

/**
 * Inspect optional call graph payload to decide reachability
 */
function assessCallGraphReachability(vuln, callGraph) {
    if (!callGraph || typeof callGraph !== 'object') return null;

    const dependencyName = extractPackageName(vuln.dependency);
    const normalized = normalizePackageName(dependencyName);
    const nodes = callGraph.nodes || callGraph.functions || [];
    const edges = callGraph.edges || callGraph.calls || [];

    const referencedByNode = nodes.some(node =>
        normalizePackageName(node.name || node.id || '') === normalized
    );

    const referencedByEdge = edges.some(edge => {
        const from = normalizePackageName(edge.from || edge.source || '');
        const to = normalizePackageName(edge.to || edge.target || '');
        return from.includes(normalized) || to.includes(normalized);
    });

    if (!referencedByNode && !referencedByEdge) {
        return {
            isReachable: false,
            confidence: 'HIGH',
            reason: 'Call graph analysis: no invocation path to the vulnerable component',
            evidence: 'No call graph nodes or edges reference this dependency'
        };
    }

    return {
        isReachable: true,
        confidence: referencedByEdge ? 'HIGH' : 'MEDIUM',
        reason: 'Call graph analysis: vulnerable component is referenced in application call graph',
        evidence: 'Call graph contains references to the vulnerable component'
    };
}

/**
 * Extract package name from dependency string
 * Handles formats like: "lodash-4.17.21.jar", "package-name@version", "groupId:artifactId"
 */
function extractPackageName(dependency) {
    if (!dependency) return '';

    // Remove file extension
    let name = dependency.replace(/\.(jar|war|zip|tar\.gz|tgz|whl|egg)$/i, '');

    // Handle Maven format (groupId:artifactId:version)
    if (name.includes(':')) {
        const parts = name.split(':');
        if (parts.length >= 2) {
            return parts[1]; // Return artifactId
        }
    }

    // Handle npm @ format
    if (name.includes('@') && !name.startsWith('@')) {
        name = name.split('@')[0];
    }

    // Handle scoped packages (@scope/package)
    if (name.startsWith('@')) {
        const atIndex = name.indexOf('@', 1);
        if (atIndex > 0) {
            name = name.substring(0, atIndex);
        }
    }

    // Remove version suffix (package-1.2.3 -> package)
    const versionPattern = /-\d+\.\d+(\.\d+)?([.-][\w.]+)?$/;
    name = name.replace(versionPattern, '');

    return name;
}

/**
 * Find matching dependency in manifest
 */
function findDependencyMatch(depName, manifestDeps) {
    if (!depName || !manifestDeps) return null;

    const normalizedSearch = normalizePackageName(depName);

    for (const [name, info] of Object.entries(manifestDeps)) {
        const normalizedName = normalizePackageName(name);

        // Exact match
        if (normalizedName === normalizedSearch) {
            return {
                name,
                version: typeof info === 'object' ? info.version : info,
                info
            };
        }

        // Partial match (for cases like "lodash" matching "lodash.merge")
        if (normalizedName.includes(normalizedSearch) || normalizedSearch.includes(normalizedName)) {
            return {
                name,
                version: typeof info === 'object' ? info.version : info,
                info,
                partialMatch: true
            };
        }
    }

    return null;
}

/**
 * Check if a dependency is used in production
 * @param {string} depName - Dependency name
 * @param {Object} manifestData - Manifest data
 * @returns {boolean}
 */
export function isProductionDependency(depName, manifestData) {
    if (!manifestData) return true; // Assume production if no manifest

    const prodDeps = manifestData.productionDependencies || {};
    const match = findDependencyMatch(depName, prodDeps);

    return match !== null;
}

/**
 * Get reachability score (0-100)
 * Higher score = more likely reachable
 */
export function getReachabilityScore(reachabilityInfo) {
    if (!reachabilityInfo) return 50;

    let score = 50; // Base score

    if (reachabilityInfo.isDirect) score += 30;
    if (!reachabilityInfo.isDevDependency) score += 15;
    if (reachabilityInfo.confidence === 'HIGH') score += 5;

    return Math.min(100, Math.max(0, score));
}
