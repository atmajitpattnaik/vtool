import xml2js from 'xml2js';

/**
 * Parse dependency manifest file
 * Supports: package.json, pom.xml, requirements.txt
 * @param {string} content - File content
 * @param {string} filename - Original filename for format detection
 * @returns {Object} Normalized dependency data
 */
export async function parseManifest(content, filename) {
    const lowerFilename = filename.toLowerCase();
    try {
        if (lowerFilename.includes('package.json') || lowerFilename.endsWith('.json')) {
            return parsePackageJson(content);
        } else if (lowerFilename.includes('pom.xml') || lowerFilename.endsWith('.xml')) {
            return parsePomXml(content);
        } else if (lowerFilename.includes('requirements') || lowerFilename.endsWith('.txt')) {
            return parseRequirementsTxt(content);
        } else {
            // Try to auto-detect
            if (content.trim().startsWith('{')) {
                return parsePackageJson(content);
            } else if (content.trim().startsWith('<?xml') || content.includes('<project')) {
                return parsePomXml(content);
            } else {
                return parseRequirementsTxt(content);
            }
        }
    } catch (err) {
        throw new Error(`Unable to parse manifest "${filename}": ${err.message}`);
    }
}

/**
 * Parse npm/Node.js package.json
 */
function parsePackageJson(content) {
    const data = JSON.parse(content);

    const dependencies = {};
    const devDependencies = {};
    const allDependencies = {};

    // Parse production dependencies
    if (data.dependencies) {
        for (const [name, version] of Object.entries(data.dependencies)) {
            const cleanVersion = cleanVersionString(version);
            dependencies[name] = cleanVersion;
            allDependencies[name] = { version: cleanVersion, isDev: false, isOptional: false };
        }
    }

    // Parse dev dependencies
    if (data.devDependencies) {
        for (const [name, version] of Object.entries(data.devDependencies)) {
            const cleanVersion = cleanVersionString(version);
            devDependencies[name] = cleanVersion;
            allDependencies[name] = { version: cleanVersion, isDev: true, isOptional: false };
        }
    }

    // Parse optional dependencies
    if (data.optionalDependencies) {
        for (const [name, version] of Object.entries(data.optionalDependencies)) {
            const cleanVersion = cleanVersionString(version);
            if (!allDependencies[name]) {
                allDependencies[name] = { version: cleanVersion, isDev: false, isOptional: true };
            } else {
                allDependencies[name].isOptional = true;
            }
        }
    }

    // Parse peer dependencies
    if (data.peerDependencies) {
        for (const [name, version] of Object.entries(data.peerDependencies)) {
            const cleanVersion = cleanVersionString(version);
            if (!allDependencies[name]) {
                allDependencies[name] = { version: cleanVersion, isDev: false, isOptional: false, isPeer: true };
            } else {
                allDependencies[name].isPeer = true;
            }
        }
    }

    return {
        name: data.name || 'Unknown Project',
        version: data.version || '0.0.0',
        type: 'npm',
        dependencies: allDependencies,
        productionDependencies: dependencies,
        devDependencies: devDependencies,
        scripts: data.scripts || {},
        engines: data.engines || {}
    };
}

/**
 * Parse Maven pom.xml
 */
async function parsePomXml(content) {
    const parser = new xml2js.Parser({
        explicitArray: false,
        ignoreAttrs: false,
        mergeAttrs: true
    });

    const data = await parser.parseStringPromise(content);
    const project = data.project || data;

    const dependencies = {};
    const allDependencies = {};

    // Parse dependencies
    const deps = project.dependencies?.dependency || [];
    const depArray = Array.isArray(deps) ? deps : [deps];

    for (const dep of depArray) {
        if (!dep) continue;

        const groupId = dep.groupId || '';
        const artifactId = dep.artifactId || '';
        const version = dep.version || 'Unknown';
        const scope = dep.scope || 'compile';

        const name = `${groupId}:${artifactId}`;
        const cleanVersion = cleanVersionString(version);

        dependencies[name] = cleanVersion;
        allDependencies[name] = {
            version: cleanVersion,
            isDev: scope === 'test' || scope === 'provided',
            isOptional: dep.optional === 'true',
            scope: scope,
            groupId,
            artifactId
        };
    }

    // Parse dependency management
    const managedDeps = project.dependencyManagement?.dependencies?.dependency || [];
    const managedArray = Array.isArray(managedDeps) ? managedDeps : [managedDeps];

    for (const dep of managedArray) {
        if (!dep) continue;

        const groupId = dep.groupId || '';
        const artifactId = dep.artifactId || '';
        const version = dep.version || 'Unknown';
        const name = `${groupId}:${artifactId}`;

        if (!allDependencies[name]) {
            allDependencies[name] = {
                version: cleanVersionString(version),
                isDev: false,
                isOptional: false,
                isManaged: true,
                groupId,
                artifactId
            };
        }
    }

    return {
        name: project.artifactId || project.name || 'Unknown Project',
        version: project.version || '0.0.0',
        type: 'maven',
        groupId: project.groupId || '',
        dependencies: allDependencies,
        productionDependencies: dependencies,
        devDependencies: {},
        parent: project.parent ? {
            groupId: project.parent.groupId,
            artifactId: project.parent.artifactId,
            version: project.parent.version
        } : null
    };
}

/**
 * Parse Python requirements.txt
 */
function parseRequirementsTxt(content) {
    const lines = content.split('\n');
    const dependencies = {};
    const allDependencies = {};

    for (const line of lines) {
        const trimmedLine = line.trim();

        // Skip empty lines and comments
        if (!trimmedLine || trimmedLine.startsWith('#') || trimmedLine.startsWith('-')) {
            continue;
        }

        // Parse package==version, package>=version, package~=version, etc.
        const match = trimmedLine.match(/^([a-zA-Z0-9_-]+)(?:\[.*?\])?(?:([<>=!~]+)(.+))?$/);

        if (match) {
            const name = match[1].toLowerCase();
            const operator = match[2] || '';
            const version = match[3] ? match[3].trim() : 'Any';

            dependencies[name] = version;
            allDependencies[name] = {
                version: version,
                isDev: false,
                isOptional: false,
                versionOperator: operator
            };
        }
    }

    return {
        name: 'Python Project',
        version: '0.0.0',
        type: 'pip',
        dependencies: allDependencies,
        productionDependencies: dependencies,
        devDependencies: {}
    };
}

/**
 * Clean version string (remove ^, ~, >=, etc.)
 */
function cleanVersionString(version) {
    if (!version || typeof version !== 'string') return 'Unknown';

    // Remove common version prefixes
    return version
        .replace(/^[\^~>=<]+/, '')
        .replace(/\s+/g, '')
        .trim();
}

/**
 * Normalize package name for comparison
 */
export function normalizePackageName(name) {
    if (!name) return '';

    return name
        .toLowerCase()
        .replace(/[_-]/g, '')
        .replace(/@[\w/-]+\//, '') // Remove npm scopes
        .trim();
}

/**
 * Check if two version strings match
 */
export function versionsMatch(version1, version2) {
    if (!version1 || !version2) return false;

    const clean1 = cleanVersionString(version1);
    const clean2 = cleanVersionString(version2);

    return clean1 === clean2 ||
        clean1.startsWith(clean2) ||
        clean2.startsWith(clean1);
}
