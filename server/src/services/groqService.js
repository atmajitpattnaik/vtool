import Groq from 'groq-sdk';

// Initialize Groq client
let groqClient = null;

function getGroqClient() {
    if (!groqClient) {
        const apiKey = (process.env.GROQ_API_KEY || '').trim();
        console.log('🔑 GROQ API Key check:', apiKey ? `Found (starts with ${apiKey.substring(0, 8)}...)` : 'NOT FOUND');

        if (!apiKey || apiKey === 'your_groq_api_key_here' || !apiKey.startsWith('gsk_')) {
            throw new Error('GROQ_API_KEY is not configured. Please set a valid API key in .env file.');
        }

        groqClient = new Groq({ apiKey });
    }

    return groqClient;
}

/**
 * Generate human-readable report using Groq LLM
 * @param {Object} analysisJson - The analysis JSON output
 * @returns {Object} Formatted report with sections
 */
export async function generateLLMReport(analysisJson) {
    const client = getGroqClient();

    const prompt = buildPrompt(analysisJson);

    let lastError = null;
    const maxRetries = 3;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const completion = await client.chat.completions.create({
                model: 'llama-3.3-70b-versatile',
                messages: [
                    {
                        role: 'system',
                        content: getSystemPrompt()
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.3,
                max_tokens: 4000,
                top_p: 1
            });

            const responseContent = completion.choices[0]?.message?.content;

            if (!responseContent) {
                throw new Error('Empty response from Groq API');
            }

            return {
                content: responseContent,
                model: 'llama-3.3-70b-versatile',
                generated_at: new Date().toISOString(),
                tokens_used: completion.usage?.total_tokens || 0
            };

        } catch (error) {
            lastError = error;
            console.error(`Groq API attempt ${attempt} failed:`, error.message);

            if (attempt < maxRetries) {
                // Exponential backoff
                const delay = Math.pow(2, attempt) * 1000;
                console.log(`Retrying in ${delay}ms...`);
                await sleep(delay);
            }
        }
    }

    // If all retries failed, return a fallback report
    console.error('All Groq API attempts failed, generating fallback report');
    return generateFallbackReport(analysisJson, lastError);
}

/**
 * Build the prompt for the LLM
 */
function buildPrompt(analysisJson) {
    return `
Analyze the following vulnerability scan results and generate a comprehensive security report.

## Analysis Data

### Summary
- Total vulnerabilities scanned: ${analysisJson.metadata?.total_vulnerabilities_scanned || 0}
- False positives identified: ${analysisJson.metadata?.false_positives_identified || 0}
- True vulnerabilities found: ${analysisJson.metadata?.true_vulnerabilities_found || 0}
- Project: ${analysisJson.metadata?.project_name || 'Unknown'}
- Analysis timestamp: ${analysisJson.metadata?.analysis_timestamp || 'Unknown'}

### False Positives (${analysisJson.false_positives?.length || 0} items)
${formatFalsePositivesForPrompt(analysisJson.false_positives || [])}

### True Vulnerabilities (${analysisJson.true_vulnerabilities?.length || 0} items)
${formatVulnerabilitiesForPrompt(analysisJson.true_vulnerabilities || [])}

### Risk Summary
${JSON.stringify(analysisJson.summary || {}, null, 2)}

Please generate a report with the following sections:
1. Executive Summary - A brief overview suitable for management
2. False Positives Table - Showing which vulnerabilities were identified as false positives and why
3. Actual Vulnerabilities Table - Showing real vulnerabilities with severity, CVSS score, and description
4. Remediation Recommendations - Prioritized list of actions to address the vulnerabilities
5. Risk Assessment - Overall risk posture and recommendations

Format the tables in markdown format for easy reading.
`;
}

/**
 * Get the system prompt for the LLM
 */
function getSystemPrompt() {
    return `You are a senior security analyst generating vulnerability assessment reports. Your reports should be:
- Clear and actionable
- Properly prioritized by severity
- Include specific remediation steps
- Professional in tone
- Well-formatted with markdown tables and headers

When presenting vulnerabilities:
- Group by severity (CRITICAL first, then HIGH, MEDIUM, LOW)
- Include CVE IDs for reference
- Provide clear upgrade paths when available

For false positives:
- Explain why each was classified as a false positive
- Group by reason category
- This helps teams understand the analysis methodology`;
}

/**
 * Format false positives for prompt
 */
function formatFalsePositivesForPrompt(falsePositives) {
    if (falsePositives.length === 0) {
        return 'No false positives identified.';
    }

    return falsePositives.slice(0, 20).map(fp =>
        `- **${fp.cve_id}** in ${fp.dependency}: ${fp.reason} - ${fp.details}`
    ).join('\n');
}

/**
 * Format vulnerabilities for prompt
 */
function formatVulnerabilitiesForPrompt(vulnerabilities) {
    if (vulnerabilities.length === 0) {
        return 'No true vulnerabilities identified.';
    }

    return vulnerabilities.slice(0, 20).map(vuln =>
        `- **${vuln.cve_id}** [${vuln.severity}] in ${vuln.dependency}: CVSS ${vuln.cvss_score} - ${vuln.description?.substring(0, 200) || 'No description'}...`
    ).join('\n');
}

/**
 * Generate a fallback report when Groq API fails
 */
function generateFallbackReport(analysisJson, error) {
    const vulns = analysisJson.true_vulnerabilities || [];
    const fps = analysisJson.false_positives || [];

    let report = `# Vulnerability Analysis Report\n\n`;
    report += `**Generated:** ${new Date().toISOString()}\n`;
    report += `**Project:** ${analysisJson.metadata?.project_name || 'Unknown'}\n\n`;
    report += `> ⚠️ Note: AI-enhanced report generation was unavailable. This is a basic report.\n\n`;

    // Executive Summary
    report += `## Executive Summary\n\n`;
    report += `This analysis identified **${vulns.length} genuine vulnerabilities** and **${fps.length} false positives** `;
    report += `from a total of ${analysisJson.metadata?.total_vulnerabilities_scanned || 0} reported findings.\n\n`;

    // Severity breakdown
    const severityCounts = analysisJson.summary?.severity_breakdown || {};
    if (Object.keys(severityCounts).length > 0) {
        report += `**Severity Breakdown:**\n`;
        report += `- Critical: ${severityCounts.critical || 0}\n`;
        report += `- High: ${severityCounts.high || 0}\n`;
        report += `- Medium: ${severityCounts.medium || 0}\n`;
        report += `- Low: ${severityCounts.low || 0}\n\n`;
    }

    // False Positives Table
    report += `## False Positives\n\n`;
    if (fps.length > 0) {
        report += `| CVE ID | Dependency | Reason | Confidence |\n`;
        report += `|--------|------------|--------|------------|\n`;
        for (const fp of fps) {
            report += `| ${fp.cve_id} | ${fp.dependency} | ${fp.reason} | ${fp.confidence} |\n`;
        }
    } else {
        report += `No false positives were identified.\n`;
    }
    report += `\n`;

    // True Vulnerabilities Table
    report += `## Vulnerabilities Requiring Action\n\n`;
    if (vulns.length > 0) {
        report += `| CVE ID | Dependency | Severity | CVSS Score |\n`;
        report += `|--------|------------|----------|------------|\n`;
        for (const vuln of vulns) {
            report += `| ${vuln.cve_id} | ${vuln.dependency} | ${vuln.severity} | ${vuln.cvss_score} |\n`;
        }
        report += `\n`;

        // Remediation
        report += `## Remediation Recommendations\n\n`;
        for (const vuln of vulns) {
            report += `### ${vuln.cve_id}\n`;
            report += `${vuln.recommended_fix || 'Upgrade to the latest patched version.'}\n\n`;
        }
    } else {
        report += `No actionable vulnerabilities were found. The identified issues were classified as false positives.\n`;
    }

    return {
        content: report,
        model: 'fallback',
        generated_at: new Date().toISOString(),
        tokens_used: 0,
        error: error?.message || 'Unknown error'
    };
}

/**
 * Sleep utility for retry delays
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
