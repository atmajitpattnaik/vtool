import express from 'express';
import { parseOwaspReport } from '../parsers/owaspParser.js';
import { parseManifest } from '../parsers/manifestParser.js';
import { analyzeReachability } from '../analyzers/reachabilityAnalyzer.js';
import { detectFalsePositives } from '../analyzers/falsePositiveDetector.js';
import { extractVulnerabilities } from '../analyzers/vulnerabilityExtractor.js';
import { generateJsonOutput } from '../services/jsonGenerator.js';
import { generateLLMReport } from '../services/groqService.js';

const router = express.Router();

/**
 * POST /api/analyze
 * Main analysis endpoint - accepts OWASP report and dependency manifest
 */
router.post('/analyze', (req, res, next) => {
    const upload = req.app.locals.upload;

    upload.fields([
        { name: 'owaspReport', maxCount: 1 },
        { name: 'dependencyManifest', maxCount: 1 }
    ])(req, res, async (err) => {
        if (err) {
            return next(err);
        }

        try {
            // Validate files
            if (!req.files?.owaspReport?.[0]) {
                return res.status(400).json({ error: 'OWASP report file is required' });
            }

            const owaspFile = req.files.owaspReport[0];
            const manifestFile = req.files.dependencyManifest?.[0];
            const callGraph = parseCallGraphField(req.body?.callGraph);

            console.log('📥 Received files:', {
                owasp: owaspFile.originalname,
                manifest: manifestFile?.originalname || 'Not provided',
                callGraph: callGraph ? 'Provided' : 'Not provided'
            });

            // Parse OWASP report
            const owaspContent = owaspFile.buffer.toString('utf-8');
            const owaspData = await parseOwaspReport(owaspContent, owaspFile.originalname);

            console.log(`📊 Parsed ${owaspData.vulnerabilities.length} vulnerabilities from OWASP report`);

            // Parse dependency manifest if provided
            let manifestData = null;
            if (manifestFile) {
                const manifestContent = manifestFile.buffer.toString('utf-8');
                manifestData = await parseManifest(manifestContent, manifestFile.originalname);
                console.log(`📦 Parsed ${Object.keys(manifestData.dependencies).length} dependencies from manifest`);
            }

            // Perform reachability analysis
            const reachabilityResults = await analyzeReachability(owaspData, manifestData, callGraph);

            // Detect false positives
            const falsePositives = await detectFalsePositives(owaspData, manifestData, reachabilityResults);

            // Extract true vulnerabilities
            const trueVulnerabilities = await extractVulnerabilities(owaspData, falsePositives);

            // Generate JSON output
            const jsonOutput = generateJsonOutput(falsePositives, trueVulnerabilities, {
                projectName: manifestData?.name || 'Unknown Project',
                owaspReportName: owaspFile.originalname
            });

            console.log(`✅ Analysis complete: ${falsePositives.length} false positives, ${trueVulnerabilities.length} true vulnerabilities`);

            res.json({
                success: true,
                analysis: jsonOutput
            });

        } catch (error) {
            console.error('Analysis error:', error);
            res.status(error.status || 500).json({ error: error.message || 'Internal server error' });
        }
    });
});

/**
 * POST /api/generate-report
 * Generate LLM-based human-readable report from analysis JSON
 */
router.post('/generate-report', async (req, res, next) => {
    try {
        const { analysis } = req.body;

        if (!analysis) {
            return res.status(400).json({ error: 'Analysis data is required' });
        }

        console.log('🤖 Generating LLM report...');

        const report = await generateLLMReport(analysis);

        console.log('✅ LLM report generated successfully');

        res.json({
            success: true,
            report
        });

    } catch (error) {
        console.error('Report generation error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Internal server error' });
    }
});

/**
 * POST /api/full-analysis
 * Combined endpoint: analyze + generate report
 */
router.post('/full-analysis', (req, res, next) => {
    const upload = req.app.locals.upload;

    upload.fields([
        { name: 'owaspReport', maxCount: 1 },
        { name: 'dependencyManifest', maxCount: 1 }
    ])(req, res, async (err) => {
        if (err) {
            return next(err);
        }

        try {
            // Validate files
            if (!req.files?.owaspReport?.[0]) {
                return res.status(400).json({ error: 'OWASP report file is required' });
            }

            const owaspFile = req.files.owaspReport[0];
            const manifestFile = req.files.dependencyManifest?.[0];
            const callGraph = parseCallGraphField(req.body?.callGraph);

            // Parse OWASP report
            const owaspContent = owaspFile.buffer.toString('utf-8');
            const owaspData = await parseOwaspReport(owaspContent, owaspFile.originalname);

            // Parse dependency manifest if provided
            let manifestData = null;
            if (manifestFile) {
                const manifestContent = manifestFile.buffer.toString('utf-8');
                manifestData = await parseManifest(manifestContent, manifestFile.originalname);
            }

            // Perform analysis
            const reachabilityResults = await analyzeReachability(owaspData, manifestData, callGraph);
            const falsePositives = await detectFalsePositives(owaspData, manifestData, reachabilityResults);
            const trueVulnerabilities = await extractVulnerabilities(owaspData, falsePositives);

            // Generate JSON output
            const jsonOutput = generateJsonOutput(falsePositives, trueVulnerabilities, {
                projectName: manifestData?.name || 'Unknown Project',
                owaspReportName: owaspFile.originalname
            });

            // Generate LLM report
            const llmReport = await generateLLMReport(jsonOutput);

            res.json({
                success: true,
                analysis: jsonOutput,
                report: llmReport
            });

        } catch (error) {
            console.error('Full analysis error:', error);
            res.status(error.status || 500).json({ error: error.message || 'Internal server error' });
        }
    });
});

export default router;

/**
 * Safely parse optional call graph JSON supplied as a string field
 */
function parseCallGraphField(callGraphString) {
    if (!callGraphString || typeof callGraphString !== 'string') return null;
    try {
        const parsed = JSON.parse(callGraphString);
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
        return null;
    }
}
