const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');
const { initDatabase, saveDetectionResult } = require('./database');
const { loadModel, predict, extractFeatures } = require('./ml_model');
const app = express();
const PORT = 3000;

// Load or initialize ML model (training happens offline via scripts)
let mlModel = null;
let modelTrained = false;

// Try to load existing model immediately (doesn't require database)
mlModel = loadModel();
if (mlModel) {
    modelTrained = true;
    console.log('ML model loaded successfully from disk');
}

// Initialize database (for logging and metrics only)
let db;
initDatabase().then(database => {
    db = database;
    console.log('Database initialized (used for logging detections and metrics).');
}).catch(err => {
    console.error('Database initialization failed:', err);
});
// Helper: load offline model metrics (from training scripts)
function loadOfflineModelMetrics() {
    try {
        const metricsPath = path.join(__dirname, 'model_metrics.json');
        if (!fs.existsSync(metricsPath)) {
            return null;
        }
        const data = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));
        return data;
    } catch (err) {
        console.error('Error loading offline model metrics:', err);
        return null;
    }
}

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Handle favicon and other common browser requests (prevent 404 errors)
app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
});

app.get('/robots.txt', (req, res) => {
    res.status(204).end();
});

// Set EJS as the templating engine
app.set('views', path.join(__dirname, 'public'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

/**
 * 1. OUTPUT ENCODING FUNCTION
 * Safely converts special HTML characters into their harmless entity equivalents.
 */
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

/**
 * Middleware for SECURITY HEADERS (CSP)
 */
app.use((req, res, next) => {
    // Generate a unique nonce for this request (needed for a strong CSP)
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;

    // Define the Content Security Policy header
    const cspHeader = `
        default-src 'self';
        script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
        style-src 'self' 'unsafe-inline';
        connect-src 'self' https://cdn.jsdelivr.net;
        object-src 'none';
        base-uri 'self';
        form-action 'self';
    `.replace(/\s+/g, ' ').trim();

    // Set the CSP header
    res.setHeader('Content-Security-Policy', cspHeader);
    
    // Set other security headers (e.g., HttpOnly cookie is set later)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    next();
});


// --- XSS DEMONSTRATION ENDPOINT ---
app.get('/search', (req, res) => {
    // Decode the query parameter properly
    const rawInput = decodeURIComponent(req.query.q || 'Default Search Term');
    console.log("[BANK → XSS SERVER] Input Received:", rawInput);
    // Default to vulnerable to demonstrate detection first; switch via mode=secure for prevention.
    const mode = req.query.mode === 'secure' ? 'secure' : 'vulnerable';
    // Get ground truth label if provided
    const groundTruth = req.query.truth || null;
    
    // Use Random Forest model for prediction if available, otherwise fall back to pattern matching
    let isMalicious = false;
    let attackScore = 0;
    let mlPrediction = null;
    let attackPatterns = {};
    
    if (mlModel && modelTrained) {
        // Use ML model for prediction
        mlPrediction = predict(mlModel, rawInput);
        isMalicious = mlPrediction.isMalicious;
        attackScore = mlPrediction.isMalicious ? Math.round(mlPrediction.probability * 9) : 0;
        
        // Still extract patterns for display purposes
        const features = extractFeatures(rawInput);
        attackPatterns = {
            scriptTag: features[0] === 1,
            scriptClosing: features[1] === 1,
            onerror: features[2] === 1,
            onclick: features[3] === 1,
            javascript: features[4] === 1,
            imgTag: features[5] === 1,
            iframeTag: features[6] === 1,
            eval: features[7] === 1,
            alert: features[8] === 1
        };
    } else {
        // Fallback to pattern matching if model not trained
        attackPatterns = {
            scriptTag: /<script[\s>]/i.test(rawInput),
            scriptClosing: /<\/script>/i.test(rawInput),
            onerror: /onerror\s*=/i.test(rawInput),
            onclick: /onclick\s*=/i.test(rawInput),
            javascript: /javascript:/i.test(rawInput),
            imgTag: /<img[\s>]/i.test(rawInput),
            iframeTag: /<iframe[\s>]/i.test(rawInput),
            eval: /eval\s*\(/i.test(rawInput),
            alert: /alert\s*\(/i.test(rawInput)
        };
        attackScore = Object.values(attackPatterns).filter(Boolean).length;
        isMalicious = attackScore > 0;
    }
    
    // Process input based on mode
    let processedInput;
    let encodingApplied = false;
    
    if (mode === 'secure') {
        processedInput = escapeHtml(rawInput);
        encodingApplied = true;
    } else {
        processedInput = rawInput; // Vulnerable mode - no encoding
        encodingApplied = false;
    }
    
    // Prepare analysis data
    const analysisData = {
        rawInput: rawInput,
        processedInput: processedInput,
        mode: mode,
        encodingApplied: encodingApplied,
        attackPatterns: attackPatterns,
        attackScore: attackScore,
        isMalicious: isMalicious,
        groundTruth: groundTruth,
        timestamp: new Date().toISOString(),
        inputLength: rawInput.length,
        encodedLength: processedInput.length,
        mlModelUsed: modelTrained,
        mlPrediction: mlPrediction ? {
            probability: mlPrediction.probability,
            confidence: mlPrediction.confidence
        } : null
    };
    
    // Save to database
    if (db) {
        saveDetectionResult(db, analysisData).catch(err => {
            console.error('Error saving to database:', err);
        });
    }
    
    res.render('vulnerable.html', { 
        userInput: processedInput, 
        nonce: res.locals.nonce,
        analysis: analysisData
    });
});
// --- XSS API CHECK ENDPOINT ---
app.post('/check_xss', (req, res) => {
    const input = req.body.input || "";

    console.log("[XSS CHECK] Input:", input);

    let isMalicious = false;

    if (mlModel && modelTrained) {
        const prediction = predict(mlModel, input);
        isMalicious = prediction.isMalicious;
    } else {
        const patterns = {
            scriptTag: /<script[\s>]/i.test(input),
            scriptClosing: /<\/script>/i.test(input),
            onerror: /onerror\s*=/i.test(input),
            onclick: /onclick\s*=/i.test(input),
            javascript: /javascript:/i.test(input),
            imgTag: /<img[\s>]/i.test(input),
            iframeTag: /<iframe[\s>]/i.test(input),
            eval: /eval\s*\(/i.test(input),
            alert: /alert\s*\(/i.test(input)
        };

        isMalicious = Object.values(patterns).some(Boolean);
    }

    return res.json({
        safe: !isMalicious
    });
});

// For demonstrating HttpOnly cookies (though not part of this specific XSS demo)
app.get('/login', (req, res) => {
    res.cookie('session_id', 'user_session_token_123', {
        httpOnly: true, // Prevents client-side JS from reading it
        secure: true,   // Only send over HTTPS
        sameSite: 'Strict' 
    });
    res.send('Logged in. Session cookie set with HttpOnly.');
});


// Serve static test page
app.get('/test', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// Serve scanner page
app.get('/scanner', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'scanner.html'));
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
    try {
        const { getStatistics, getRecentResults, getPatternFrequency } = require('./database');
        console.log('Database functions loaded');
        
        if (!db) {
            return res.status(500).send(`
                <html>
                    <head><title>Database Not Ready</title></head>
                    <body style="font-family: Arial; padding: 40px; text-align: center;">
                        <h1>Database Not Initialized</h1>
                        <p>The metrics database is not ready yet. Please try again later.</p>
                        <p><a href="/scanner">Go to Scanner</a></p>
                    </body>
                </html>
            `);
        }
        
        // Fetch all data with error handling
        let stats = {};
        let recentResults = [];
        let patternFreq = {};
        let confusion = {
            true_positives: 0,
            true_negatives: 0,
            false_positives: 0,
            false_negatives: 0,
            total_labeled: 0,
            precision: 0,
            recall: 0,
            f1_score: 0,
            accuracy: 0,
            model_used: false
        };
        let kFoldResults = null;
        
        try {
            stats = await getStatistics(db) || {};
            console.log('Statistics retrieved:', Object.keys(stats));
        } catch (err) {
            console.error('Error getting statistics:', err);
        }
        
        console.log('Fetching recent results...');
        try {
            recentResults = await getRecentResults(db, 20) || [];
            console.log('Recent results retrieved:', recentResults.length, 'items');
        } catch (err) {
            console.error('Error getting recent results:', err);
        }
        
        console.log('Fetching pattern frequency...');
        try {
            patternFreq = await getPatternFrequency(db) || {};
            console.log('Pattern frequency retrieved:', Object.keys(patternFreq).length, 'patterns');
        } catch (err) {
            console.error('Error getting pattern frequency:', err);
        }
        
        // Load confusion matrix and k-fold summary from offline training (model_metrics.json)
        console.log('Loading offline model metrics for confusion matrix and k-fold...');
        const offlineMetrics = loadOfflineModelMetrics();
        if (offlineMetrics && offlineMetrics.confusion) {
            confusion = offlineMetrics.confusion;
            console.log('Loaded offline confusion matrix from model_metrics.json');
        } else {
            console.warn('Offline confusion matrix not available, using zeros.');
        }
        if (offlineMetrics) {
            // Shape this to match metrics.html expectations
            const conf = offlineMetrics.confusion || {
                true_positives: 0,
                true_negatives: 0,
                false_positives: 0,
                false_negatives: 0,
                total_labeled: 0,
                precision: 0,
                recall: 0,
                f1_score: 0,
                accuracy: 0,
                model_used: false
            };
            kFoldResults = {
                k: offlineMetrics.k,
                meanAccuracy: offlineMetrics.meanAccuracy,
                stdAccuracy: offlineMetrics.stdAccuracy,
                foldAccuracies: offlineMetrics.foldAccuracies || [],
                aggregatedConfusionMatrix: conf,
                // For compatibility with existing metrics.html table, provide minimal stubs
                totalSamples: conf.total_labeled || 0,
                foldResults: [], // No per-fold breakdown in offline file
                averageMetrics: {
                    accuracy: conf.accuracy,
                    precision: conf.precision,
                    recall: conf.recall,
                    f1_score: conf.f1_score
                },
                standardDeviation: {
                    accuracy: offlineMetrics.stdAccuracy || 0,
                    precision: 0,
                    recall: 0,
                    f1_score: 0
                }
            };
            console.log('Loaded offline k-fold summary from model_metrics.json');
        } else {
            kFoldResults = null;
            console.warn('Offline k-fold metrics not available.');
        }
        
        // Optionally run k-fold in background (non-blocking)
        // Uncomment below if you want to try k-fold, but it may hang
        /*
        console.log('Fetching k-fold results (this may take a while)...');
        try {
            kFoldResults = await Promise.race([
                performKFoldCrossValidation(db, 4),
                new Promise((_, reject) => setTimeout(() => reject(new Error('K-fold timeout')), 3000))
            ]);
            console.log('K-fold results retrieved');
        } catch (kFoldErr) {
            console.warn('K-fold cross-validation error or timeout:', kFoldErr.message);
            kFoldResults = { error: 'K-fold validation timed out or failed. This operation can be slow with large datasets.' };
        }
        */
        
        console.log('All data fetched, preparing to render template...');

        // Render the template with callback to catch rendering errors (non-blocking for k-fold)
        console.log('About to render metrics.html template');
        console.log('Data summary:', {
            statsCount: Object.keys(stats).length,
            recentResultsCount: recentResults.length,
            hasConfusion: !!confusion,
            hasKFold: !!kFoldResults
        });
        
        res.render('metrics.html', {
            statistics: stats,
            recentResults: recentResults,
            patternFrequency: patternFreq,
            confusion: confusion,
            kFoldResults: kFoldResults,
            nonce: res.locals.nonce || ''
        }, function(err, html) {
            if (err) {
                console.error('Template rendering error:', err);
                console.error('Error message:', err.message);
                console.error('Error stack:', err.stack);
                if (!res.headersSent) {
                    return res.status(500).send(`
                        <html>
                            <head><title>Template Error</title></head>
                            <body style="font-family: Arial; padding: 40px;">
                                <h1>Error rendering metrics page</h1>
                                <p><strong>Error:</strong> ${err.message}</p>
                                <p><strong>Line:</strong> ${err.line || 'Unknown'}</p>
                                <p><a href="/scanner">Go to Scanner</a></p>
                            </body>
                        </html>
                    `);
                }
                return;
            }
            console.log('Template rendered successfully, length:', html ? html.length : 0);
            if (!res.headersSent) {
                res.send(html);
            } else {
                console.warn('Response already sent, cannot send template');
            }
        });
    } catch (err) {
        console.error('Error in metrics endpoint:', err);
        console.error('Stack trace:', err.stack);
        if (!res.headersSent) {
            res.status(500).send(`
                <html>
                    <head><title>Error</title></head>
                    <body style="font-family: Arial; padding: 40px;">
                        <h1>Error loading metrics</h1>
                        <p><strong>Error:</strong> ${err.message}</p>
                        <p><strong>Details:</strong> ${err.stack || 'No additional details'}</p>
                        <p><a href="/scanner">Go to Scanner</a></p>
                    </body>
                </html>
            `);
        }
    }
});

// Root endpoint - redirect to scanner page
app.get('/', (req, res) => {
    res.redirect('/scanner');
});

// Health check endpoint to verify server is working (put at end to avoid conflicts)
app.get('/health', (req, res) => {
    res.send('Server is working!');
});

const server = app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log('---');
    if (modelTrained && mlModel) {
        console.log('Random Forest ML Model: ACTIVE');
    } else {
        console.log('Random Forest ML Model: NOT TRAINED (using pattern matching fallback)');
        console.log('   Train model by scanning inputs with "Ground Truth" labels (need at least 2 samples)');
    }
    console.log('---');
    console.log(`To test VULNERABILITY (Detection), use:`);
    console.log(`http://localhost:${PORT}/search?mode=vulnerable&q=<script>alert('XSS_ATTACK_DETECTED')</script>`);
    console.log('---');
    console.log(`To test PREVENTION (Secure Mode), use:`);
    console.log(`http://localhost:${PORT}/search?mode=secure&q=<script>alert('XSS_ATTACK_DETECTED')</script>`);
    console.log('---');
    console.log(`Default mode: vulnerable (detection demo). Pass mode=secure for prevention.`);
});

// Handle port already in use error
server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`\nError: Port ${PORT} is already in use.`);
        console.error('Please either:');
        console.error(`  1. Kill the process using port ${PORT}:`);
        console.error(`     Windows: netstat -ano | findstr :${PORT}  (then taskkill /PID <PID> /F)`);
        console.error(`     Mac/Linux: lsof -ti:${PORT} | xargs kill -9`);
        console.error(`  2. Or change the PORT constant in server.js to a different port\n`);
        process.exit(1);
    } else {
        throw err;
    }
});