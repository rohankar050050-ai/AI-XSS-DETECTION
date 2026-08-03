const fs = require('fs');
const path = require('path');
const { trainModel, saveModel, extractFeatures } = require('./ml_model');

const CSV_PATH = path.join(__dirname, 'dataset', 'css1.csv');

// Parse CSV file
function parseCSV(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
    
    const data = [];
    for (const line of lines) {
        const parts = line.split(',');
        if (parts.length >= 4) {
            const testName = parts[0].trim();
            const category = parts[1].trim();
            const realVulnerability = parts[2].trim().toLowerCase() === 'true';
            const cwe = parts[3].trim();
            
            data.push({
                testName,
                category,
                realVulnerability,
                cwe
            });
        }
    }
    
    return data;
}

// Generate XSS payload based on test name and category
function generateXSSPayload(testName, category, isVulnerable) {
    if (category.toLowerCase() !== 'xss') {
        // For non-XSS tests, generate clean input
        return isVulnerable ? `test_${testName}_input` : `normal_input_${testName}`;
    }
    
    // For XSS tests, generate actual XSS payloads based on test number
    const testNum = parseInt(testName.replace('BenchmarkTest', '')) || 0;
    const payloads = [
        `<script>alert('XSS${testNum}')</script>`,
        `<img src=x onerror=alert('XSS${testNum}')>`,
        `<iframe src=javascript:alert('XSS${testNum}')></iframe>`,
        `<div onclick=alert('XSS${testNum}')>Click</div>`,
        `<svg/onload=alert('XSS${testNum}')>`,
        `<a href=javascript:alert('XSS${testNum}')>Link</a>`,
        `<script>eval('alert("XSS${testNum}")')</script>`,
        `<body onload=alert('XSS${testNum}')>`,
        `<input onfocus=alert('XSS${testNum}') autofocus>`,
        `<embed src=javascript:alert('XSS${testNum}')>`
    ];
    
    if (isVulnerable) {
        return payloads[testNum % payloads.length];
    } else {
        // Clean input for non-vulnerable XSS tests
        return `Hello World ${testNum}`;
    }
}

// Main training function
function trainFromCSV() {
    console.log('Reading CSV file:', CSV_PATH);
    const csvData = parseCSV(CSV_PATH);
    console.log(`Loaded ${csvData.length} records from CSV`);
    
    // Filter only XSS category tests for better training
    const xssData = csvData.filter(record => record.category.toLowerCase() === 'xss');
    console.log(`Filtered to ${xssData.length} XSS category tests`);
    
    if (xssData.length === 0) {
        console.error('No XSS category tests found in CSV. Using all data but accuracy may be low.');
        // Fall back to all data if no XSS tests
        xssData.push(...csvData);
    }
    
    // Prepare training data
    const trainingData = [];
    const trainingLabels = [];
    
    console.log('Generating XSS payloads and extracting features...');
    for (const record of xssData) {
        // Generate actual XSS payload based on test characteristics
        const payload = generateXSSPayload(record.testName, record.category, record.realVulnerability);
        const features = extractFeatures(payload);
        trainingData.push(features);
        
        // Convert vulnerability flag to binary label: true = 1 (malicious), false = 0 (clean)
        trainingLabels.push(record.realVulnerability ? 1 : 0);
    }
    
    console.log(`Prepared ${trainingData.length} training samples`);
    console.log(`Features per sample: ${trainingData[0]?.length || 0}`);
    console.log(`Malicious samples: ${trainingLabels.filter(l => l === 1).length}`);
    console.log(`Clean samples: ${trainingLabels.filter(l => l === 0).length}`);
    
        // Train the model
        console.log('\nTraining Random Forest model...');
        try {
            const classifier = trainModel(trainingData, trainingLabels);
            console.log('Model trained successfully!');
            
            // Save the model with feature count
            const featureCount = trainingData[0] ? trainingData[0].length : 19;
            const saved = saveModel(classifier, featureCount);
            if (saved) {
                console.log('\n✅ Training completed successfully!');
                console.log('Model saved to: random_forest_model.json');
            } else {
                console.error('\n❌ Failed to save model');
            }
        } catch (error) {
            console.error('Error training model:', error);
            process.exit(1);
        }
}

// Run training
if (require.main === module) {
    trainFromCSV();
}

module.exports = { trainFromCSV, parseCSV };
