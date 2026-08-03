const fs = require('fs');
const path = require('path');
const { extractFeatures, trainModel, saveModel } = require('./ml_model');
const { parseCSV } = require('./train_from_csv');

// Paths to datasets
const XSS_DATASET_PATH = path.join(__dirname, 'dataset', 'XSS_dataset.csv');
const CSS1_PATH = path.join(__dirname, 'dataset', 'css1.csv');

// Number of folds for cross-validation (reduced for speed)
const K_FOLDS = 3;

// ----------------- Helpers -----------------

function shuffleInPlace(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

function standardizeTrainTest(trainX, testX) {
    const nFeatures = trainX[0].length;
    const means = new Array(nFeatures).fill(0);
    const stds = new Array(nFeatures).fill(0);

    // Compute means
    for (const row of trainX) {
        for (let j = 0; j < nFeatures; j++) {
            means[j] += row[j];
        }
    }
    for (let j = 0; j < nFeatures; j++) {
        means[j] /= trainX.length;
    }

    // Compute stds
    for (const row of trainX) {
        for (let j = 0; j < nFeatures; j++) {
            const diff = row[j] - means[j];
            stds[j] += diff * diff;
        }
    }
    for (let j = 0; j < nFeatures; j++) {
        stds[j] = Math.sqrt(stds[j] / trainX.length) || 1;
    }

    function applyStandardization(data) {
        return data.map(row =>
            row.map((val, j) => (val - means[j]) / stds[j])
        );
    }

    return {
        trainX: applyStandardization(trainX),
        testX: applyStandardization(testX),
    };
}

// Simple CSV parser for XSS_dataset.csv
function parseXSSDataset(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').filter(line => line.trim());

    const records = [];

    for (let i = 1; i < lines.length; i++) { // skip header
        const line = lines[i];
        // Format: index,"Sentence",Label
        const match = line.match(/^(\d+),"(.*)",(0|1)\s*$/);
        if (!match) continue;
        const sentence = match[2].replace(/""/g, '"'); // unescape quotes
        const label = parseInt(match[3], 10);
        records.push({ sentence, label });
    }

    return records;
}

// Generate XSS payload based on test name and category (reused idea from train_from_csv.js)
function generateXSSPayload(testName, category, isVulnerable) {
    if (category.toLowerCase() !== 'xss') {
        // For non-XSS tests, generate clean input
        return isVulnerable ? `test_${testName}_input` : `normal_input_${testName}`;
    }

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
        `<embed src=javascript:alert('XSS${testNum}')>`,
    ];

    if (isVulnerable) {
        return payloads[testNum % payloads.length];
    } else {
        return `Hello World ${testNum}`;
    }
}

// ----------------- Main Training Logic -----------------

function buildCombinedDataset() {
    console.log('Loading XSS_dataset.csv...');
    const xssRecords = parseXSSDataset(XSS_DATASET_PATH);
    console.log(`Loaded ${xssRecords.length} records from XSS_dataset.csv`);

    console.log('Loading css1.csv via parseCSV...');
    const cssRecords = parseCSV(CSS1_PATH);
    console.log(`Loaded ${cssRecords.length} records from css1.csv`);

    // Filter css1 to XSS category
    const cssXSS = cssRecords.filter(r => r.category && r.category.toLowerCase() === 'xss');
    console.log(`Filtered to ${cssXSS.length} XSS category records from css1.csv`);

    let X = [];
    let y = [];

    // Add XSS_dataset records
    for (const rec of xssRecords) {
        const feats = extractFeatures(rec.sentence);
        X.push(feats);
        y.push(rec.label); // 1 = XSS, 0 = clean
    }

    // Add css1 XSS records (use synthetic payloads)
    for (const rec of cssXSS) {
        const payload = generateXSSPayload(rec.testName, rec.category, rec.realVulnerability);
        const feats = extractFeatures(payload);
        X.push(feats);
        y.push(rec.realVulnerability ? 1 : 0);
    }

    console.log(`Combined dataset size: ${X.length} samples, feature dimension: ${X[0]?.length || 0}`);

    // Optional: subsample for quicker experimentation
    const MAX_SAMPLES = 4000;
    if (X.length > MAX_SAMPLES) {
        console.log(`Subsampling from ${X.length} to ${MAX_SAMPLES} samples for faster k-fold training...`);
        const indices = Array.from({ length: X.length }, (_, i) => i);
        shuffleInPlace(indices);
        const selected = indices.slice(0, MAX_SAMPLES);
        X = selected.map(i => X[i]);
        y = selected.map(i => y[i]);
        console.log(`Subsampled dataset size: ${X.length}`);
    }
    return { X, y };
}

function kFoldCrossValidation(X, y, k = K_FOLDS) {
    const indices = Array.from({ length: X.length }, (_, i) => i);
    shuffleInPlace(indices);

    const foldSize = Math.floor(X.length / k);
    const accuracies = [];
    const foldConfusions = [];

    for (let fold = 0; fold < k; fold++) {
        const start = fold * foldSize;
        const end = fold === k - 1 ? X.length : start + foldSize;
        const testIdx = indices.slice(start, end);
        const trainIdx = indices.filter((_, idx) => idx < start || idx >= end);

        const trainX = trainIdx.map(i => X[i]);
        const trainY = trainIdx.map(i => y[i]);
        const testX = testIdx.map(i => X[i]);
        const testY = testIdx.map(i => y[i]);

        // Standardize features based on training data
        const { trainX: normTrainX, testX: normTestX } = standardizeTrainTest(trainX, testX);

        // Train model on normalized features (lightweight RF from ml_model.js)
        const classifier = trainModel(normTrainX, trainY);

        // Evaluate on test fold
        let correct = 0;
        let tp = 0, tn = 0, fp = 0, fn = 0;
        for (let i = 0; i < normTestX.length; i++) {
            const pred = classifier.predict([normTestX[i]])[0];
            const actual = testY[i];
            if (pred === actual) correct++;

            if (pred === 1 && actual === 1) tp++;
            else if (pred === 0 && actual === 0) tn++;
            else if (pred === 1 && actual === 0) fp++;
            else if (pred === 0 && actual === 1) fn++;
        }
        const acc = correct / normTestX.length;
        accuracies.push(acc);
        foldConfusions.push({ tp, tn, fp, fn });
        console.log(`Fold ${fold + 1}/${k} accuracy: ${(acc * 100).toFixed(2)}%`);
    }

    const meanAcc = accuracies.reduce((a, b) => a + b, 0) / accuracies.length;
    const stdAcc = Math.sqrt(
        accuracies.reduce((sum, acc) => sum + Math.pow(acc - meanAcc, 2), 0) / accuracies.length
    );

    // Aggregate confusion across folds
    let aggTp = 0, aggTn = 0, aggFp = 0, aggFn = 0;
    for (const c of foldConfusions) {
        aggTp += c.tp;
        aggTn += c.tn;
        aggFp += c.fp;
        aggFn += c.fn;
    }
    const total = aggTp + aggTn + aggFp + aggFn;
    const precision = (aggTp + aggFp) > 0 ? (aggTp / (aggTp + aggFp)) : 0;
    const recall = (aggTp + aggFn) > 0 ? (aggTp / (aggTp + aggFn)) : 0;
    const f1Score = (precision + recall) > 0 ? (2 * precision * recall / (precision + recall)) : 0;
    const accuracy = total > 0 ? ((aggTp + aggTn) / total) : 0;

    console.log('---');
    console.log(`K-Fold (${k}) Accuracy: ${(meanAcc * 100).toFixed(2)}% ± ${(stdAcc * 100).toFixed(2)}%`);

    return {
        k,
        foldAccuracies: accuracies,
        meanAccuracy: meanAcc,
        stdAccuracy: stdAcc,
        totalSamples: total,
        confusion: {
            true_positives: aggTp,
            true_negatives: aggTn,
            false_positives: aggFp,
            false_negatives: aggFn,
            total_labeled: total,
            precision,
            recall,
            f1_score: f1Score,
            accuracy,
            model_used: true
        }
    };
}

// Run when executed directly
if (require.main === module) {
    const { X, y } = buildCombinedDataset();
    // 1) Report k-fold accuracy (offline evaluation) and capture metrics
    const kfoldMetrics = kFoldCrossValidation(X, y, K_FOLDS);

    // Persist offline evaluation metrics for the UI (/metrics)
    const metricsPayload = {
        dataset: 'combined XSS_dataset.csv + css1.csv (XSS only)',
        k: kfoldMetrics.k,
        foldAccuracies: kfoldMetrics.foldAccuracies,
        meanAccuracy: kfoldMetrics.meanAccuracy,
        stdAccuracy: kfoldMetrics.stdAccuracy,
        confusion: kfoldMetrics.confusion
    };
    const METRICS_PATH = path.join(__dirname, 'model_metrics.json');
    fs.writeFileSync(METRICS_PATH, JSON.stringify(metricsPayload, null, 2));
    console.log('Saved offline model metrics to', METRICS_PATH);

    // 2) Train final model on the full (possibly subsampled) dataset and save it
    console.log('---');
    console.log('Training final Random Forest model on full combined dataset for deployment...');
    const finalClassifier = trainModel(X, y);
    const featureCount = X[0] ? X[0].length : null;
    const saved = saveModel(finalClassifier, featureCount);
    if (saved) {
        console.log('Final combined-dataset model saved to random_forest_model.json');
    } else {
        console.error('Failed to save final combined-dataset model');
    }
}

module.exports = {
    buildCombinedDataset,
    kFoldCrossValidation,
};


