const { RandomForestClassifier } = require('ml-random-forest');
const { Matrix } = require('ml-matrix');
const fs = require('fs');
const path = require('path');

const MODEL_PATH = path.join(__dirname, 'random_forest_model.json');

// Infer feature count dynamically from the extractor if needed
function inferFeatureCountFromExtractor() {
    try {
        const feats = extractFeatures('');
        if (Array.isArray(feats)) {
            return feats.length;
        }
    } catch (e) {
        // Ignore and fall back to defaults
    }
    return null;
}

// Feature extraction function - converts input to feature vector
function extractFeatures(input) {
    const features = [];
    const lowerInput = input.toLowerCase();
    
    // Feature 1-9: Pattern detection (binary features)
    features.push(/<script[\s>]/i.test(input) ? 1 : 0);  // scriptTag
    features.push(/<\/script>/i.test(input) ? 1 : 0);    // scriptClosing
    features.push(/onerror\s*=/i.test(input) ? 1 : 0);  // onerror
    features.push(/onclick\s*=/i.test(input) ? 1 : 0);  // onclick
    features.push(/javascript:/i.test(input) ? 1 : 0);  // javascript protocol
    features.push(/<img[\s>]/i.test(input) ? 1 : 0);    // imgTag
    features.push(/<iframe[\s>]/i.test(input) ? 1 : 0);  // iframeTag
    features.push(/eval\s*\(/i.test(input) ? 1 : 0);     // eval
    features.push(/alert\s*\(/i.test(input) ? 1 : 0);    // alert
    
    // Additional XSS patterns
    features.push(/<svg[\s>]/i.test(input) ? 1 : 0);    // svg tag
    features.push(/<body[\s>]/i.test(input) ? 1 : 0);   // body tag
    features.push(/<input[\s>]/i.test(input) ? 1 : 0);  // input tag
    features.push(/<form[\s>]/i.test(input) ? 1 : 0);   // form tag
    features.push(/onload\s*=/i.test(input) ? 1 : 0);   // onload
    features.push(/onmouseover\s*=/i.test(input) ? 1 : 0); // onmouseover
    features.push(/document\./i.test(input) ? 1 : 0);    // document object
    features.push(/window\./i.test(input) ? 1 : 0);     // window object
    
    // Character counts (normalized by length for better ML performance)
    const length = Math.max(input.length, 1); // Avoid division by zero
    features.push(input.length);                          // input length
    features.push((input.match(/</g) || []).length / length);     // normalized < count
    features.push((input.match(/>/g) || []).length / length);     // normalized > count
    features.push((input.match(/=/g) || []).length / length);      // normalized = count
    features.push((input.match(/"/g) || []).length / length);      // normalized " count
    features.push((input.match(/'/g) || []).length / length);      // normalized ' count
    features.push((input.match(/\(/g) || []).length / length);     // normalized ( count
    features.push((input.match(/\)/g) || []).length / length);     // normalized ) count
    features.push((input.match(/on\w+/gi) || []).length); // number of event handlers
    features.push((input.match(/script/gi) || []).length); // number of "script" occurrences
    
    // Pattern combinations (more discriminative features)
    features.push((/<script[\s>]/i.test(input) && /alert/i.test(input)) ? 1 : 0); // script + alert
    features.push((/<img[\s>]/i.test(input) && /onerror/i.test(input)) ? 1 : 0); // img + onerror
    features.push((/<iframe[\s>]/i.test(input) && /javascript:/i.test(input)) ? 1 : 0); // iframe + javascript:
    
    // Encoding attempts (common XSS evasion)
    features.push(/&#x/i.test(input) ? 1 : 0);  // hex encoding
    features.push(/&#/i.test(input) ? 1 : 0);    // decimal encoding
    features.push(/%3c/i.test(input) ? 1 : 0);   // URL encoding <
    features.push(/%3e/i.test(input) ? 1 : 0);   // URL encoding >
    
    // Suspicious patterns
    features.push(/<[^>]*on\w+\s*=/i.test(input) ? 1 : 0); // any tag with event handler
    features.push(/javascript\s*:/i.test(input) ? 1 : 0); // javascript: protocol (case variations)
    
    return features;
}

// Train Random Forest model with improved hyperparameters
function trainModel(trainingData, trainingLabels) {
    if (trainingData.length === 0) {
        throw new Error('No training data available');
    }
    
    if (trainingData.length < 2) {
        throw new Error('Need at least 2 samples to train the model');
    }
    
    // Check class distribution
    const maliciousCount = trainingLabels.filter(l => l === 1).length;
    const cleanCount = trainingLabels.filter(l => l === 0).length;
    const total = trainingLabels.length;
    
    console.log(`Training data distribution: ${maliciousCount} malicious (${(maliciousCount/total*100).toFixed(1)}%), ${cleanCount} clean (${(cleanCount/total*100).toFixed(1)}%)`);
    
    // Warn if severe class imbalance
    if (maliciousCount < total * 0.1 || cleanCount < total * 0.1) {
        console.warn('Warning: Severe class imbalance detected. Model performance may be affected.');
    }
    
    const X = new Matrix(trainingData);
    const y = trainingLabels;
    
    // Improved hyperparameters for better accuracy, tuned for speed vs performance
    const featureCount = trainingData[0].length;
    const maxFeatures = Math.max(1, Math.floor(Math.sqrt(featureCount)));
    
    const options = {
        seed: 42, // For reproducibility
        maxFeatures: maxFeatures,
        replacement: true,
        // Lighter forest so k-fold CV runs in reasonable time
        nEstimators: 100,
        treeOptions: {
            minNumSamples: Math.max(1, Math.floor(trainingData.length * 0.01)), // At least 1% of data per leaf
            gainFunction: 'gini',
            maxDepth: 12,
            gainThreshold: 0.001
        }
    };
    
    console.log(`Training Random Forest with ${options.nEstimators} trees, maxDepth=${options.treeOptions.maxDepth}, maxFeatures=${maxFeatures}`);
    
    const classifier = new RandomForestClassifier(options);
    classifier.train(X, y);
    
    // Calculate training accuracy for validation
    let correct = 0;
    for (let i = 0; i < trainingData.length; i++) {
        const prediction = classifier.predict([trainingData[i]]);
        if (prediction[0] === trainingLabels[i]) {
            correct++;
        }
    }
    const trainingAccuracy = (correct / trainingData.length) * 100;
    console.log(`Training accuracy: ${trainingAccuracy.toFixed(2)}%`);
    
    return classifier;
}

// Save model to disk
function saveModel(classifier, featureCount = null) {
    try {
        // Serialize model once so we can inspect hyperparameters as well
        const treesJson = classifier.toJSON();

        // Get featureCount from classifier if available, otherwise use provided value
        let numFeatures = classifier.featureCount;
        if (!numFeatures && featureCount !== null) {
            numFeatures = featureCount;
        }
        // If still not available, try to infer from the model structure
        if (!numFeatures && treesJson && treesJson.baseModel && treesJson.baseModel.maxFeatures) {
            // maxFeatures is typically sqrt of feature count, so featureCount ~= maxFeatures^2
            const maxFeatures = treesJson.baseModel.maxFeatures;
            numFeatures = Math.pow(maxFeatures, 2);
        }
        // If still not known, infer from extractFeatures('')
        if (!numFeatures) {
            const inferred = inferFeatureCountFromExtractor();
            if (inferred) {
                numFeatures = inferred;
                console.warn('Inferred featureCount from extractFeatures:', numFeatures);
            }
        }
        // Final fallback if we can't determine (kept for backward compatibility)
        if (!numFeatures) {
            numFeatures = 19;
            console.warn('Could not determine featureCount, using default:', numFeatures);
        }

        // Extract top-level hyperparameters for convenience (they also exist inside treesJson)
        let hyperparameters = {};
        if (treesJson && treesJson.baseModel) {
            const base = treesJson.baseModel;
            hyperparameters = {
                maxFeatures: base.maxFeatures,
                nEstimators: base.nEstimators,
                treeOptions: base.treeOptions || {}
            };
        }

        const modelData = {
            trees: treesJson,
            featureCount: numFeatures,
            hyperparameters
        };
        fs.writeFileSync(MODEL_PATH, JSON.stringify(modelData, null, 2));
        console.log('Random Forest model saved to', MODEL_PATH, 'with featureCount:', numFeatures);
        return true;
    } catch (err) {
        console.error('Error saving model:', err);
        return false;
    }
}

// Load model from disk
function loadModel() {
    try {
        if (!fs.existsSync(MODEL_PATH)) {
            return null;
        }
        
        const modelData = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8'));
        // Use featureCount if available, otherwise try to infer or use extractor
        let featureCount = modelData.featureCount;
        if (!featureCount && modelData.trees && modelData.trees.baseModel) {
            const maxFeatures = modelData.trees.baseModel.maxFeatures;
            if (maxFeatures) {
                featureCount = Math.pow(maxFeatures, 2);
            }
        }
        if (!featureCount) {
            const inferred = inferFeatureCountFromExtractor();
            if (inferred) {
                featureCount = inferred;
                console.warn('Inferred featureCount from extractFeatures while loading model:', featureCount);
            }
        }
        // Final fallback
        if (!featureCount) {
            featureCount = 19;
            console.warn('Could not determine featureCount from model, using default:', featureCount);
        }

        const classifier = RandomForestClassifier.load(modelData.trees, featureCount);
        console.log('Random Forest model loaded from', MODEL_PATH, 'with featureCount:', featureCount);
        if (modelData.hyperparameters) {
            console.log('Model hyperparameters:', modelData.hyperparameters);
        }
        return classifier;
    } catch (err) {
        console.error('Error loading model:', err);
        return null;
    }
}

// Predict using the model
function predict(classifier, input) {
    if (!classifier) {
        return null;
    }
    
    const features = extractFeatures(input);
    const prediction = classifier.predict([features]);
    
    // predictProbability requires a label parameter (0 or 1)
    // Get probabilities for both classes
    const probClean = classifier.predictProbability([features], 0)[0] || 0;
    const probMalicious = classifier.predictProbability([features], 1)[0] || 0;
    
    return {
        isMalicious: prediction[0] === 1,
        probability: probMalicious, // Probability of being malicious
        confidence: Math.max(probClean, probMalicious)
    };
}

// Get feature importance (if available)
function getFeatureImportance(classifier) {
    if (!classifier || !classifier.featureImportance) {
        return null;
    }
    return classifier.featureImportance();
}

module.exports = {
    extractFeatures,
    trainModel,
    saveModel,
    loadModel,
    predict,
    getFeatureImportance,
    MODEL_PATH
};

