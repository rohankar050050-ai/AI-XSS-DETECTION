const { initDatabase, getConfusionMatrix, performKFoldCrossValidation, getStatistics } = require('./database');
const { loadModel } = require('./ml_model');
const fs = require('fs');
const path = require('path');

async function verifySetup() {
    console.log('='.repeat(60));
    console.log('🔍 Verifying Setup');
    console.log('='.repeat(60));
    
    let allGood = true;
    
    // Check 1: Model file exists
    console.log('\n1️⃣ Checking Random Forest Model...');
    const modelPath = path.join(__dirname, 'random_forest_model.json');
    if (fs.existsSync(modelPath)) {
        console.log('   ✅ Model file exists:', modelPath);
        const model = loadModel();
        if (model) {
            console.log('   ✅ Model loaded successfully');
        } else {
            console.log('   ❌ Model failed to load');
            allGood = false;
        }
    } else {
        console.log('   ❌ Model file not found');
        allGood = false;
    }
    
    // Check 2: Database connection
    console.log('\n2️⃣ Checking Database...');
    try {
        const db = await initDatabase();
        console.log('   ✅ Database connected');
        
        // Check 3: Database has data
        console.log('\n3️⃣ Checking Database Data...');
        const stats = await getStatistics(db);
        const totalScans = stats.total_scans || 0;
        const labeledSamples = stats.labeled_samples || 0;
        
        console.log(`   Total scans: ${totalScans}`);
        console.log(`   Labeled samples: ${labeledSamples}`);
        
        if (labeledSamples > 0) {
            console.log('   ✅ Database has labeled data');
        } else {
            console.log('   ⚠️  No labeled data in database');
            allGood = false;
        }
        
        // Check 4: Confusion Matrix works
        console.log('\n4️⃣ Testing Confusion Matrix...');
        try {
            const confusion = await getConfusionMatrix(db);
            console.log('   ✅ Confusion Matrix calculated successfully');
            console.log(`   - True Positives: ${confusion.true_positives}`);
            console.log(`   - True Negatives: ${confusion.true_negatives}`);
            console.log(`   - False Positives: ${confusion.false_positives}`);
            console.log(`   - False Negatives: ${confusion.false_negatives}`);
            console.log(`   - Accuracy: ${(confusion.accuracy * 100).toFixed(2)}%`);
            console.log(`   - Model Used: ${confusion.model_used ? 'Random Forest ✅' : 'Pattern Matching'}`);
        } catch (err) {
            console.log('   ❌ Confusion Matrix error:', err.message);
            allGood = false;
        }
        
        // Check 5: K-Fold Cross-Validation works
        console.log('\n5️⃣ Testing K-Fold Cross-Validation...');
        try {
            const kfold = await performKFoldCrossValidation(db, 4);
            if (kfold.error) {
                console.log('   ⚠️  K-Fold error:', kfold.error);
            } else {
                console.log('   ✅ K-Fold Cross-Validation completed');
                console.log(`   - K: ${kfold.k} folds`);
                console.log(`   - Total Samples: ${kfold.totalSamples}`);
                console.log(`   - Accuracy: ${(kfold.aggregatedConfusionMatrix.accuracy * 100).toFixed(2)}%`);
                console.log(`   - Precision: ${(kfold.aggregatedConfusionMatrix.precision * 100).toFixed(2)}%`);
                console.log(`   - Recall: ${(kfold.aggregatedConfusionMatrix.recall * 100).toFixed(2)}%`);
                console.log(`   - F1 Score: ${(kfold.aggregatedConfusionMatrix.f1_score * 100).toFixed(2)}%`);
                console.log(`   - Model Used: ${kfold.model_used || 'N/A'}`);
            }
        } catch (err) {
            console.log('   ❌ K-Fold error:', err.message);
            allGood = false;
        }
        
        db.close();
        
    } catch (err) {
        console.log('   ❌ Database error:', err.message);
        allGood = false;
    }
    
    // Final Summary
    console.log('\n' + '='.repeat(60));
    if (allGood) {
        console.log('✅ All checks passed! Setup is complete and ready.');
        console.log('\n📋 Next Steps:');
        console.log('   1. Start the server: node server.js');
        console.log('   2. Visit http://localhost:3000/metrics');
        console.log('   3. You should see:');
        console.log('      - Random Forest model indicators');
        console.log('      - Confusion matrix with metrics');
        console.log('      - K-fold cross-validation results');
    } else {
        console.log('⚠️  Some checks failed. Please review the errors above.');
    }
    console.log('='.repeat(60));
}

verifySetup().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
