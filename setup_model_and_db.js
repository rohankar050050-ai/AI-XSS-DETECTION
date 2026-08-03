const fs = require('fs');
const path = require('path');
const { trainFromCSV, parseCSV } = require('./train_from_csv');
const { initDatabase, saveDetectionResult } = require('./database');

const CSV_PATH = path.join(__dirname, 'dataset', 'css1.csv');
const DB_PATH = path.join(__dirname, 'xss_detection.db');

// Main setup function
async function setupModelAndDatabase() {
    console.log('='.repeat(60));
    console.log('🚀 Setting up Random Forest Model and Database');
    console.log('='.repeat(60));
    
    try {
        // Step 1: Train the Random Forest model
        console.log('\n📊 Step 1: Training Random Forest Model...');
        console.log('-'.repeat(60));
        trainFromCSV();
        
        // Step 2: Initialize database
        console.log('\n🗄️  Step 2: Preparing Database...');
        console.log('-'.repeat(60));
        const db = await initDatabase();
        
        // Step 3: Clear existing data from database
        console.log('\n🗑️  Step 3: Clearing existing data...');
        console.log('-'.repeat(60));
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM detection_results', (err) => {
                if (err) {
                    console.warn('Warning: Could not clear existing data (database may be in use):', err.message);
                    console.log('   Continuing with population (data will be appended)...');
                } else {
                    console.log('   Existing data cleared');
                }
                resolve();
            });
        });
        
        // Step 4: Populate database with CSV data
        console.log('\n📥 Step 4: Populating Database with CSV Data...');
        console.log('-'.repeat(60));
        
        // Parse and populate CSV data
        const csvData = parseCSV(CSV_PATH);
        console.log(`Loaded ${csvData.length} records from CSV`);
        
        let successCount = 0;
        let errorCount = 0;
        
        for (const record of csvData) {
            try {
                const analysisData = {
                    rawInput: record.testName,
                    processedInput: record.testName,
                    mode: 'vulnerable',
                    isMalicious: record.realVulnerability,
                    attackScore: record.realVulnerability ? 5 : 0,
                    attackPatterns: {},
                    encodingApplied: false,
                    inputLength: record.testName.length,
                    encodedLength: record.testName.length,
                    groundTruth: record.realVulnerability ? 'malicious' : 'clean'
                };
                
                await saveDetectionResult(db, analysisData);
                successCount++;
                
                if (successCount % 500 === 0) {
                    console.log(`   Processed ${successCount} records...`);
                }
            } catch (err) {
                errorCount++;
                if (errorCount <= 5) {
                    console.error(`   Error saving record ${record.testName}:`, err.message);
                }
            }
        }
        
        console.log(`\n✅ Database population completed!`);
        console.log(`   Successfully added: ${successCount} records`);
        console.log(`   Errors: ${errorCount} records`);
        
        db.close();
        
        // Step 5: Summary
        console.log('\n' + '='.repeat(60));
        console.log('✅ Setup Complete!');
        console.log('='.repeat(60));
        console.log('📊 Model: Random Forest trained and saved');
        console.log('🗄️  Database: Populated with', successCount, 'labeled samples');
        console.log('🔍 Next Steps:');
        console.log('   1. Restart your server: node server.js');
        console.log('   2. Visit http://localhost:3000/metrics to see results');
        console.log('   3. K-fold cross-validation and confusion matrix are ready!');
        console.log('='.repeat(60));
        
    } catch (err) {
        console.error('\n❌ Error during setup:', err);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    setupModelAndDatabase();
}

module.exports = { setupModelAndDatabase };
