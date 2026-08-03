const { initDatabase, saveDetectionResult } = require('./database');
const { parseCSV } = require('./train_from_csv');
const path = require('path');

const CSV_PATH = path.join(__dirname, 'dataset', 'css1.csv');

// Populate database with CSV data
async function populateDatabase() {
    try {
        console.log('Initializing database...');
        const db = await initDatabase();
        
        console.log('Reading CSV file:', CSV_PATH);
        const csvData = parseCSV(CSV_PATH);
        console.log(`Loaded ${csvData.length} records from CSV`);
        
        console.log('Populating database...');
        let successCount = 0;
        let errorCount = 0;
        
        for (const record of csvData) {
            try {
                // Create a mock analysis data structure
                // Use test name as raw_input for feature extraction
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
                
                if (successCount % 100 === 0) {
                    console.log(`Processed ${successCount} records...`);
                }
            } catch (err) {
                errorCount++;
                if (errorCount <= 5) {
                    console.error(`Error saving record ${record.testName}:`, err.message);
                }
            }
        }
        
        console.log('\n✅ Database population completed!');
        console.log(`   Successfully added: ${successCount} records`);
        console.log(`   Errors: ${errorCount} records`);
        console.log(`\nYou can now use the confusion matrix and k-fold cross-validation with this data.`);
        
        db.close();
    } catch (err) {
        console.error('Error populating database:', err);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    populateDatabase();
}

module.exports = { populateDatabase };
