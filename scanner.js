// Test if script is loading
console.log('scanner.js loaded');

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scannerForm');
    const inputField = document.getElementById('inputCommand');

    if (!form) {
        console.error('Scanner form not found!');
        return;
    }

    if (!inputField) {
        console.error('Input field not found!');
        return;
    }

    function handleScan() {
        const command = inputField.value.trim();
        const groundTruthElement = document.getElementById('groundTruth');
        const groundTruth = groundTruthElement ? groundTruthElement.value : '';
        
        if (!command) {
            alert('Please enter a command or payload to scan');
            inputField.focus();
            return false;
        }

        // Encode the input for URL
        const encodedInput = encodeURIComponent(command);
        let url = `/search?mode=vulnerable&q=${encodedInput}`;
        
        // Add ground truth if specified
        if (groundTruth) {
            url += `&truth=${encodeURIComponent(groundTruth)}`;
        }
        
        console.log('Navigating to:', url);
        
        // Navigate to results page
        window.location.href = url;
        return false;
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        e.stopPropagation();
        return handleScan();
    });

    console.log('Scanner form initialized successfully');

    // Also add direct button click handler as fallback
    const scanButton = form.querySelector('button[type="submit"]');
    if (scanButton) {
        scanButton.addEventListener('click', (e) => {
            console.log('Scan button clicked directly');
            // Prevent double submission
            if (e.target === scanButton) {
                e.preventDefault();
                handleScan();
            }
        });
    }
});

function loadExample(payload, groundTruth = '') {
    const inputField = document.getElementById('inputCommand');
    const groundTruthSelect = document.getElementById('groundTruth');
    
    if (inputField) {
        inputField.value = payload;
    }
    
    if (groundTruth && groundTruthSelect) {
        groundTruthSelect.value = groundTruth;
    }
}

