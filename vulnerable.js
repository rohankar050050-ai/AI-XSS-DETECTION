(() => {
    let analysis = {};
    
    function parseAnalysisData() {
        try {
            const dataEl = document.getElementById('analysis-data');
            if (dataEl) {
                const text = dataEl.textContent || dataEl.innerText || '';
                if (text.trim()) {
                    try {
                        analysis = JSON.parse(text);
                        console.log('Analysis data loaded:', analysis);
                        return true;
                    } catch (e) {
                        console.error('Failed to parse analysis data JSON:', e, 'Raw text:', text.substring(0, 100));
                    }
                } else {
                    console.warn('Analysis data element is empty');
                }
            } else {
                console.warn('Analysis data element not found');
            }
        } catch (e) {
            console.error('Error accessing analysis data element:', e);
        }
        return false;
    }
    
    // Try to parse immediately if DOM is ready
    if (document.readyState !== 'loading') {
        parseAnalysisData();
    }

    const outputElement = document.getElementById('output-area');
    const statusElement = document.getElementById('status');
    const statusCard = document.getElementById('status-card');

    function getRawInputFromURL() {
        const urlParams = new URLSearchParams(window.location.search);
        const q = urlParams.get('q');
        if (!q) return 'Default Search Term';
        try {
            return decodeURIComponent(q);
        } catch (e) {
            return q;
        }
    }

    function initializeUI() {
        try {
            // Try to parse analysis data if not already parsed
            if (!analysis || !analysis.rawInput) {
                parseAnalysisData();
            }

            // Fallback to URL parsing if analysis data is incomplete
            if (!analysis || !analysis.rawInput || analysis.inputLength === 0) {
                const rawInput = getRawInputFromURL();
                const mode = new URLSearchParams(window.location.search).get('mode') || 'vulnerable';

                const attackPatterns = {
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

                const attackScore = Object.values(attackPatterns).filter(Boolean).length;
                const isMalicious = attackScore > 0;

                const processedInput = outputElement ? (outputElement.textContent || outputElement.innerText || '') : '';
                const encodingApplied = mode === 'secure' && processedInput !== rawInput;

                analysis = {
                    rawInput,
                    processedInput,
                    mode,
                    encodingApplied,
                    attackPatterns,
                    attackScore,
                    isMalicious,
                    inputLength: rawInput.length,
                    encodedLength: processedInput.length,
                    timestamp: new Date().toISOString()
                };
            }
        } catch (e) {
            console.error('Error in initializeUI:', e);
            // Set default analysis if everything fails
            analysis = {
                rawInput: getRawInputFromURL(),
                processedInput: '',
                mode: 'vulnerable',
                encodingApplied: false,
                attackPatterns: {},
                attackScore: 0,
                isMalicious: false,
                inputLength: 0,
                encodedLength: 0,
                timestamp: new Date().toISOString()
            };
        }

        try {
            const rawInputDisplay = document.getElementById('raw-input-display');
            if (rawInputDisplay) {
                rawInputDisplay.textContent = analysis.rawInput || 'No input';
            }

            const inputLengthEl = document.getElementById('input-length');
            if (inputLengthEl) {
                inputLengthEl.textContent = analysis.inputLength || 0;
            }

            const encodedLengthEl = document.getElementById('encoded-length');
            if (encodedLengthEl) {
                encodedLengthEl.textContent = analysis.encodedLength || 0;
            }

            const securityModeEl = document.getElementById('security-mode-display');
            if (securityModeEl) {
                securityModeEl.textContent = analysis.mode === 'secure' ? 'SECURE' : 'VULNERABLE';
            }

            const attackScoreEl = document.getElementById('attack-score-display');
            if (attackScoreEl) {
                attackScoreEl.textContent = analysis.attackScore || 0;
            }

            // Always update status first to remove "Analyzing input..." message
            checkXSSStatus();
            renderAttackPatterns();
            renderFlowDiagram();
            renderCharts();
            renderAnalysisTable();
            renderEncodingComparison();
        } catch (e) {
            console.error('Error rendering UI:', e);
            // At least update the status to show something
            if (statusElement) {
                statusElement.innerHTML = '<b>ERROR:</b> Failed to analyze input. Please try again.';
                if (statusCard) {
                    statusCard.className = 'status-card neutral';
                }
            }
        }
    }

    function checkXSSStatus() {
        if (!statusElement || !statusCard) {
            console.error('Status elements not found');
            return;
        }

        let statusText = '';
        let statusClass = 'neutral';
        
        // Check if analysis data is available
        if (!analysis || analysis.attackScore === undefined) {
            statusText = '<b>ANALYZING:</b> Processing input data...';
            statusClass = 'neutral';
        } else {
            // Clear detection status based on isMalicious flag
            if (analysis.isMalicious) {
                statusText = '<b>ATTACK DETECTED:</b> XSS attack patterns found in the input!';
                statusClass = 'detection';
            } else {
                statusText = '<b>NO ATTACK DETECTED:</b> The input appears to be clean and safe.';
                statusClass = 'prevention';
            }
        }
        
        statusElement.innerHTML = statusText;
        statusCard.className = `status-card ${statusClass}`;
    }

    function renderAttackPatterns() {
        const patterns = analysis.attackPatterns || {};
        const container = document.getElementById('attack-patterns');
        container.innerHTML = '';

        const patternNames = {
            scriptTag: '&lt;script&gt; Tag',
            scriptClosing: '&lt;/script&gt; Tag',
            onerror: 'onerror Event',
            onclick: 'onclick Event',
            javascript: 'javascript: Protocol',
            imgTag: '&lt;img&gt; Tag',
            iframeTag: '&lt;iframe&gt; Tag',
            eval: 'eval() Function',
            alert: 'alert() Function'
        };

        for (const [key, detected] of Object.entries(patterns)) {
            const div = document.createElement('div');
            div.className = `pattern-item ${detected ? 'detected' : 'safe'}`;
            div.innerHTML = `
                <div>${patternNames[key] || key}</div>
                <div style="font-size: 1.5em; margin-top: 5px;">
                    ${detected ? 'WARNING' : 'OK'}
                </div>
            `;
            container.appendChild(div);
        }
    }

    function renderFlowDiagram() {
        const container = document.getElementById('flow-steps');
        container.innerHTML = '';

        const steps = [
            { number: '1', title: 'User Input', desc: 'Raw input received' },
            { number: '2', title: 'Pattern Scan', desc: 'Analyzing for threats' },
            { number: '3', title: analysis.mode === 'secure' ? 'Encoding' : 'No Encoding', desc: analysis.mode === 'secure' ? 'HTML entities applied' : 'Raw output' },
            { number: '4', title: 'Browser Render', desc: 'DOM processing' },
            { number: '5', title: analysis.isMalicious && analysis.mode === 'vulnerable' ? 'Attack' : 'Safe', desc: analysis.isMalicious && analysis.mode === 'vulnerable' ? 'XSS executed' : 'Protected' }
        ];

        steps.forEach((step, index) => {
            const div = document.createElement('div');
            div.className = 'flow-step';
            if (index === 2 || (index === 4 && analysis.isMalicious)) {
                div.classList.add('active');
            }
            div.innerHTML = `
                <div class="flow-step-number">${step.number}</div>
                <div style="font-weight: bold; margin-bottom: 5px;">${step.title}</div>
                <div style="font-size: 0.9em; opacity: 0.8;">${step.desc}</div>
            `;
            container.appendChild(div);
        });
    }

    function renderCharts() {
        // Text-only fallbacks (charts disabled)
        const patterns = analysis.attackPatterns || {};
        const patternData = Object.values(patterns).filter(Boolean).length;
        const safePatterns = Object.values(patterns).length - patternData;

        const patternCanvas = document.getElementById('patternChart');
        if (patternCanvas) {
            const div = document.createElement('div');
            div.id = 'patternChart';
            div.style.padding = '20px';
            div.style.textAlign = 'center';
            div.innerHTML = `
                <div style="font-weight:bold;">Detected Patterns: ${patternData}</div>
                <div>Safe Patterns: ${safePatterns}</div>
            `;
            patternCanvas.replaceWith(div);
        }

        const securityCanvas = document.getElementById('securityChart');
        if (securityCanvas) {
            const effectiveness = analysis.mode === 'secure' && analysis.encodingApplied ? 100 :
                                 (analysis.mode === 'vulnerable' ? 0 : 50);
            const div = document.createElement('div');
            div.id = 'securityChart';
            div.style.padding = '20px';
            div.style.textAlign = 'center';
            div.innerHTML = `
                <div style="font-weight:bold;">Protection Level: ${effectiveness}%</div>
                <div>${analysis.mode === 'secure' ? 'Secure mode (encoding on)' : 'Vulnerable mode (no encoding)'}</div>
            `;
            securityCanvas.replaceWith(div);
        }
    }

    function renderAnalysisTable() {
        const table = document.getElementById('analysis-table');
        table.innerHTML = '';

        const rows = [
            ['Mode', analysis.mode === 'secure' ? 'Secure (Prevention Enabled)' : 'Vulnerable (No Protection)', analysis.mode === 'secure' ? 'OK' : 'WARNING'],
            ['Encoding Applied', analysis.encodingApplied ? 'Yes' : 'No', analysis.encodingApplied ? 'OK' : 'NO'],
            ['Malicious Input', analysis.isMalicious ? 'Yes' : 'No', analysis.isMalicious ? 'WARNING' : 'OK'],
            ['Attack Score', analysis.attackScore || 0, analysis.attackScore > 5 ? 'HIGH' : analysis.attackScore > 0 ? 'MEDIUM' : 'OK'],
            ['Input Length', analysis.inputLength || 0, '-'],
            ['Encoded Length', analysis.encodedLength || 0, '-'],
            ['Timestamp', new Date(analysis.timestamp || Date.now()).toLocaleString(), '-']
        ];

        rows.forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${row[0]}</strong></td>
                <td>${row[1]}</td>
                <td style="text-align: center; font-size: 1.2em;">${row[2]}</td>
            `;
            table.appendChild(tr);
        });
    }

    function renderEncodingComparison() {
        const container = document.getElementById('encoding-comparison');
        const raw = analysis.rawInput || '';
        const processed = analysis.processedInput || '';

        container.innerHTML = `
            <div style="margin-bottom: 10px;"><strong>Raw Input:</strong></div>
            <div style="color: #e74c3c; margin-bottom: 20px;">${escapeHtml(raw)}</div>
            <div style="margin-bottom: 10px;"><strong>Encoded Output:</strong></div>
            <div style="color: #27ae60;">${escapeHtml(processed)}</div>
        `;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function switchMode(mode) {
        console.log('Switching to mode:', mode);
        const url = new URL(window.location);
        url.searchParams.set('mode', mode);
        // Preserve the current query parameter or use a default
        const currentQ = url.searchParams.get('q');
        if (!currentQ || currentQ === 'Default Search Term') {
            const defaultPayload = '<script>alert("XSS")</script>';
            url.searchParams.set('q', defaultPayload);
        }
        console.log('Navigating to:', url.toString());
        window.location.href = url.toString();
    }

    // Initialize when DOM is ready
    function startInitialization() {
        // Parse analysis data first
        parseAnalysisData();
        
        // Initialize UI
        initializeUI();
        
        // Setup mode buttons
        setupModeButtons();
        
        // Fallback: Update status after a short delay if still showing "Analyzing..."
        setTimeout(() => {
            if (statusElement && statusElement.textContent.includes('Analyzing')) {
                console.warn('Status still showing "Analyzing" after timeout, forcing update');
                checkXSSStatus();
            }
        }, 500);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startInitialization);
    } else {
        // DOM is already loaded
        startInitialization();
    }

    function setupModeButtons() {
        const mode = analysis.mode || new URLSearchParams(window.location.search).get('mode') || 'vulnerable';
        const buttons = document.querySelectorAll('.mode-btn');
        
        console.log('Setting up mode buttons. Current mode:', mode, 'Found buttons:', buttons.length);
        
        // Use event delegation on the parent container to avoid duplicate listeners
        const modeSelector = document.querySelector('.mode-selector');
        if (modeSelector) {
            // Remove any existing listener by cloning the container (cleaner approach)
            const newContainer = modeSelector.cloneNode(true);
            modeSelector.parentNode.replaceChild(newContainer, modeSelector);
            
            // Now set up buttons on the new container
            const newButtons = newContainer.querySelectorAll('.mode-btn');
            newButtons.forEach(btn => {
                const btnMode = btn.dataset.mode || (btn.classList.contains('secure') ? 'secure' : 'vulnerable');
                
                // Set active state
                if (btnMode === mode) {
                    btn.classList.add('active');
                }
                
                // Add click event listener
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('Mode button clicked:', btnMode);
                    switchMode(btnMode);
                });
            });
        } else {
            // Fallback: direct button setup
            buttons.forEach(btn => {
                const btnMode = btn.dataset.mode || (btn.classList.contains('secure') ? 'secure' : 'vulnerable');
                
                if (btnMode === mode) {
                    btn.classList.add('active');
                }
                
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('Mode button clicked:', btnMode);
                    switchMode(btnMode);
                });
            });
        }
    }
})();

