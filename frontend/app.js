document.addEventListener('DOMContentLoaded', () => {
    // Nav elements
    const navScanner = document.getElementById('nav-scanner');
    const navHistory = document.getElementById('nav-history');
    const viewScanner = document.getElementById('view-scanner');
    const viewHistory = document.getElementById('view-history');

    // Scanner elements
    const targetUrlInput = document.getElementById('target-url');
    const delayInput = document.getElementById('delay');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statusIndicator = document.getElementById('status-indicator');
    const resultsBody = document.getElementById('results-body');
    const statusText = statusIndicator.querySelector('.text');
    
    // Stats elements
    const progressBarFill = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const cvssScoreDisplay = document.getElementById('cvss-score');
    const cvssSeverityDisplay = document.getElementById('cvss-severity');
    const funFactDisplay = document.getElementById('fun-fact');

    let pollInterval = null;
    let quoteInterval = null;

    const funFacts = [
        "\"Security is not a product, but a process.\" - Bruce Schneier",
        "A single SQL Injection payload can dump an entire database in seconds.",
        "Cross-Site Scripting (XSS) is responsible for over 40% of web vulnerabilities.",
        "\"Amateurs hack systems, professionals hack people.\" - Bruce Schneier",
        "Fuzzing was originally developed in 1988 by Barton Miller at UW-Madison.",
        "Over 80% of cyber attacks are driven by highly organized crime rings.",
        "The first computer virus was created in 1983 and was called 'Elk Cloner'.",
        "A zero-day vulnerability is a flaw that is unknown to the vendor.",
        "\"Given enough eyeballs, all bugs are shallow.\" - Linus's Law",
        "Cybersecurity ventures predict cybercrime damages will cost $10.5 trillion by 2025."
    ];

    // Navigation logic
    function switchView(viewId) {
        navScanner.classList.remove('active');
        navHistory.classList.remove('active');
        viewScanner.classList.remove('active-view');
        viewHistory.classList.remove('active-view');

        if (viewId === 'scanner') {
            navScanner.classList.add('active');
            viewScanner.classList.add('active-view');
        } else {
            navHistory.classList.add('active');
            viewHistory.classList.add('active-view');
        }
    }

    navScanner.addEventListener('click', () => switchView('scanner'));
    navHistory.addEventListener('click', () => switchView('history'));

    // Quotes Rotator (every 11 seconds)
    function startQuotes() {
        if (quoteInterval) clearInterval(quoteInterval);
        quoteInterval = setInterval(() => {
            const randomFact = funFacts[Math.floor(Math.random() * funFacts.length)];
            funFactDisplay.style.opacity = 0;
            setTimeout(() => {
                funFactDisplay.textContent = randomFact;
                funFactDisplay.style.opacity = 1;
            }, 500); // fade transition
        }, 11000);
    }
    startQuotes();

    startBtn.addEventListener('click', async () => {
        const targetUrl = targetUrlInput.value.trim();
        const delayMs = parseInt(delayInput.value) || 100;
        const intensity = document.getElementById('intensity').value;

        if (!targetUrl) {
            alert("Please provide a Base Target URL.");
            return;
        }

        const tableContainer = document.querySelector('.table-container');
        tableContainer.className = 'table-container glow-' + intensity;

        try {
            const response = await fetch('/api/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target_url: targetUrl,
                    intensity: intensity,
                    delay_ms: delayMs
                })
            });

            const data = await response.json();
            
            if (data.status === 'success') {
                setRunningState(true);
                resultsBody.innerHTML = ''; // Clear previous results
                progressBarFill.style.width = '0%';
                progressText.textContent = '0% (Initializing crawler...)';
                cvssScoreDisplay.textContent = '0.0';
                cvssScoreDisplay.style.color = 'var(--neon-green)';
                cvssSeverityDisplay.textContent = 'NONE';
                startPolling();
            } else {
                alert(data.message);
            }
        } catch (error) {
            console.error("Error starting fuzzer:", error);
            alert("Failed to start fuzzer. Is the backend running?");
        }
    });

    stopBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/stop', { method: 'POST' });
            setRunningState(false);
            stopPolling();
            // Do one last poll to get final results
            fetchResults();
        } catch (error) {
            console.error("Error stopping fuzzer:", error);
        }
    });

    function setRunningState(isRunning) {
        if (isRunning) {
            startBtn.disabled = true;
            stopBtn.disabled = false;
            statusIndicator.classList.add('running');
            statusText.textContent = 'ATTACKING';
        } else {
            startBtn.disabled = false;
            stopBtn.disabled = true;
            statusIndicator.classList.remove('running');
            statusText.textContent = 'IDLE';
            progressText.textContent = 'Completed.';
            progressBarFill.style.width = '100%';
        }
    }

    function startPolling() {
        if (pollInterval) clearInterval(pollInterval);
        // Polling every 7 seconds as requested!
        pollInterval = setInterval(fetchResults, 7000);
    }

    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }

    async function fetchResults() {
        try {
            const response = await fetch('/api/results');
            const data = await response.json();

            // Render table
            renderResults(data.results);

            // Update Progress Bar
            if (data.total_requests > 0) {
                const percent = Math.round((data.completed_requests / data.total_requests) * 100);
                progressBarFill.style.width = percent + '%';
                progressText.textContent = percent + '% (' + data.completed_requests + '/' + data.total_requests + ')';
            }

            // Update CVSS Display
            if (data.max_cvss !== undefined) {
                cvssScoreDisplay.textContent = data.max_cvss.toFixed(1);
                if (data.max_cvss >= 9.0) {
                    cvssScoreDisplay.style.color = '#ff0000';
                    cvssSeverityDisplay.textContent = 'CRITICAL';
                } else if (data.max_cvss >= 7.0) {
                    cvssScoreDisplay.style.color = '#ff3333';
                    cvssSeverityDisplay.textContent = 'HIGH';
                } else if (data.max_cvss >= 4.0) {
                    cvssScoreDisplay.style.color = '#FFA500';
                    cvssSeverityDisplay.textContent = 'MODERATE';
                } else if (data.max_cvss > 0) {
                    cvssScoreDisplay.style.color = 'var(--neon-green)';
                    cvssSeverityDisplay.textContent = 'LOW';
                }
            }

            if (!data.is_running && statusIndicator.classList.contains('running')) {
                setRunningState(false);
                stopPolling();
            }
        } catch (error) {
            console.error("Error fetching results:", error);
        }
    }

    function renderResults(results) {
        resultsBody.innerHTML = '';
        
        results.forEach(result => {
            const tr = document.createElement('tr');
            
            let statusClass = 'status-0';
            if (result.status_code >= 200 && result.status_code < 300) statusClass = 'status-2xx';
            else if (result.status_code >= 300 && result.status_code < 400) statusClass = 'status-3xx';
            else if (result.status_code >= 400 && result.status_code < 500) statusClass = 'status-4xx';
            else if (result.status_code >= 500) statusClass = 'status-5xx';

            tr.innerHTML = `
                <td class="payload-cell" title="${escapeHtml(result.payload)}">${escapeHtml(result.payload)}</td>
                <td class="${statusClass}">${result.status_code || 'ERR'}</td>
                <td>${result.length}</td>
                <td>${result.time_ms}</td>
                <td class="payload-cell" title="${escapeHtml(result.error || '')}">${escapeHtml(result.error || '-')}</td>
            `;
            
            resultsBody.appendChild(tr);
        });
        
        // Scroll to bottom
        const container = document.querySelector('.table-container');
        container.scrollTop = container.scrollHeight;
    }

    function escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return unsafe
             .toString()
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // --- History Logic ---
    let historyData = [];
    let currentSort = { column: 'date', asc: false };

    async function loadHistory() {
        try {
            const response = await fetch('/api/scans');
            const data = await response.json();
            if (data.status === 'success') {
                historyData = data.scans;
                renderHistory();
            }
        } catch (e) {
            console.error("Failed to load history", e);
        }
    }

    function renderHistory() {
        const tbody = document.getElementById('history-body');
        if (!tbody) return;
        tbody.innerHTML = '';
        
        // Sort data
        historyData.sort((a, b) => {
            let valA = a[currentSort.column] || '';
            let valB = b[currentSort.column] || '';
            
            if (currentSort.column === 'date') {
                valA = new Date(a.start_time).getTime() || 0;
                valB = new Date(b.start_time).getTime() || 0;
            } else if (currentSort.column === 'params') {
                valA = a.total_findings;
                valB = b.total_findings;
            }
            
            if (valA < valB) return currentSort.asc ? -1 : 1;
            if (valA > valB) return currentSort.asc ? 1 : -1;
            return 0;
        });

        historyData.forEach(scan => {
            const tr = document.createElement('tr');
            let dateStr = scan.start_time ? new Date(scan.start_time).toLocaleString() : 'N/A';
            tr.innerHTML = `
                <td>${scan.id}</td>
                <td>${escapeHtml(scan.url)}</td>
                <td style="text-transform: uppercase">${scan.mode}</td>
                <td>${dateStr}</td>
                <td>${scan.total_findings}</td>
                <td style="color: ${scan.max_cvss >= 7 ? '#ff3333' : 'var(--neon-green)'}; font-weight: bold;">${scan.max_cvss.toFixed(1)}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    document.querySelectorAll('#history-table th').forEach(th => {
        th.addEventListener('click', () => {
            const column = th.getAttribute('data-sort');
            if (currentSort.column === column) {
                currentSort.asc = !currentSort.asc;
            } else {
                currentSort.column = column;
                currentSort.asc = true;
            }
            renderHistory();
        });
    });

    // Override the history nav click to also load data
    navHistory.addEventListener('click', () => {
        loadHistory();
    });
});
