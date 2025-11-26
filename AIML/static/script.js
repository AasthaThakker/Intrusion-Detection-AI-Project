// Tab Switching
function switchTab(tabName) {
    const tabs = document.querySelectorAll('.tab-content');
    const btns = document.querySelectorAll('.tab-btn');
    
    tabs.forEach(tab => tab.classList.remove('active'));
    btns.forEach(btn => btn.classList.remove('active'));
    
    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.classList.add('active');
}

// File Upload Handling
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');

dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInput.files = files;
        displayFileName(files[0].name);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        displayFileName(e.target.files[0].name);
    }
});

function displayFileName(name) {
    fileName.textContent = `Selected: ${name}`;
    fileName.style.display = 'block';
}

// Form Submission
const uploadForm = document.getElementById('uploadForm');
const analyzeBtn = document.getElementById('analyzeBtn');

uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const btnText = analyzeBtn.querySelector('.btn-text');
    const loadingSpinner = analyzeBtn.querySelector('.loading-spinner');
    
    // Show loading state
    btnText.style.display = 'none';
    loadingSpinner.style.display = 'inline';
    analyzeBtn.disabled = true;
    
    try {
        const formData = new FormData(uploadForm);
        
        const response = await fetch('/predict', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Error: ' + data.error);
            return;
        }
        
        displayResults(data);
    } catch (error) {
        alert('Error analyzing data: ' + error.message);
    } finally {
        // Reset button state
        btnText.style.display = 'inline';
        loadingSpinner.style.display = 'none';
        analyzeBtn.disabled = false;
    }
});

// Display Results
let pieChart = null;
let threeScene = null;

function displayResults(data) {
    // Show results section
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
    
    // Update stats
    document.getElementById('totalRecords').textContent = data.total_records;
    document.getElementById('intrusionCount').textContent = data.intrusion_count;
    document.getElementById('normalCount').textContent = data.normal_count;
    document.getElementById('intrusionPercentage').textContent = `${data.intrusion_percentage}%`;
    document.getElementById('normalPercentage').textContent = `${data.normal_percentage}%`;
    
    // Create pie chart
    createPieChart(data);
    
    // Create 3D visualization
    create3DVisualization(data);
    
    // Populate table
    populateTable(data.results);
}

function createPieChart(data) {
    const ctx = document.getElementById('pieChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (pieChart) {
        pieChart.destroy();
    }
    
    pieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Normal Traffic', 'Intrusions'],
            datasets: [{
                data: [data.normal_count, data.intrusion_count],
                backgroundColor: [
                    'rgba(0, 255, 136, 0.8)',
                    'rgba(255, 0, 85, 0.8)'
                ],
                borderColor: [
                    '#00ff88',
                    '#ff0055'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e0e6ed',
                        font: {
                            size: 14
                        },
                        padding: 20
                    }
                },
                tooltip: {
                    backgroundColor: '#131720',
                    titleColor: '#00ff88',
                    bodyColor: '#e0e6ed',
                    borderColor: '#1f2937',
                    borderWidth: 1,
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(2);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function create3DVisualization(data) {
    const container = document.getElementById('threeDView');
    container.innerHTML = '';
    
    const results = data.results || [];
    const maxNodes = 80;
    const sliced = results.slice(0, maxNodes);

    // Scene setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0e1a);
    
    const camera = new THREE.PerspectiveCamera(
        75,
        container.clientWidth / container.clientHeight,
        0.1,
        1000
    );
    camera.position.z = 18;
    
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);
    
    // Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.4);
    scene.add(ambientLight);
    
    const pointLight = new THREE.PointLight(0x00ff88, 1, 100);
    pointLight.position.set(10, 10, 10);
    scene.add(pointLight);
    
    // Central node (your monitored network)
    const centralGeometry = new THREE.SphereGeometry(1.2, 32, 32);
    const centralMaterial = new THREE.MeshPhongMaterial({ 
        color: 0x00d4ff,
        emissive: 0x00d4ff,
        emissiveIntensity: 0.5
    });
    const centralNode = new THREE.Mesh(centralGeometry, centralMaterial);
    scene.add(centralNode);
    
    const nodes = [];
    
    // Build nodes from actual results
    sliced.forEach((record, index) => {
        const isIntrusion = record.prediction === 'Intrusion';
        const severityScore = record.severity_score || (record.reasons ? record.reasons.length : 0);
        
        const baseRadius = isIntrusion ? 7 : 5;
        const radius = baseRadius + severityScore * 0.25;

        const angle = (index / sliced.length) * Math.PI * 2;
        const jitter = (Math.random() - 0.5) * 2;

        const nodeSize = 0.25 + Math.min(severityScore * 0.15, 0.6);

        const geometry = new THREE.SphereGeometry(nodeSize, 16, 16);
        const material = new THREE.MeshPhongMaterial({ 
            color: isIntrusion ? 0xff0055 : 0x00ff88,
            emissive: isIntrusion ? 0xff0055 : 0x00ff88,
            emissiveIntensity: isIntrusion ? 0.6 : 0.3
        });
        const node = new THREE.Mesh(geometry, material);
        
        node.position.x = Math.cos(angle) * radius;
        node.position.y = Math.sin(angle) * radius;
        node.position.z = jitter;

        scene.add(node);
        nodes.push({ mesh: node, isIntrusion, severityScore });

        // Connection line
        const lineMaterial = new THREE.LineBasicMaterial({ 
            color: isIntrusion ? 0xff0055 : 0x00ff88, 
            opacity: isIntrusion ? 0.6 : 0.3, 
            transparent: true 
        });
        const points = [centralNode.position.clone(), node.position.clone()];
        const lineGeometry = new THREE.BufferGeometry().setFromPoints(points);
        const line = new THREE.Line(lineGeometry, lineMaterial);
        scene.add(line);
    });
    
    // Animation
    let time = 0;
    function animate() {
        requestAnimationFrame(animate);
        time += 0.01;
        
        centralNode.rotation.y += 0.01;
        
        nodes.forEach((nodeObj, index) => {
            const node = nodeObj.mesh;
            const pulse = nodeObj.isIntrusion
                ? (Math.sin(time * 3 + index) + 1) * 0.02 * Math.min(nodeObj.severityScore + 1, 3)
                : (Math.sin(time * 2 + index) + 1) * 0.005;

            node.position.y += Math.sin(time + index) * 0.004;
            node.scale.set(1 + pulse, 1 + pulse, 1 + pulse);
        });
        
        // Orbit camera
        camera.position.x = Math.sin(time * 0.2) * 18;
        camera.position.z = Math.cos(time * 0.2) * 18;
        camera.lookAt(scene.position);
        
        renderer.render(scene, camera);
    }
    
    animate();
    
    // Handle window resize
    window.addEventListener('resize', () => {
        const width = container.clientWidth;
        const height = container.clientHeight;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setSize(width, height);
    });
}


function populateTable(results) {
    const tableBody = document.getElementById('resultsTableBody');
    tableBody.innerHTML = '';
    
    // Limit to first 100 results for performance
    const displayResults = results.slice(0, 100);
    
    displayResults.forEach(result => {
        const row = document.createElement('tr');
        
        const threatClass = result.threat_level === 'High' ? 'threat-high' : 'threat-low';
        const statusIcon = result.prediction === 'Intrusion' ? '⚠️' : '✅';

        const reasonsArray = result.reasons || [];
        const reasonsText = reasonsArray.length
            ? reasonsArray.slice(0, 3).join(' • ')
            : (result.prediction === 'Intrusion'
                ? 'Pattern similar to known attack traffic'
                : 'No obvious anomaly');

        row.innerHTML = `
            <td>${result.index}</td>
            <td>${statusIcon} ${result.prediction}</td>
            <td class="${threatClass}">${result.threat_level}</td>
            <td class="reason-cell" title="${reasonsArray.join(' | ')}">
                ${reasonsText}
            </td>
        `;
        
        tableBody.appendChild(row);
    });
    
    if (results.length > 100) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td colspan="4" style="text-align: center; color: var(--text-secondary);">
                ... and ${results.length - 100} more results
            </td>
        `;
        tableBody.appendChild(row);
    }
}
