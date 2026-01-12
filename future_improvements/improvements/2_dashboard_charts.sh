#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# IMPROVEMENT 2: Add Dashboard Charts
# Time: 2 hours
# Priority: HIGH (Makes demo impressive)
# ═══════════════════════════════════════════════════════════════

echo "📊 IMPROVEMENT 2: Adding Dashboard Charts"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd ../..

# Create charts component
cat > templates/components/charts.html << 'CHARTS'
<!-- Dashboard Charts with Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>

<div class="row mt-4">
    <div class="col-lg-6 mb-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-chart-line"></i> Threat Trends (Last 7 Days)</h5>
            </div>
            <div class="card-body">
                <canvas id="threatTrendsChart" height="80"></canvas>
            </div>
        </div>
    </div>
    
    <div class="col-lg-6 mb-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-chart-pie"></i> Threat Distribution</h5>
            </div>
            <div class="card-body">
                <canvas id="threatTypesChart" height="80"></canvas>
            </div>
        </div>
    </div>
</div>

<script>
// Threat Trends Line Chart
const trendCtx = document.getElementById('threatTrendsChart');
if (trendCtx) {
    new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Threats Detected',
                data: [12, 19, 8, 15, 22, 18, 25],
                borderColor: 'rgba(79, 172, 254, 1)',
                backgroundColor: 'rgba(79, 172, 254, 0.1)',
                tension: 0.4,
                fill: true,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#fff', font: { size: 12 } }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: 'rgba(255,255,255,0.7)' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                },
                x: {
                    ticks: { color: 'rgba(255,255,255,0.7)' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                }
            }
        }
    });
}

// Threat Types Doughnut Chart
const typeCtx = document.getElementById('threatTypesChart');
if (typeCtx) {
    new Chart(typeCtx, {
        type: 'doughnut',
        data: {
            labels: ['Malware', 'Data Leak', 'Unauthorized', 'Other'],
            datasets: [{
                data: [45, 25, 20, 10],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(16, 185, 129, 0.8)'
                ],
                borderColor: '#1e293b',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { 
                        color: '#fff', 
                        padding: 15,
                        font: { size: 11 }
                    }
                }
            }
        }
    });
}
</script>
CHARTS

echo "✅ Charts component created: templates/components/charts.html"
echo ""
echo "📝 To use:"
echo "   Add to dashboard.html before {% endblock %}:"
echo "   {% include 'components/charts.html' %}"
echo ""
