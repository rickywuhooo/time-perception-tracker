document.addEventListener('DOMContentLoaded', function () {
    const ctx = document.getElementById('analysisChart')?.getContext('2d');
    if (!ctx) return;

    const over = parseInt(document.getElementById('over-count').textContent);
    const under = parseInt(document.getElementById('under-count').textContent);
    const accurate = parseInt(document.getElementById('accurate-count').textContent);

    new Chart(ctx, {
        type: 'pie', 
        data: {
            labels: ['Overestimated', 'Underestimated', 'Accurate'],
            datasets: [{
                label: 'Task Count',
                data: [over, under, accurate],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.6)',   
                    'rgba(255, 206, 86, 0.6)',   
                    'rgba(75, 192, 192, 0.6)'    
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top'
                }
            },

            scales: {
                x: { display: false },
                y: { display: false }
            }
        }
    });
});
