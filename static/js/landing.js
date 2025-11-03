// Live Threat Counter animation (dummy data)
(function(){
  var el = document.getElementById('liveCounter');
  if(!el) return;
  var value = parseInt((el.textContent || '12904').replace(/,/g,''), 10) || 12904;
  function step(){
    var inc = Math.floor(Math.random()*6); // 0-5
    value += inc;
    el.textContent = value.toLocaleString();
  }
  setInterval(step, 800);
})();

// Attack pie chart (dummy distribution)
(function(){
  var ctx = document.getElementById('attackPie');
  if(!ctx) return;
  new Chart(ctx, {
    type: 'pie',
    data: {
      labels: ['SQLi', 'XSS', 'SSRF', 'Traversal', 'Other'],
      datasets: [{
        data: [34, 22, 14, 10, 20],
        backgroundColor: ['#1ad46a','#5ee488','#ffd25a','#ff8a65','#81d4fa']
      }]
    },
    options: {
      plugins: { legend: { labels: { color: '#cfeedd' } } }
    }
  });
})();

