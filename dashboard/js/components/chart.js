// dashboard/js/components/chart.js
// simple canvas-based charts so we don't need heavy dependencies like Chart.js

class SimpleChart {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.options = {
      type: 'line', // 'line' or 'bar'
      color: '#388bfd',
      fillColor: 'rgba(56, 139, 253, 0.1)',
      lineWidth: 2,
      padding: 10,
      labels: [], // x-axis labels
      data: [],   // y-axis data
      ...options
    };
    
    // handle resize
    this.resizeHandler = () => this.draw();
    window.addEventListener('resize', this.resizeHandler);
  }

  destroy() {
    window.removeEventListener('resize', this.resizeHandler);
  }

  update(data, labels) {
    if (data) this.options.data = data;
    if (labels) this.options.labels = labels;
    this.draw();
  }

  draw() {
    const { ctx, canvas, options } = this;
    const { data, type, color, fillColor, lineWidth, padding } = options;

    if (!data || data.length === 0) return;

    // ensure canvas resolution matches display size
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;

    const w = canvas.width;
    const h = canvas.height;
    
    ctx.clearRect(0, 0, w, h);

    const max = Math.max(...data, 1); // avoid division by zero
    const min = 0; // always start at zero for these charts

    const graphW = w - (padding * 2);
    const graphH = h - (padding * 2);
    
    if (type === 'bar') {
      const barW = (graphW / data.length) * 0.8;
      const gap = (graphW / data.length) * 0.2;
      
      ctx.fillStyle = color;
      data.forEach((val, i) => {
        const barH = (val / max) * graphH;
        const x = padding + (i * (barW + gap)) + (gap / 2);
        const y = h - padding - barH;
        
        // draw bar
        ctx.beginPath();
        ctx.roundRect(x, y, barW, barH, [4, 4, 0, 0]);
        ctx.fill();
      });
    } else {
      // line chart
      const stepX = graphW / (data.length - 1 || 1);
      
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth = lineWidth;
      ctx.lineJoin = 'round';
      
      data.forEach((val, i) => {
        const x = padding + (i * stepX);
        const y = h - padding - ((val / max) * graphH);
        
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      
      ctx.stroke();

      // fill
      if (fillColor) {
        ctx.lineTo(w - padding, h - padding);
        ctx.lineTo(padding, h - padding);
        ctx.fillStyle = fillColor;
        ctx.fill();
      }
    }

    // draw max value label
    ctx.fillStyle = '#8b949e';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(Format.formatNumber(max), w - 5, 12);
  }
}

window.SimpleChart = SimpleChart;
