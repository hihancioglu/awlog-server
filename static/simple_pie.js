class SimplePie {
  constructor(canvas, labels, values, opts={}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.labels = labels;
    this.values = values;
    this.colors = opts.colors || [
      '#3366cc', '#dc3912', '#ff9900', '#109618', '#990099',
      '#0099c6', '#dd4477', '#66aa00', '#b82e2e', '#316395'
    ];
    this.legend = opts.legend;
    this.format = opts.format || (v => String(v));
    this.draw();
  }
  draw() {
    const total = this.values.reduce((a,b)=>a+b,0) || 1;
    let start = -Math.PI/2;
    const {width, height} = this.canvas;
    const cx = width/2, cy = height/2;
    const r = Math.min(cx, cy) - 4;
    for(let i=0;i<this.values.length;i++){
      const val = this.values[i];
      const slice = val/total*2*Math.PI;
      this.ctx.beginPath();
      this.ctx.moveTo(cx,cy);
      this.ctx.arc(cx,cy,r,start,start+slice);
      this.ctx.closePath();
      this.ctx.fillStyle = this.colors[i%this.colors.length];
      this.ctx.fill();
      start += slice;
    }
    if(this.legend) this.drawLegend();
  }
  drawLegend() {
    const total = this.values.reduce((a,b)=>a+b,0) || 1;
    const ul = document.createElement('ul');
    ul.style.listStyle='none';
    ul.style.padding='0';
    for(let i=0;i<this.labels.length;i++){
      const li=document.createElement('li');
      const box=document.createElement('span');
      box.style.display='inline-block';
      box.style.width='12px';
      box.style.height='12px';
      box.style.marginRight='6px';
      box.style.background=this.colors[i%this.colors.length];
      li.appendChild(box);
      const valText=this.format(this.values[i]);
      li.appendChild(document.createTextNode(this.labels[i]+': '+valText));
      ul.appendChild(li);
    }
    this.legend.innerHTML='';
    this.legend.appendChild(ul);
  }
}
window.SimplePie = SimplePie;
