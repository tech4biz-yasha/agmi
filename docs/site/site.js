
(function(){
  if(!window.matchMedia||!window.matchMedia('(prefers-reduced-motion: no-preference)').matches)return;
  var figs=document.querySelectorAll('.diag');if(!figs.length||!('IntersectionObserver' in window))return;
  figs.forEach(function(f){f.classList.add('arm');var b=document.createElement('button');b.type='button';b.className='replay';b.textContent='replay';b.setAttribute('aria-label','replay the animation');
    b.addEventListener('click',function(){f.classList.remove('play');void f.offsetWidth;f.classList.add('play')});f.appendChild(b)});
  var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('play');io.unobserve(e.target)}})},{threshold:.35});
  figs.forEach(function(f){io.observe(f)});
})();
(function(){
  var drawer=document.getElementById('drawer');if(!drawer)return;
  var q=function(id){return document.getElementById(id)};
  var names={};document.querySelectorAll('.matrix tbody th').forEach(function(th){});
  function open(btn){
    var row=btn.dataset.row,att=btn.dataset.attack,v=btn.dataset.verdict;
    var th=btn.closest('tr').querySelector('th');
    q('dkick').textContent=th.querySelector('.rowver')?th.querySelector('.rowver').textContent:'';
    q('dtitle').textContent=(th.querySelector('.rowname')?th.querySelector('.rowname').textContent:row)+', '+(btn.dataset.name||att);
    q('dverdict').textContent=v;q('dverdict').className='drawer-verdict '+({accepted:'v-acc',surfaced:'v-acc',rejected:'v-rej','kept out':'v-rej',reported:'v-rep'}[v]||'v-na');
    q('ddetail').textContent=btn.dataset.detail||'(no detail recorded)';
    q('dpoint').textContent=btn.dataset.point?(btn.dataset.point==='audit'?'audit: a separate call the operator has to make':'read: the read path itself'):'front door, read path';
    q('drepro').textContent='python agmi/full_runner.py --json results/scorecard.json   # row '+row+', attack '+att;
    drawer.hidden=false;drawer.querySelector('.drawer-close').focus();
  }
  function close(){drawer.hidden=true}
  document.addEventListener('click',function(e){
    var b=e.target.closest('.cellbtn');if(b){open(b);return}
    if(e.target.closest('.drawer-close')||e.target===drawer)close();
  });
  document.addEventListener('keydown',function(e){if(e.key==='Escape')close()});
})();
