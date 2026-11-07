/* "xx" homepage theme — runtime wiring.
   Runs after xx/homepage.html has been placed inside the shadow root of #dmXx.
   Everything the page needs from the live store (products, cart, wishlist, account,
   product popup, category / gender popups) is reached through the store's own global
   functions, so nothing is duplicated here. */
(function () {
  var host = document.getElementById('dmXx');
  var R = host && host.shadowRoot;
  if (!R || R.__xxInit) return;
  R.__xxInit = true;

  var WA = 'https://wa.me/917004847813';
  function $(id) { return R.getElementById(id); }
  function g(name) { return typeof window[name] === 'function' ? window[name] : null; }
  function esc(t) { return String(t == null ? '' : t).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function inr(n) { return Math.round(Number(n) || 0).toLocaleString('en-IN'); }
  function reduced() { return window.matchMedia && matchMedia('(prefers-reduced-motion:reduce)').matches; }

  /* ---------- products (live from the store's API) ---------- */
  var all = null, loading = null;
  function tileImg(cat) { var i = R.querySelector('.tc[data-cat="' + cat + '"] img'); return i ? i.src : ''; }
  function tileIcon(cat) { var s = R.querySelector('.tc[data-cat="' + cat + '"] .ti svg'); return s ? s.outerHTML : ''; }
  function norm(p) {
    var price = Number(p.price) || 0, sale = null;
    if (p.onSale && p.salePercent && p.saleActive !== false) sale = Math.round(price * (100 - p.salePercent)) / 100;
    var cat = p.category || 'Other';
    return {
      id: p.id, name: p.name || '', cat: cat, price: sale || price, old: sale ? price : 0,
      desc: p.description || '', moq: p.moq || 1, img: p.image || tileImg(cat), own: !!p.image,
      pct: Number(p.buyBadgePercent) > 0 ? Number(p.buyBadgePercent) : 10,
      badge: Number(p.buyBadgePercent) > 0, popular: !!p.popular, trending: !!p.trending,
      month: Number(p.soldMonth) || 0, total: Number(p.soldTotal) || 0
    };
  }
  function load() {
    if (all) return Promise.resolve(all);
    if (loading) return loading;
    loading = fetch('/api/products', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw 0; return r.json(); })
      .then(function (d) { return (d && d.success && d.products) ? d.products.map(norm) : []; })
      .catch(function () { return []; })
      .then(function (a) { all = a; return a; });
    return loading;
  }

  /* ---------- opening things in the live store ---------- */
  function openProduct(id) { var f = g('openProductModal'); if (f) f(Number(id)); }
  function openCat(cat) {
    var f = g('filterCategoryFromCard'); if (f) { f(cat || 'All'); return; }
    openShop(cat || 'All');
  }
  function openGender(x) { var f = g('openGenderModal'); if (f) f(String(x).toLowerCase()); }

  /* ---------- product cards (offers + best sellers) ---------- */
  function wished(id) { try { var f = g('wishlistIds'); return f ? f().indexOf(Number(id)) >= 0 : false; } catch (e) { return false; } }
  function media(p) {
    if (p.img) return '<img src="' + esc(p.img) + '" alt="' + esc(p.name) + '" loading="lazy">';
    return tileIcon(p.cat);
  }
  function card(p, top, extra) {
    var w = wished(p.id);
    return '<article class="pc" data-id="' + esc(p.id) + '" tabindex="0" role="button" aria-label="' + esc(p.name) + '" style="cursor:pointer">' +
      '<div class="pc-i">' + media(p) + top +
      '<button type="button" class="pc-ht" aria-pressed="' + w + '" aria-label="Add ' + esc(p.name) + ' to wishlist">' + (w ? '&#9829;' : '&#9825;') + '</button></div>' +
      '<div class="pc-b"><span class="pc-c">' + esc(p.cat) + '</span><h3 class="pc-n">' + esc(p.name) + '</h3>' +
      '<div class="pc-p">&#8377;' + inr(p.price) + (p.old ? '<s style="font:400 12px Poppins,sans-serif;color:#a99;margin-left:5px">&#8377;' + inr(p.old) + '</s>' : '') + '</div>' +
      '<div class="pc-m">MOQ: ' + p.moq + '</div>' + (extra || '') + '</div></article>';
  }
  var S = { offers: [], best: [], hasSales: false };
  function renderSections() {
    var og = $('offerGrid'), sg = $('soldGrid'), os = $('offers'), ss = $('sellers');
    var seen = {};
    var offers = all.filter(function (p) { return p.badge || p.popular || p.trending; }).filter(function (p) { if (seen[p.id]) return false; seen[p.id] = 1; return true; }).slice(0, 6);
    // Real sales first ("Most sold this month"); until there are any orders, fall back to the most-viewed products.
    var sold = all.filter(function (p) { return p.total > 0; }).sort(function (a, b) { return (b.month - a.month) || (b.total - a.total); }).slice(0, 6);
    var hasSales = sold.length > 0, best = sold;
    if (!hasSales) { best = all.filter(function (p) { return p.popular; }); if (!best.length) best = all.filter(function (p) { return p.trending; }); best = best.slice(0, 6); }
    S = { offers: offers, best: best, hasSales: hasSales };
    var max = Math.max.apply(null, best.map(function (p) { return p.month; }).concat([1]));
    if (og) og.innerHTML = offers.map(function (p) {
      var bulk = Math.round(p.price * 10 * (100 - p.pct) / 100);
      return card(p, '<span class="pc-o">BUY 10 @ Rs.' + inr(bulk) + '<i>' + p.pct + '% OFF</i></span>');
    }).join('');
    if (sg) sg.innerHTML = best.map(function (p, k) {
      return card(p, '<span class="pc-rk" aria-label="Rank ' + (k + 1) + '">' + (k + 1) + '</span>', hasSales ?
        '<div class="pc-s"><div class="a"><b>' + inr(p.month) + '</b> sold this month</div><div class="pc-bar"><i style="width:' + Math.max(4, Math.round(p.month / max * 100)) + '%"></i></div><div class="t">Total sold: <b>' + inr(p.total) + '</b></div></div>' : '');
    }).join('');
    if (os) os.hidden = !offers.length;
    if (ss) ss.hidden = !best.length;
    var lead = ss && ss.querySelector('.lead'), h = $('selH');
    if (h) h.textContent = hasSales ? 'Most sold this month' : 'Most popular right now';
    if (lead) lead.textContent = hasSales ? 'What our customers are ordering the most.' : 'The gifts our customers are looking at the most.';
  }

  /* ---------- Shop dialog (Shop Now button + search) ---------- */
  var dlg = $('dmShop'), grid = $('dmShopG'), cats = $('dmShopC'), cnt = $('dmShopN'), ttl = $('dmShopT');
  var cur = 'All', query = '';
  function matches(p) {
    if (cur !== 'All' && p.cat !== cur) return false;
    if (query) {
      if (window.dmSearch) return window.dmSearch.score(p, query) > 0;
      var q = query.toLowerCase(); if ((p.name + ' ' + p.cat).toLowerCase().indexOf(q) < 0) return false;
    }
    return true;
  }
  function drawCats() {
    var list = ['All']; all.forEach(function (p) { if (list.indexOf(p.cat) < 0) list.push(p.cat); });
    cats.innerHTML = list.map(function (c) { return '<button type="button" data-c="' + esc(c) + '" aria-pressed="' + (c === cur) + '">' + esc(c) + '</button>'; }).join('');
  }
  function drawGrid() {
    var a, note = '';
    if (query && window.dmSearch) {
      var pool = all.filter(function (p) { return cur === 'All' || p.cat === cur; });
      var res = window.dmSearch.search(pool, query, 24); // best match first; never empty if the shop has products
      a = res.items;
      if (res.kind === 'related') note = 'No exact match for “' + query + '” — closest picks';
      else if (res.kind === 'popular') note = 'Nothing matched “' + query + '” — popular picks for you';
    } else a = all.filter(matches);
    ttl.textContent = note || (query ? 'Results for “' + query + '”' : 'All gifts');
    cnt.textContent = a.length + (a.length === 1 ? ' product' : ' products');
    if (!a.length) { grid.innerHTML = '<div class="sh-msg">' + (query ? 'No gifts match your search. Try another word, or ' : 'No products here yet. ') + '<a href="' + WA + '" target="_blank" rel="noopener" style="color:var(--rose);font-weight:600">ask us on WhatsApp</a>.</div>'; return; }
    grid.innerHTML = a.map(function (p) {
      return '<a class="pc" href="' + WA + '?text=' + encodeURIComponent('Hi Design Makers, I want to order: ' + p.name) + '" target="_blank" rel="noopener" data-id="' + esc(p.id) + '">' +
        '<div class="pc-i">' + media(p) + '</div><div class="pc-b"><span class="pc-c">' + esc(p.cat) + '</span><h3 class="pc-n">' + esc(p.name) + '</h3>' +
        '<div class="pc-p">&#8377;' + inr(p.price) + (p.old ? '<s>&#8377;' + inr(p.old) + '</s>' : '') + '</div><div class="pc-m">MOQ: ' + p.moq + '</div></div></a>';
    }).join('');
    grid.scrollTop = 0;
  }
  function openShop(c, q) {
    if (!dlg || !dlg.showModal) return;
    cur = c || 'All'; query = q || '';
    cats.hidden = false;
    grid.innerHTML = '<div class="sh-msg">Loading gifts...</div>'; cnt.textContent = '';
    if (!dlg.open) dlg.showModal();
    document.body.style.overflow = 'hidden';
    load().then(function () {
      if (cur !== 'All' && !all.some(function (p) { return p.cat === cur; })) cur = 'All';
      drawCats(); drawGrid();
    });
  }
  if (dlg) {
    dlg.addEventListener('click', function (e) { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', function () { document.body.style.overflow = ''; });
    dlg.querySelector('.sh-x').addEventListener('click', function () { dlg.close(); });
    cats.addEventListener('click', function (e) { var b = e.target.closest('button'); if (!b) return; cur = b.dataset.c; drawCats(); drawGrid(); });
    grid.addEventListener('click', function (e) {
      var a = e.target.closest('a.pc'); if (!a) return;
      if (g('openProductModal')) { e.preventDefault(); dlg.close(); openProduct(a.dataset.id); }
    });
  }
  /* ---------- Offers / Best sellers / How it works: open as a popup, never scroll the page ---------- */
  function openInfo(kind) {
    if (!dlg || !dlg.showModal) return;
    query = '';
    cats.hidden = true;
    if (!dlg.open) dlg.showModal();
    document.body.style.overflow = 'hidden';
    if (kind === 'how') {
      var st = R.querySelector('.steps'), hd = $('how');
      ttl.textContent = hd ? hd.textContent : 'How it works'; cnt.textContent = '';
      grid.innerHTML = '<div style="grid-column:1/-1">' + (st ? st.outerHTML : '') + '</div>';
      grid.scrollTop = 0; return;
    }
    ttl.textContent = kind === 'offers' ? 'Offers on bulk orders' : (S.hasSales ? 'Most sold this month' : 'Most popular right now');
    cnt.textContent = 'Loading...';
    grid.innerHTML = '<div class="sh-msg">Loading gifts...</div>';
    load().then(function () {
      if (!dlg.open) return;
      var list = kind === 'offers' ? S.offers : S.best;
      cnt.textContent = list.length + (list.length === 1 ? ' product' : ' products');
      grid.innerHTML = list.length ? list.map(function (p, k) {
        if (kind === 'offers') {
          var bulk = Math.round(p.price * 10 * (100 - p.pct) / 100);
          return card(p, '<span class="pc-o">BUY 10 @ Rs.' + inr(bulk) + '<i>' + p.pct + '% OFF</i></span>');
        }
        return card(p, '<span class="pc-rk" aria-label="Rank ' + (k + 1) + '">' + (k + 1) + '</span>');
      }).join('') : '<div class="sh-msg">Nothing here yet.</div>';
      grid.scrollTop = 0;
    });
  }

  var shopBtn = $('dmShopBtn');
  if (shopBtn) shopBtn.addEventListener('click', function () { openShop('All'); });

  /* ---------- global click handling inside the page ---------- */
  var tabs = $('dmTabs');
  R.addEventListener('click', function (e) {
    var t = e.target;
    var sc = t.closest('[data-sc]');
    if (sc) { var tr = $('t2'); tr.scrollBy({ left: Number(sc.dataset.sc) * tr.clientWidth * .8, behavior: 'smooth' }); return; }

    var ht = t.closest('.pc-ht');
    if (ht) {
      e.preventDefault(); e.stopPropagation();
      var id = ht.closest('.pc').dataset.id, f = g('toggleWishlistById');
      if (f) { f(id); }
      var on = wished(id);
      R.querySelectorAll('.pc[data-id="' + id + '"] .pc-ht').forEach(function (b) { b.setAttribute('aria-pressed', on); b.innerHTML = on ? '&#9829;' : '&#9825;'; });
      return;
    }
    var pc = t.closest('article.pc');
    if (pc) { e.preventDefault(); if (dlg && dlg.open && dlg.contains(pc)) dlg.close(); openProduct(pc.dataset.id); return; }

    var act = t.closest('[data-act]');
    if (act) {
      e.preventDefault();
      var a = act.dataset.act, fn = { account: 'openAccountModal', wishlist: 'openWishlistModal', cart: 'openCart' }[a];
      if (fn) { if (g(fn)) g(fn)(); }
      else if (a === 'top') window.scrollTo({ top: 0, behavior: reduced() ? 'auto' : 'smooth' });
      return;
    }
    var gd = t.closest('[data-gender]');
    if (gd) { e.preventDefault(); openGender(gd.dataset.gender); return; }
    var fc = t.closest('a.card');
    if (fc && window.matchMedia && matchMedia('(hover:none)').matches) {
      /* touch screens: 1st tap flips the card, the button on the back opens the category */
      if (!fc.classList.contains('flipped')) {
        e.preventDefault();
        [].forEach.call(R.querySelectorAll('a.card.flipped'), function (x) { x.classList.remove('flipped'); });
        fc.classList.add('flipped'); return;
      }
      if (!t.closest('.bk i')) { e.preventDefault(); fc.classList.remove('flipped'); return; }
    }
    if (fc && fc.dataset.pid) { e.preventDefault(); openProduct(fc.dataset.pid); return; }
    var ct = t.closest('[data-cat]');
    if (ct) { e.preventDefault(); openCat(ct.dataset.cat); return; }

    var info = t.closest('a[href="#offers"],a[href="#sellers"],a[href="#how"]');
    if (info) { e.preventDefault(); openInfo(info.getAttribute('href').slice(1)); return; }

    var link = t.closest('a[href^="#"]');
    if (link && link.getAttribute('href').length > 1) {
      var el = R.getElementById(link.getAttribute('href').slice(1));
      if (el) { e.preventDefault(); el.scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'start' }); }
    }
    if (tabs && t.closest('#dmTabs')) {
      var tab = t.closest('a'); if (tab && tab.target !== '_blank') {
        [].forEach.call(tabs.querySelectorAll('a'), function (x) { x.classList.remove('on'); x.removeAttribute('aria-current'); });
        tab.classList.add('on'); tab.setAttribute('aria-current', 'true');
        tab.scrollIntoView({ inline: 'center', block: 'nearest', behavior: 'smooth' });
      }
    }
  });
  R.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var pc = e.target.closest && e.target.closest('article.pc');
    if (pc && e.target === pc) { e.preventDefault(); if (dlg && dlg.open && dlg.contains(pc)) dlg.close(); openProduct(pc.dataset.id); }
  });

  /* ---------- search ---------- */
  var q = $('dmQ'), ph = $('dmPh'), roll = $('dmRoll'), form = q && q.closest('form');
  if (form) form.addEventListener('submit', function (e) { e.preventDefault(); openShop('All', q.value.trim()); });
  if (q && ph) q.addEventListener('input', function () { ph.hidden = q.value.length > 0; });

  /* ---------- cart badge mirrors the store's own counter ---------- */
  var cc = R.querySelector('.icons .cc'), real = document.getElementById('cartCount');
  function syncCart() { if (cc && real) cc.textContent = real.textContent || '0'; }
  if (real) { syncCart(); new MutationObserver(syncCart).observe(real, { childList: true, characterData: true, subtree: true }); }
  document.addEventListener('visibilitychange', function () { if (!document.hidden) { renderIfReady(); } });

  /* ---------- rolling search placeholder ---------- */
  function startRoller(names) {
    if (!roll || roll.children.length) return;
    var words = names.slice(0, 10);
    ['Mugs', 'Cushions', 'Photo Frames', 'Keychains', 'T-Shirts', 'Gifts for Her', 'Gifts for Him'].forEach(function (w) { if (words.length < 10 && words.indexOf(w) < 0) words.push(w); });
    words.sort(function () { return .5 - Math.random(); });
    var sp = words.map(function (w, k) { var e = document.createElement('span'); e.textContent = w; if (k === 0) e.className = 'cur'; roll.appendChild(e); return e; }), i = 0, t = null;
    function step() { var prev = sp[i]; prev.className = 'out'; i = (i + 1) % sp.length; sp[i].className = 'cur'; setTimeout(function () { prev.style.transition = 'none'; prev.className = ''; void prev.offsetWidth; prev.style.transition = ''; }, 560); }
    function play() { clearInterval(t); if (sp.length > 1) t = setInterval(step, reduced() ? 3000 : 2300); } // still rotates with 'reduce motion' on (plain fade, no slide)
    document.addEventListener('visibilitychange', function () { document.hidden ? clearInterval(t) : play(); });
    play();
  }

  /* ---------- "Not sure what to gift?" slider ---------- */
  (function () {
    var A = $('dmPs'), B = $('dmPs2'); if (!A) return;
    var tA = A.querySelector('.ps-t'), dA = A.querySelector('.ps-d'), tB = B && B.querySelector('.ps-t'), dB = B && B.querySelector('.ps-d'), t = 0, timer = null;
    var CAT = { 'Mugs and Keychains': 'Mugs', 'Photo Mugs': 'Mugs', 'Personalised Mugs': 'Mugs', 'Cushions': 'Cushions', 'Photo Frames': 'Frames', 'Keychains': 'Keychains', 'T-Shirts': 'T-Shirts', 'Gift Sets': 'All' };
    function sl(tr) { return tr.querySelectorAll('.ps-s'); }
    function N() { return sl(tA).length; }
    function off() { return Math.floor(N() / 2); }
    function paint(tr, dots, i) {
      [].forEach.call(sl(tr), function (e, k) { e.classList.toggle('on', k === i); });
      [].forEach.call(dots.children, function (b, k) { b.classList.toggle('on', k === i); b.setAttribute('aria-current', k === i ? 'true' : 'false'); });
    }
    function show(k) { var n = N(); if (!n) return; t = (k % n + n) % n; paint(tA, dA, t); if (B) paint(tB, dB, (t + off()) % n); }
    function stop() { clearInterval(timer); timer = null; }
    function play() { stop(); if (N() < 2 || reduced()) return; timer = setInterval(function () { show(t + 1); }, 3000); }
    function dots(tr, d, shift) {
      d.innerHTML = '';
      [].forEach.call(sl(tr), function (e, k) {
        var b = document.createElement('button'); b.type = 'button';
        b.setAttribute('aria-label', 'Show ' + e.querySelector('figcaption').textContent);
        b.onclick = function (ev) { ev.stopPropagation(); show(k - shift()); play(); };
        d.appendChild(b);
      });
    }
    function cloneB() { if (!B) return; tB.innerHTML = ''; [].forEach.call(sl(tA), function (f) { var c = f.cloneNode(true); c.classList.remove('on'); tB.appendChild(c); }); }
    function open(tr) { var f = tr.querySelector('.ps-s.on'); if (!f) return; openCat(CAT[f.querySelector('figcaption').textContent] || 'All'); }
    [tA, tB].forEach(function (tr) {
      if (!tr) return;
      tr.style.cursor = 'pointer'; tr.setAttribute('role', 'button'); tr.setAttribute('tabindex', '0'); tr.setAttribute('aria-label', 'View these gifts');
      tr.addEventListener('click', function () { open(tr); });
      tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(tr); } });
    });
    [A, B].forEach(function (r) { if (r) { r.addEventListener('mouseenter', stop); r.addEventListener('mouseleave', play); } });
    document.addEventListener('visibilitychange', function () { document.hidden ? stop() : play(); });
    if (B && N() < 2) { B.hidden = true; B = null; }
    cloneB(); dots(tA, dA, function () { return 0; }); if (B) dots(tB, dB, off);
    show(0); play();

    // blurred backdrop follows the active slide
    var sec = R.querySelector('section.cta'), L = sec && sec.querySelectorAll('.cbg'), k = 0, curSrc = '';
    if (sec && L.length > 1) {
      var sync = function () {
        var im = tA.querySelector('.ps-s.on img'); if (!im || im.src === curSrc) return; curSrc = im.src;
        var n = L[k ^ 1], o = L[k]; n.style.backgroundImage = 'url("' + curSrc + '")'; n.classList.add('on'); o.classList.remove('on'); k ^= 1;
      };
      new MutationObserver(sync).observe(tA, { attributes: true, subtree: true, attributeFilter: ['class'] });
      sync();
    }
  })();

  /* ---------- floating WhatsApp button appears after a little scroll ---------- */
  (function () {
    var w = R.querySelector('a.wa'); if (!w) return; var tick = false;
    function upd() { tick = false; w.classList.toggle('show', (window.pageYOffset || document.documentElement.scrollTop) > 140); }
    window.addEventListener('scroll', function () { if (!tick) { tick = true; requestAnimationFrame(upd); } }, { passive: true });
    upd();
  })();

  /* the card's back gets a soft blurred copy of its photo as texture */
  function setBg(c) {
    var img = c.querySelector('.fr img'), bk = c.querySelector('.bk');
    if (img && bk && img.src) bk.style.setProperty('--bg', 'url("' + img.src + '")');
  }
  /* the card's back shows the details of the product whose photo is on the front */
  function fillBack(c, p, rank) {
    var bk = c.querySelector('.bk'); if (!bk) return;
    var bulk = Math.round(p.price * 10 * (100 - p.pct) / 100);
    var off = p.old ? Math.round((1 - p.price / p.old) * 100) : 0;
    var tagTxt = p.month > 0 ? '&#9733; Best seller' : (p.popular ? '&#9733; Popular' : (p.trending ? '&#9650; Trending' : ''));
    var chips = ['<li>MOQ ' + esc(p.moq) + '</li>'];
    if (p.badge) chips.push('<li class="hot">Buy 10 @ &#8377;' + inr(bulk) + ' &middot; ' + p.pct + '% off</li>');
    if (p.month > 0) chips.push('<li>' + inr(p.month) + ' sold this month</li>');
    bk.innerHTML =
      (tagTxt ? '<em class="bk-r">' + tagTxt + '</em>' : '') +
      '<small class="bk-k">' + esc(p.cat) + '</small>' +
      '<b>' + esc(p.name) + '</b>' +
      '<span class="bk-p"><strong>&#8377;' + inr(p.price) + '</strong>' + (p.old ? '<s>&#8377;' + inr(p.old) + '</s><u>' + off + '% OFF</u>' : '') + '</span>' +
      '<ul class="bk-m">' + chips.join('') + '</ul>' +
      '<i>View product</i>';
    bk.classList.add('pd');
    var ch = c.querySelector('.fr .chip'), cb = ch && ch.querySelector('b'), cs = ch && ch.querySelector('span');
    if (cb) cb.textContent = p.name;
    if (cs) cs.textContent = p.cat;
    c.dataset.pid = p.id;
    c.setAttribute('aria-label', p.name + ', Rs. ' + inr(p.price));
  }
  /* ---------- category cards: show the best-selling product's photo (falls back to the built-in photo) ---------- */
  var heroIds = [null, null, null];
  function paintCategoryCards(a) {
    var ranked = a.filter(function (p) { return p.own; }).sort(function (x, y) {
      return (y.month - x.month) || (y.total - x.total) || ((y.popular ? 1 : 0) - (x.popular ? 1 : 0)) || ((y.trending ? 1 : 0) - (x.trending ? 1 : 0));
    });
    var used = {}, forced = [];
    /* admin picks (slot 1 = big card, 2 = top right, 3 = bottom right) win; empty slots fall back to best sellers */
    for (var k = 0; k < 3; k++) {
      var hp = heroIds[k] == null ? null : a.filter(function (p) { return Number(p.id) === Number(heroIds[k]) && p.own; })[0];
      forced[k] = hp || null;
      if (hp) used[hp.id] = 1;
    }
    var slotNo = 0;
    Array.prototype.forEach.call(R.querySelectorAll('.card[data-cat]'), function (c) {
      var slotIdx = slotNo++;
      var cat = c.getAttribute('data-cat'), img = c.querySelector('.fr img'); if (!img) return;
      var pick = forced[slotIdx];
      if (pick) {
        fillBack(c, pick, ranked.indexOf(pick));
        var pre0 = new Image();
        pre0.onload = function () { img.src = pre0.src; img.alt = pick.name; setBg(c); };
        pre0.src = pick.img;
        return;
      }
      for (var i = 0; i < ranked.length; i++) {
        var p = ranked[i];
        if (!used[p.id] && (cat === 'All' || p.cat === cat)) { pick = p; break; }
      }
      if (!pick) return;
      used[pick.id] = 1;
      fillBack(c, pick, ranked.indexOf(pick));
      var pre = new Image();
      pre.onload = function () { img.src = pre.src; img.alt = pick.name; setBg(c); };
      pre.src = pick.img;
    });
  }

  /* ---------- data-driven parts ---------- */
  var painted = false;
  function renderIfReady() { if (all && all.length) { renderSections(); } }
  var heroLoad = fetch('/api/settings', { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (d) {
    var st = d && d.success && d.settings ? d.settings : {}, ids = Array.isArray(st.heroProductIds) ? st.heroProductIds.slice(0, 3) : [];
    if (ids[0] == null && st.heroProductId != null) ids[0] = st.heroProductId;
    heroIds = [ids[0] == null ? null : ids[0], ids[1] == null ? null : ids[1], ids[2] == null ? null : ids[2]];
  }).catch(function () {});
  load().then(function (a) { return heroLoad.then(function () { return a; }); }).then(function (a) {
    // category tiles may carry the product photo for custom products later; sections are built from live data only
    renderSections(); painted = true; paintCategoryCards(a);
    Array.prototype.forEach.call(R.querySelectorAll('.card[data-cat]'), setBg);
    startRoller(a.map(function (p) { return p.name; }).filter(function (n, i, s) { return s.indexOf(n) === i; }));
  });

  // The store's wishlist can change elsewhere (e.g. from the wishlist popup) — keep hearts in sync.
  var wlOverlay = document.getElementById('wishlistOverlay');
  if (wlOverlay) new MutationObserver(function () { if (!wlOverlay.classList.contains('open') && painted) renderSections(); }).observe(wlOverlay, { attributes: true, attributeFilter: ['class'] });
})();
