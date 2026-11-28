// Service worker of the winners site: decrypts videos and posters on the fly (AES-GCM chunks), answers video Range
// requests (fast start, seeking, fullscreen before play) and keeps every encrypted file in Cache Storage (names are content hashes).
var SWV = 2, CFG = {"salt": "ee1bf69208c5caf654af400bbcc9249a", "iter": 600000, "ch": 65536}, CH = CFG.ch, CT = CH + 16, KEY = null, MEM = new Map(), MEMB = 0, RAW = "mh-raw-1";
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });

function idb(mode, fn) {
  return new Promise(function (ok, no) {
    var r = indexedDB.open("mh", 1);
    r.onupgradeneeded = function () { r.result.createObjectStore("k"); };
    r.onsuccess = function () { var t = r.result.transaction("k", mode), s = t.objectStore("k"), q = fn(s); t.oncomplete = function () { ok(q && q.result); }; t.onerror = function () { no(t.error); }; };
    r.onerror = function () { no(r.error); };
  });
}
function hex(s) { var b = new Uint8Array(s.length / 2); for (var i = 0; i < b.length; i++) b[i] = parseInt(s.substr(i * 2, 2), 16); return b; }
function getKey(tries) {
  if (KEY) return Promise.resolve(KEY);
  tries = tries || 0;
  return idb("readonly", function (s) { return s.get("key"); }).then(function (k) { if (k) KEY = k; return KEY; }).catch(function () { return null; })
    .then(function (k) { if (k || tries >= 20) return k; return new Promise(function (ok) { setTimeout(ok, 100); }).then(function () { return getKey(tries + 1); }); });  // the page sends the key right after it opens
}
self.addEventListener("message", function (e) {
  var d = e.data || {};
  if (d.ping && e.ports && e.ports[0]) e.ports[0].postMessage({ v: SWV });  // the page checks it talks to this version
  if (d.key) { crypto.subtle.importKey("raw", hex(d.key), "AES-GCM", false, ["decrypt"]).then(function (k) { KEY = k; return idb("readwrite", function (s) { return s.put(k, "key"); }); }).catch(function () {}); }
  if (d.forget) { KEY = null; MEM.clear(); idb("readwrite", function (s) { return s.delete("key"); }).catch(function () {}); caches.delete(RAW); }
  if (d.warm) d.warm.forEach(function (u) { var m = parse(new URL(u, self.registration.scope)); if (m) chunks(m, 0, Math.min(m.n - 1, 2)).catch(function () {}); });
});

// virtual address: x/[m<k>/]<sub>/<id>.<nonce prefix>.<plain size>.<ext>  ->  encrypted file <sub>/<id>.b
function parse(u) {
  // media lives in shard sites next to this one: x/m3/v/<id>... -> /dash-m3/v/<id>.b (same origin, so no CORS)
  var m = u.pathname.match(/\/x\/(?:(m\d+)\/)?([a-z])\/([0-9a-f]{20})\.([0-9a-f]{16})\.(\d+)\.(mp4|webp)$/);
  if (!m) return null;
  var size = +m[5], base = m[1] ? "../../../../dash-" + m[1] + "/" : "../../";
  return { file: new URL(base + m[2] + "/" + m[3] + ".b", u).href, id: m[3], pre: hex(m[4]), size: size, n: Math.max(1, Math.ceil(size / CH)), type: m[6] === "mp4" ? "video/mp4" : "image/webp" };
}
function iv(pre, i) { var v = new Uint8Array(12); v.set(pre); new DataView(v.buffer).setUint32(8, i); return v; }
function remember(k, v) { MEM.set(k, v); MEMB += v.byteLength; while (MEMB > 48e6) { var f = MEM.keys().next().value; MEMB -= MEM.get(f).byteLength; MEM.delete(f); } }

// plain chunks a..b of one file: memory, then Cache Storage, then one Range request for the missing run
function chunks(m, a, b) {
  return getKey().then(function (key) {
    if (!key) throw new Error("no key");
    return caches.open(RAW).then(function (cache) {
      var out = [], miss = [];
      return Promise.all(range(a, b).map(function (i) {
        var k = m.id + ":" + i; if (MEM.has(k)) { out[i - a] = MEM.get(k); return; }
        return cache.match(m.file + "?c=" + i).then(function (r) { if (r) return r.arrayBuffer().then(function (ct) { return dec(key, m, i, ct).then(function (p) { out[i - a] = p; }); }); miss.push(i); });
      })).then(function () {
        if (!miss.length) return out;
        var lo = Math.min.apply(null, miss), hi = Math.max.apply(null, miss), end = Math.min(m.n * CT, (hi + 1) * CT) - 1;
        return fetch(m.file, { headers: { Range: "bytes=" + lo * CT + "-" + end } }).then(function (r) {
          if (!r.ok) throw new Error("fetch " + r.status);
          return r.arrayBuffer().then(function (buf) {
            var off = r.status === 206 ? lo * CT : 0;
            return Promise.all(range(lo, hi).map(function (i) {
              var ct = buf.slice(i * CT - off, Math.min((i + 1) * CT - off, buf.byteLength));
              cache.put(m.file + "?c=" + i, new Response(ct)).catch(function () {});
              return dec(key, m, i, ct).then(function (p) { if (out[i - a] === undefined) out[i - a] = p; });
            }));
          });
        }).then(function () { return out; });
      });
    });
  });
}
function range(a, b) { var r = []; for (var i = a; i <= b; i++) r.push(i); return r; }
function dec(key, m, i, ct) { return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv(m.pre, i) }, key, ct).then(function (p) { remember(m.id + ":" + i, p); return p; }); }
function join(parts) { var n = 0; parts.forEach(function (p) { n += p.byteLength; }); var o = new Uint8Array(n), x = 0; parts.forEach(function (p) { o.set(new Uint8Array(p), x); x += p.byteLength; }); return o; }

function serve(req, m) {
  var rg = req.headers.get("range"), s = 0, e = m.size - 1, part = false;
  if (rg) {
    var q = rg.match(/bytes=(\d*)-(\d*)/);
    if (q) { part = true; if (q[1] === "") { s = Math.max(0, m.size - +q[2]); } else { s = +q[1]; if (q[2] !== "") e = Math.min(+q[2], m.size - 1); else e = Math.min(m.size - 1, s + 16 * CH - 1); } }
    if (s >= m.size) return new Response(null, { status: 416, headers: { "Content-Range": "bytes */" + m.size } });
  }
  var a = Math.floor(s / CH), b = Math.floor(e / CH);
  return chunks(m, a, b).then(function (ps) {
    var all = join(ps), body = all.slice(s - a * CH, e - a * CH + 1);
    var h = { "Content-Type": m.type, "Accept-Ranges": "bytes", "Content-Length": String(body.byteLength), "Cache-Control": "no-store" };
    if (part) h["Content-Range"] = "bytes " + s + "-" + e + "/" + m.size;
    return new Response(body, { status: part ? 206 : 200, headers: h });
  }).catch(function (err) { return new Response("", { status: 503, statusText: String(err && err.message || err) }); });
}

self.addEventListener("fetch", function (ev) {
  var u = new URL(ev.request.url);
  if (u.origin !== location.origin) return;
  var m = parse(u);
  if (m) { ev.respondWith(serve(ev.request, m)); return; }
  // content-addressed data files: cache first (they never change; old ones are dropped)
  if (/\/d\/[0-9a-f]{20}\.b$/.test(u.pathname) && !ev.request.headers.get("range")) {
    ev.respondWith(caches.open(RAW).then(function (c) {
      return c.match(ev.request).then(function (hit) {
        return hit || fetch(ev.request).then(function (r) {
          if (r.ok) { var cl = r.clone(); c.keys().then(function (ks) { ks.forEach(function (k) { if (/\/d\/[0-9a-f]{20}\.b$/.test(k.url) && k.url !== u.href) c.delete(k); }); }); c.put(ev.request, cl); }
          return r;
        });
      });
    }));
  }
});
