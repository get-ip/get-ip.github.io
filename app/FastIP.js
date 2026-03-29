/*!
 * FastIP.js — multi-source public IP detection library
 * Resolves the client's public IPv4/IPv6 address via a waterfall of 85+ free endpoints.
 *
 * Features:
 *   • Dual-stack support  (getDualStack → { v4: Promise, v6: Promise })
 *   • Adaptive ranking    (fastest responders bubble to the front, slow ones decay)
 *   • deflate-raw store   (ratings + blacklist compressed in a single localStorage key)
 *   • Zero dependencies   (vanilla JS IIFE, no bundler required)
 *
 * Usage:
 *   FastIP.getPublicIP()   → Promise<string>                 single best IP
 *   FastIP.getDualStack()  → { v4: Promise, v6: Promise }    independent dual-stack
 *
 * https://github.com/DosX-dev/FastIP.js
 */
(function (global) {
    'use strict';

    /* ── Regex ─────────────────────────────────────────────────────────── */

    const ipv4Re = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$/;

    const ipv6Re = new RegExp('^(' +
        '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' +
        '([0-9a-fA-F]{1,4}:){1,7}:|' +
        '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' +
        '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|' +
        '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|' +
        '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|' +
        '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|' +
        '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|' +
        ':((:[0-9a-fA-F]{1,4}){1,7}|:)' +
        ')$');

    const ipv4InText = /\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)){3})\b/g;

    /* ── Private IP filter ──────────────────────────────────────────────── */

    function isPrivateIPv4(str) {
        const p = str.split('.').map(Number), a = p[0], b = p[1];
        return (
            a === 0 || a === 10 || a === 127 ||
            (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 0 && p[2] === 0) ||
            (a === 192 && b === 168) ||
            (a === 198 && (b === 18 || b === 19)) ||
            a >= 224
        );
    }

    function isPrivateIPv6(str) {
        const s = str.toLowerCase();
        return (
            s === '::1' || s === '::' ||
            /^fe[89ab]/i.test(s) ||
            s.startsWith('fc') || s.startsWith('fd') ||
            s.startsWith('::ffff:')
        );
    }

    function isPublicIP(str) {
        if (!str) return false;
        str = str.trim();
        if (ipv4Re.test(str)) return !isPrivateIPv4(str);
        if (ipv6Re.test(str)) return !isPrivateIPv6(str);
        return false;
    }

    function extractFromText(raw) {
        if (!raw) return null;
        for (const part of raw.split(/[\r\n,;|]+/)) {
            const t = part.trim().replace(/:\d+$/, '');
            if (isPublicIP(t)) return t;
        }
        ipv4InText.lastIndex = 0;
        let m;
        while ((m = ipv4InText.exec(raw)) !== null) {
            if (isPublicIP(m[1])) return m[1];
        }
        return null;
    }

    /* ── Sources ────────────────────────────────────────────────────────── */
    /* t:'x' = cloudflare-trace  |  t:'j' = json  |  t:'t' = plain text      */
    /* f = json field name  |  v:4 = IPv4-forced  |  v:6 = IPv6-forced       */

    const SOURCES = [
        // ── Fast tier: start immediately, no JSON load needed ──────────────
        { u: 'https://www.cloudflare.com/cdn-cgi/trace', t: 'x' },
        { u: 'https://icanhazip.com', t: 't' },
        { u: 'https://ipv4.icanhazip.com', t: 't', v: 4 },
        { u: 'https://api.ipify.org?format=json', t: 'j', f: 'ip' },
        { u: 'https://api64.ipify.org?format=json', t: 'j', f: 'ip' },
        { u: 'https://checkip.amazonaws.com', t: 't' },
        { u: 'https://am.i.mullvad.net/ip', t: 't' },
        { u: 'https://ident.me', t: 't' },
        // ── Full pool ───────────────────────────────────────────────────────
        { u: 'https://api6.ipify.org?format=json', t: 'j', f: 'ip', v: 6 },
        { u: 'https://ipinfo.io/json', t: 'j', f: 'ip' },
        { u: 'https://ipapi.co/json', t: 'j', f: 'ip' },
        { u: 'https://ip-api.com/json/?fields=query', t: 'j', f: 'query' },
        { u: 'https://httpbin.org/ip', t: 'j', f: 'origin' },
        { u: 'https://api.my-ip.io/v2/ip.json', t: 'j', f: 'ip' },
        { u: 'https://api.bigdatacloud.net/data/client-ip', t: 'j', f: 'ipString' },
        { u: 'https://wtfismyip.com/text', t: 't' },
        { u: 'https://ip.seeip.org/json', t: 'j', f: 'ip' },
        { u: 'https://ip4.seeip.org/json', t: 'j', f: 'ip', v: 4 },
        { u: 'https://jsonip.com', t: 'j', f: 'ip' },
        { u: 'https://api.db-ip.com/v2/free/self', t: 'j', f: 'ipAddress' },
        { u: 'https://get.geojs.io/v1/ip.json', t: 'j', f: 'ip' },
        { u: 'https://ipwho.is', t: 'j', f: 'ip' },
        { u: 'https://freeipapi.com/api/json', t: 'j', f: 'ipAddress' },
        { u: 'https://myexternalip.com/json', t: 'j', f: 'ip' },
        { u: 'https://ifconfig.co/json', t: 'j', f: 'ip' },
        { u: 'https://api.ipapi.is', t: 'j', f: 'ip' },
        { u: 'https://de.ipapi.is', t: 'j', f: 'ip' },
        { u: 'https://us.ipapi.is', t: 'j', f: 'ip' },
        { u: 'https://sg.ipapi.is', t: 'j', f: 'ip' },
        { u: 'https://ip.guide', t: 'j', f: 'ip' },
        { u: 'https://api.country.is', t: 'j', f: 'ip' },
        { u: 'https://am.i.mullvad.net/json', t: 'j', f: 'ip' },
        { u: 'https://api.infoip.io', t: 'j', f: 'clientIp' },
        { u: 'https://api.ipify.org', t: 't' },
        { u: 'https://api64.ipify.org', t: 't' },
        { u: 'https://v4.ident.me', t: 't', v: 4 },
        { u: 'https://ipecho.net/plain', t: 't' },
        { u: 'https://ip.tyk.nu', t: 't' },
        { u: 'https://wgetip.com', t: 't' },
        { u: 'https://bot.whatismyipaddress.com', t: 't' },
        { u: 'https://diagnostic.opendns.com/myip', t: 't' },
        { u: 'https://myip.addr.space', t: 't' },
        { u: 'https://api.my-ip.io/v2/ip.txt', t: 't' },
        { u: 'https://ip.rootnet.in', t: 't' },
        { u: 'https://myip.dnsomatic.com', t: 't' },
        { u: 'https://l2.io/ip', t: 't' },
        { u: 'https://ip.3322.net', t: 't' },
        { u: 'https://ipv4.wtfismyip.com/text', t: 't', v: 4 },
        { u: 'https://eth0.me', t: 't' },
        { u: 'https://ipaddr.site', t: 't' },
        { u: 'https://whatismyip.akamai.com', t: 't' },
        { u: 'https://ipapi.co/ip/', t: 't' },
        { u: 'https://ip.sb', t: 't' },
        { u: 'https://ipv4.seeip.org', t: 't', v: 4 },
        { u: 'https://ifconfig.co/ip', t: 't' },
        { u: 'https://ifconfig.me/ip', t: 't' },
        { u: 'https://ifconfig.io/ip', t: 't' },
        { u: 'https://ifconfig.io/all.json', t: 'j', f: 'ip' },
        { u: 'https://api.tnedi.me', t: 't' },
        { u: 'https://api.ip.sb/ip', t: 't' },
        { u: 'https://api.ip.sb/geoip', t: 'j', f: 'ip' },
        { u: 'https://myip.wtf/text', t: 't' },
        { u: 'https://www.trackip.net/ip', t: 't' },
        { u: 'https://inet-ip.info/ip', t: 't' },
        { u: 'https://iplocate.io/api/lookup', t: 'j', f: 'ip' },
        { u: 'https://ipwhois.app/json/', t: 'j', f: 'ip' },
        { u: 'https://api.myip.com', t: 'j', f: 'ip' },
        { u: 'https://reallyfreegeoip.org/json/', t: 'j', f: 'ip' },
        { u: 'https://api.ipbase.com/v1/json/', t: 'j', f: 'ip' },
        // ── IPv4-forced ──────────────────────────────────────────────────────
        { u: 'https://4.ident.me', t: 't', v: 4 },
        { u: 'https://4.tnedi.me', t: 't', v: 4 },
        { u: 'https://ip4.me/api/', t: 't', v: 4 },
        { u: 'https://api4.my-ip.io/ip', t: 't', v: 4 },
        { u: 'https://4.myip.is', t: 'j', f: 'ip', v: 4 },
        // ── IPv6-forced ──────────────────────────────────────────────────────
        { u: 'https://ipv6.icanhazip.com', t: 't', v: 6 },
        { u: 'https://v6.ident.me', t: 't', v: 6 },
        { u: 'https://ipv6.wtfismyip.com/text', t: 't', v: 6 },
        { u: 'https://ipv6.seeip.org', t: 't', v: 6 },
        { u: 'https://ip6.seeip.org/json', t: 'j', f: 'ip', v: 6 },
        { u: 'https://ipv6.ipify.org?format=json', t: 'j', f: 'ip', v: 6 },
        { u: 'https://6.ident.me', t: 't', v: 6 },
        { u: 'https://6.tnedi.me', t: 't', v: 6 },
        { u: 'https://ip6.me/api/', t: 't', v: 6 },
        { u: 'https://api6.my-ip.io/ip', t: 't', v: 6 },
        { u: 'https://6.myip.is', t: 't', v: 6 },
    ];

    const JSON_FIELDS = [
        'ip', 'IP', 'ipAddress', 'ipString', 'ip_addr', 'ip_address',
        'query', 'origin', 'clientIp', 'your_ip'
    ];

    /* ── Fetch with timeout + optional cancel signal ──────────────────── */

    function ft(url, ms, cancelSig) {
        const c = new AbortController();
        const t = setTimeout(function () { c.abort(); }, ms);
        if (cancelSig) {
            if (cancelSig.aborted) { clearTimeout(t); return Promise.reject(new DOMException('cancelled', 'AbortError')); }
            cancelSig.addEventListener('abort', function () { c.abort(); }, { once: true });
        }
        return fetch(url, { signal: c.signal, cache: 'no-store' })
            .finally(function () { clearTimeout(t); });
    }

    /* ── Resolve one source ─────────────────────────────────────────────── */

    function resolve(src, ms, cancelSig) {
        if (src.t === 'j') {
            return ft(src.u, ms, cancelSig)
                .then(function (r) { if (!r.ok) throw 0; return r.json(); })
                .then(function (data) {
                    const fields = src.f
                        ? [src.f].concat(JSON_FIELDS.filter(function (f) { return f !== src.f; }))
                        : JSON_FIELDS;
                    for (var i = 0; i < fields.length; i++) {
                        var v = data[fields[i]];
                        if (v == null) continue;
                        v = String(v).trim();
                        if (isPublicIP(v)) return v;
                        var found = extractFromText(v);
                        if (found) return found;
                    }
                    throw 0;
                });
        }

        if (src.t === 'x') {
            return ft(src.u, ms, cancelSig)
                .then(function (r) { if (!r.ok) throw 0; return r.text(); })
                .then(function (text) {
                    var m = text.match(/^ip=(.+)$/m);
                    var ip = m ? m[1].trim() : null;
                    if (!isPublicIP(ip)) throw 0;
                    return ip;
                });
        }

        return ft(src.u, ms, cancelSig)
            .then(function (r) { if (!r.ok) throw 0; return r.text(); })
            .then(function (text) {
                var ip = extractFromText(text);
                if (!ip) throw 0;
                return ip;
            });
    }

    /* ── Persistent store: compressed ratings + blacklist ────────────────────
     *
     *  Key    : FastIP2
     *  Format : "2:"+base64(deflate-raw(JSON))  |  "0:"+JSON  (plain fallback)
     *  Schema : { t:<unix_sec>, b:<number[]>, r:{"<idx>":<score>} }
     *    t = unix timestamp of the last write
     *    b = blacklist  — SOURCES indices (not hostname strings)
     *    r = ratings    — "index" → score 0-99; higher = historically faster
     *
     *  Domain-specific compression: each hostname is replaced by its ordinal
     *  index in SOURCES (~10× size reduction before deflate-raw kicks in).
     *  On top: deflate-raw via native CompressionStream (gzip without header).
     * ─────────────────────────────────────────────────────────────────────── */

    var STORE_KEY    = 'FastIP2';
    var BL_TTL_S    = 7 * 86400;   // re-admit blacklisted sources after 7 days
    var SCORE_DECAY = 0.92;        // score multiplier applied on each page load
    var SCORE_WIN   = 2;           // score awarded to the winner of each race
    var SCORE_MAX   = 99;
    var SCORE_GOLD  = 30;          // min score to try a source alone (golden shortcut; ~15 consecutive wins)
    var GOLD_MS     = 800;         // timeout for the single golden-source attempt
    var CACHE_TTL_MS = 30 * 1000;  // reuse last result for 30 s within the same page session

    var DB          = { t: 0, b: [], r: {} };  // in-memory live state
    var _saveTimer  = null;
    var _ipCache    = null;         // { t: timestamp_ms, p: Promise<string> }
    var _dsCache    = null;         // { t: timestamp_ms, v4: Promise, v6: Promise }

    function _compress(str) {
        if (typeof CompressionStream === 'undefined') return Promise.resolve(null);
        var bytes = new TextEncoder().encode(str);
        var cs = new CompressionStream('deflate-raw');
        var w = cs.writable.getWriter();
        w.write(bytes);
        w.close();
        return new Response(cs.readable).arrayBuffer().then(function (buf) {
            var arr = new Uint8Array(buf), bin = '';
            for (var i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
            return btoa(bin);
        });
    }

    function _decompress(b64) {
        if (typeof DecompressionStream === 'undefined') return Promise.reject(new Error('no DecompressionStream'));
        var bin = atob(b64);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        var ds = new DecompressionStream('deflate-raw');
        var w = ds.writable.getWriter();
        w.write(bytes);
        w.close();
        return new Response(ds.readable).arrayBuffer().then(function (buf) {
            return new TextDecoder().decode(buf);
        });
    }

    function _saveDB() {
        DB.t = Math.floor(Date.now() / 1000);
        if (_saveTimer) clearTimeout(_saveTimer);
        /* debounce 100ms — all win/penalize calls in one round merge into a single write */
        _saveTimer = setTimeout(function () {
            _saveTimer = null;
            var snap = JSON.stringify(DB);
            _compress(snap).then(function (b64) {
                try {
                    if (b64) localStorage.setItem(STORE_KEY, '2:' + b64);
                    else localStorage.setItem(STORE_KEY, '0:' + snap);
                } catch (_) { }
            }).catch(function () {
                try { localStorage.setItem(STORE_KEY, '0:' + snap); } catch (_) { }
            });
        }, 100);
    }

    function _applyDB(parsed) {
        if (!parsed || typeof parsed !== 'object') return;
        var now = Math.floor(Date.now() / 1000);
        /* expire blacklist entries when TTL has passed */
        var bl = Array.isArray(parsed.b)
            ? parsed.b.filter(function (i) { return i >= 0 && i < SOURCES.length; })
            : [];
        if ((now - (parsed.t || 0)) > BL_TTL_S) bl = [];
        /* apply score decay on session start */
        var rt = {};
        var raw_r = (parsed.r && typeof parsed.r === 'object') ? parsed.r : {};
        Object.keys(raw_r).forEach(function (k) {
            var v = Math.round((+raw_r[k] || 0) * SCORE_DECAY);
            if (v > 0) rt[k] = v;
        });
        DB = { t: parsed.t || 0, b: bl, r: rt };
    }

    function _loadDB() {
        var raw = null;
        try { raw = typeof localStorage !== 'undefined' ? localStorage.getItem(STORE_KEY) : null; } catch (_) { }

        if (!raw) return Promise.resolve();

        if (raw.slice(0, 2) === '2:') {
            return _decompress(raw.slice(2)).then(function (json) {
                _applyDB(JSON.parse(json));
            }).catch(function () { });
        }
        if (raw.slice(0, 2) === '0:') {
            try { _applyDB(JSON.parse(raw.slice(2))); } catch (_) { }
        }
        return Promise.resolve();
    }

    /* kick off store load at module init — resolves on CPU only (<1 ms), well before any network response */
    var _ready = _loadDB();

    /* ── Store helpers ──────────────────────────────────────────────────────── */

    function srcIndex(url) {
        for (var i = 0; i < SOURCES.length; i++) {
            if (SOURCES[i].u === url) return i;
        }
        return -1;
    }

    function penalize(url) {
        var i = srcIndex(url);
        if (i < 0 || DB.b.indexOf(i) >= 0) return;
        DB.b.push(i);
        _saveDB();
    }

    function reward(url) {
        var i = srcIndex(url);
        if (i < 0) return;
        var k = String(i);
        DB.r[k] = Math.min((DB.r[k] || 0) + SCORE_WIN, SCORE_MAX);
        _saveDB();
    }

    function rankSources(sources) {
        return sources.slice().sort(function (a, b) {
            var ai = srcIndex(a.u), bi = srcIndex(b.u);
            /* blacklisted sources sink to the end */
            var abl = (ai >= 0 && DB.b.indexOf(ai) >= 0) ? 1 : 0;
            var bbl = (bi >= 0 && DB.b.indexOf(bi) >= 0) ? 1 : 0;
            if (abl !== bbl) return abl - bbl;
            /* among healthy sources — sort by rating descending (higher = faster history) */
            var ar = ai >= 0 ? (DB.r[String(ai)] || 0) : 0;
            var br = bi >= 0 ? (DB.r[String(bi)] || 0) : 0;
            return br - ar;
        });
    }

    /* Penalize only network errors (TypeError = DNS / CORS / connection refused). */
    /* AbortError (timeout or cancellation) and parse errors are not penalized.    */
    function withPenalty(src, ms, cancelSig) {
        return resolve(src, ms, cancelSig).catch(function (e) {
            if (e instanceof TypeError) penalize(src.u);
            throw e;
        });
    }

    /* ── Dual-stack detection ───────────────────────────────────────────── */

    function getDualStack() {
        var now = Date.now();
        if (_dsCache && (now - _dsCache.t) < CACHE_TTL_MS) return { v4: _dsCache.v4, v6: _dsCache.v6 };

        var FAST_MS = 2500, FULL_MS = 6000;
        var V6_FAST_MS = 1500, V6_FULL_MS = 3000;
        var cancel4 = new AbortController();
        var cancel6 = new AbortController();

        // Await stored rankings — decompress is CPU-only (<5 ms), ensures correct sort order
        var rankedP = _ready.then(function () { return rankSources(SOURCES); });

        function raceTyped(sources, ms, cancelSig, validate) {
            if (!sources.length) return Promise.reject(new Error('no sources'));
            return Promise.any(sources.map(function (s) {
                return withPenalty(s, ms, cancelSig).then(function (ip) {
                    if (!validate(ip)) throw 0;
                    reward(s.u);
                    return ip;
                });
            }));
        }

        var isV4 = function (ip) { return ipv4Re.test(ip); };
        var isV6 = function (ip) { return ipv6Re.test(ip); };

        // v4: fast-8 non-v6 sources → typically 100–200 ms
        var v4 = rankedP.then(function (ranked) {
            // Exclude v:6-only sources so their slots are never wasted on the IPv4 path
            var v4src  = ranked.filter(function (s) { return s.v !== 6; });
            var v4fast = v4src.slice(0, 8);
            var v4rest = v4src.slice(8);

            function v4Race() {
                return raceTyped(v4fast, FAST_MS, cancel4.signal, isV4).catch(function () {
                    if (cancel4.signal.aborted) throw new Error('cancelled');
                    return raceTyped(v4rest, FULL_MS, cancel4.signal, isV4);
                });
            }

            // Golden v4: if our best source has strong history, try it alone first (1 req)
            var top4 = v4src[0];
            var top4Score = top4 ? (DB.r[String(srcIndex(top4.u))] || 0) : 0;
            if (top4Score >= SCORE_GOLD) {
                return withPenalty(top4, GOLD_MS, cancel4.signal)
                    .then(function (ip) { if (!isV4(ip)) throw 0; reward(top4.u); return ip; })
                    .catch(function () {
                        if (cancel4.signal.aborted) throw new Error('cancelled');
                        return v4Race();
                    });
            }
            return v4Race();
        }).then(function (ip) { cancel4.abort(); return ip; })
          .catch(function () { cancel4.abort(); return null; });

        // v6: top-3 v6 sources → remaining
        var v6 = rankedP.then(function (ranked) {
            var v6all  = ranked.filter(function (s) { return s.v === 6; });
            var v6fast = v6all.slice(0, 3);
            var v6rest = v6all.slice(3);

            function v6Race() {
                return raceTyped(v6fast, V6_FAST_MS, cancel6.signal, isV6).catch(function () {
                    if (cancel6.signal.aborted) throw new Error('cancelled');
                    return raceTyped(v6rest, V6_FULL_MS, cancel6.signal, isV6);
                });
            }

            // Golden v6
            var top6 = v6all[0];
            var top6Score = top6 ? (DB.r[String(srcIndex(top6.u))] || 0) : 0;
            if (top6Score >= SCORE_GOLD) {
                return withPenalty(top6, GOLD_MS, cancel6.signal)
                    .then(function (ip) { if (!isV6(ip)) throw 0; reward(top6.u); return ip; })
                    .catch(function () {
                        if (cancel6.signal.aborted) throw new Error('cancelled');
                        return v6Race();
                    });
            }
            return v6Race();
        }).then(function (ip) { cancel6.abort(); return ip; })
          .catch(function () { cancel6.abort(); return null; });

        // Two independent promises — UI renders v4 immediately, v6 upgrades the display if available
        _dsCache = { t: now, v4: v4, v6: v6 };
        return { v4: v4, v6: v6 };
    }

    /* ── Public API ─────────────────────────────────────────────────────── */

    function getPublicIP() {
        var now = Date.now();
        if (_ipCache && (now - _ipCache.t) < CACHE_TTL_MS) return _ipCache.p;

        var FAST_MS = 2500, FULL_MS = 6000;
        var cancel = new AbortController();

        var p = _ready.then(function () {
            var ranked = rankSources(SOURCES);

            function race(sources, ms) {
                return Promise.any(sources.map(function (s) {
                    return withPenalty(s, ms, cancel.signal).then(function (ip) {
                        reward(s.u);
                        return ip;
                    });
                }));
            }

            function fullRace() {
                // Tier 1: fast-8 (Cloudflare CDN, ipify, AWS, Mullvad)
                // Happy path: 1 response in ~150ms, remaining 7 are aborted.
                // Tier 2: rest of the pool — only if all fast-8 fail (rare).
                return race(ranked.slice(0, 8), FAST_MS).catch(function () {
                    if (!cancel.signal.aborted) return race(ranked.slice(8), FULL_MS);
                    throw new Error('cancelled');
                });
            }

            // Golden shortcut: if our top source has a strong win history,
            // fire it alone first — 1 request vs 8, same latency on hit (~100 ms).
            var top = ranked[0];
            var topScore = top ? (DB.r[String(srcIndex(top.u))] || 0) : 0;
            if (topScore >= SCORE_GOLD) {
                return withPenalty(top, GOLD_MS, cancel.signal)
                    .then(function (ip) { reward(top.u); return ip; })
                    .catch(function () {
                        if (cancel.signal.aborted) throw new Error('cancelled');
                        return fullRace();
                    });
            }
            return fullRace();
        });

        p.then(function () { cancel.abort(); }, function () { cancel.abort(); });
        _ipCache = { t: now, p: p };
        p.catch(function () { if (_ipCache && _ipCache.p === p) _ipCache = null; });
        return p;
    }

    global.FastIP = { getPublicIP: getPublicIP, getDualStack: getDualStack };

}(typeof globalThis !== 'undefined' ? globalThis : window));
