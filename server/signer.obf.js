/* sign-lab synthetic signer — obfuscated build
 *
 * 这是一个**合成靶场**的客户端签名脚本，不对应任何真实站点。
 * 运行环境：浏览器或 Node（都只依赖 globalThis，不依赖任何原生加密库）。
 *
 * 契约：
 *   __signer.canonical(params)  -> 规范化查询串
 *   __signer.sign(params, ts, nonce) -> 十六进制签名
 */
(function (_g) {
  var _0x2f = (function () {
    var _K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var _H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    function _r(x, n) { return (x >>> n) | (x << (32 - n)); }
    function _h(n) { return ('0000000' + (n >>> 0).toString(16)).slice(-8); }

    function _u(s) {
      var o = [], i, c, c2, cp;
      for (i = 0; i < s.length; i++) {
        c = s.charCodeAt(i);
        if (c < 0x80) { o.push(c); }
        else if (c < 0x800) { o.push(0xc0 | (c >> 6), 0x80 | (c & 63)); }
        else if (c >= 0xd800 && c <= 0xdbff) {
          c2 = s.charCodeAt(++i);
          cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
          o.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
                 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
        } else { o.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
      }
      return o;
    }

    function _s(msg) {
      var b = _u(msg), l = b.length, H = _H0.slice(0), w = new Array(64);
      var i, t, a, bb, c, d, e, f, g, h, S0, S1, ch, maj, t1, t2, hi, lo;
      b.push(0x80);
      while (b.length % 64 !== 56) { b.push(0); }
      hi = Math.floor(l / 536870912);
      lo = (l * 8) >>> 0;
      b.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255);
      b.push((lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
      for (i = 0; i < b.length; i += 64) {
        for (t = 0; t < 16; t++) {
          w[t] = (b[i + 4 * t] << 24) | (b[i + 4 * t + 1] << 16) | (b[i + 4 * t + 2] << 8) | b[i + 4 * t + 3];
        }
        for (t = 16; t < 64; t++) {
          S0 = _r(w[t - 15], 7) ^ _r(w[t - 15], 18) ^ (w[t - 15] >>> 3);
          S1 = _r(w[t - 2], 17) ^ _r(w[t - 2], 19) ^ (w[t - 2] >>> 10);
          w[t] = (w[t - 16] + S0 + w[t - 7] + S1) | 0;
        }
        a = H[0]; bb = H[1]; c = H[2]; d = H[3];
        e = H[4]; f = H[5]; g = H[6]; h = H[7];
        for (t = 0; t < 64; t++) {
          S1 = _r(e, 6) ^ _r(e, 11) ^ _r(e, 25);
          ch = (e & f) ^ ((~e) & g);
          t1 = (h + S1 + ch + _K[t] + w[t]) | 0;
          S0 = _r(a, 2) ^ _r(a, 13) ^ _r(a, 22);
          maj = (a & bb) ^ (a & c) ^ (bb & c);
          t2 = (S0 + maj) | 0;
          h = g; g = f; f = e; e = (d + t1) | 0;
          d = c; c = bb; bb = a; a = (t1 + t2) | 0;
        }
        H[0] = (H[0] + a) | 0;  H[1] = (H[1] + bb) | 0;
        H[2] = (H[2] + c) | 0;  H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0;  H[5] = (H[5] + f) | 0;
        H[6] = (H[6] + g) | 0;  H[7] = (H[7] + h) | 0;
      }
      return H.map(_h).join('');
    }

    return { sha256: _s };
  })();

  var _0xR = [
    0x4b, 0x53, 0x6d, 0x66, 0x5f, 0x69, 0x0b, 0x4d,
    0x4f, 0x46, 0x49, 0x4b, 0x4d, 0x73, 0x04, 0x50,
    0x57, 0x46, 0x6b, 0x78, 0x5b, 0x50, 0x77, 0x7b,
    0x4f, 0x49, 0x7f, 0x71, 0x0d, 0x57, 0x51, 0x4b,
    0x4f, 0x48, 0x5b, 0x6b, 0x5a, 0x6e, 0x58, 0x5a,
    0x4e, 0x49, 0x52, 0x0f, 0x08, 0x46, 0x4f, 0x6e,
    0x58, 0x78, 0x45, 0x55, 0x0e, 0x5d, 0x46, 0x76,
    0x75, 0x5f, 0x75, 0x7d, 0x50, 0x0c, 0x71, 0x52,
    0x65, 0x5e, 0x66, 0x76, 0x4a, 0x64, 0x08, 0x48,
    0x71, 0x70, 0x0f, 0x04, 0x6e, 0x71, 0x7d, 0x74
  ];
  var _0xT = (function () {
    var _m = (0x2 ^ 0x3e), a = [], i;
    for (i = 0; i < _0xR.length; i++) { a.push(String.fromCharCode(_0xR[i] ^ _m)); }
    return a;
  })();
  var _0xI = [
    (0x100 >> 5),
    (0xe0 >> 3),
    (0x280 >> 5),
    (0x4 ^ 0x2e),
    (0x13 + 0x2),
    (0x17 ^ 0x22),
    (0xd ^ 0x4c),
    (0x24 ^ 0x22)
  ];

  function _0xk() {
    var s = '', i;
    for (i = 0; i < _0xI.length; i++) { s += _0xT[_0xI[i]]; }
    return s;
  }

  function _0xcq(p) {
    var ks = Object.keys(p).sort(), out = [], i;
    for (i = 0; i < ks.length; i++) { out.push(ks[i] + '=' + p[ks[i]]); }
    return out.join('&');
  }

  _g.__signer = {
    version: '1.0.0-lab',
    canonical: _0xcq,
    sign: function (params, ts, nonce) {
      return _0x2f.sha256(nonce + _0xk() + _0xcq(params) + ts);
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
