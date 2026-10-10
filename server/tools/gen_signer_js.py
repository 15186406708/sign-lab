#!/usr/bin/env python3
"""生成 sign-lab 的「混淆版」客户端签名脚本：server/signer.obf.js

重要说明
--------
真实场景里，这段混淆代码跑在目标服务器上，分析者**只能看到产物**（signer.obf.js），
看不到生成器。本文件属于靶场自身的服务端工具，跟着靶场一起发布，目的是让靶场可复现：
任何人拿到仓库都能重新生成一份完全一致的混淆脚本。

混淆手法（四层，都对应真实目标里的常见做法）：
  1. 字符串表：盐不是明文，散落在一张 80 字符的数组里，靠下标取字符拼出来。
  2. 表内容异或编码：每个字符与掩码异或后以数字存放，运行期才用
     `String.fromCharCode(code ^ mask)` 还原 —— 直接把十六进制转义读成字符这招失效了。
  3. 下标用表达式写：`(0x10 >> 1)` 而不是 `8`，常量折叠掉，肉眼扫不出来。
  4. 掩码本身也是表达式：`(0x2 ^ 0x3e)`，而不是 `60`。

用法：
    python server/tools/gen_signer_js.py            # 写入 server/signer.obf.js
    python server/tools/gen_signer_js.py --stdout   # 打到标准输出，不写文件
"""

from __future__ import annotations

import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.dirname(HERE)
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

import secret  # noqa: E402

OUT_PATH = os.path.join(SERVER_DIR, "signer.obf.js")

# SHA-256 的 64 个轮常量与 8 个初始向量（标准值，硬编码避免浮点误差）
SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
SHA256_H = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

# 字符串表的字符池：大小写字母 + 数字（全部是单字节、无转义歧义的字符）
POOL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def build_table() -> list[str]:
    """按固定种子生成字符串表，并把盐的字符放到约定的下标上。"""
    rnd = random.Random(secret.JS_TABLE_SEED)
    table = [rnd.choice(POOL) for _ in range(secret.JS_TABLE_LEN)]
    for pos, ch in zip(secret.SALT_INDEX, secret.SERVER_SALT):
        if pos >= len(table):
            raise ValueError(f"下标 {pos} 超出字符串表长度 {len(table)}")
        table[pos] = ch
    return table


def index_expr(value: int, rnd: random.Random) -> str:
    """把一个整数写成一条等价的常量折叠表达式，例如 8 -> (0x10 >> 1)。"""
    mode = rnd.randrange(3)
    if mode == 0:                      # 异或
        other = rnd.randrange(1, 0x60)
        return f"(0x{value ^ other:x} ^ 0x{other:x})"
    if mode == 1:                      # 右移
        shift = rnd.randrange(1, 6)
        return f"(0x{value << shift:x} >> {shift})"
    other = rnd.randrange(1, max(2, value))   # 加法
    return f"(0x{value - other:x} + 0x{other:x})"


def js_table_literal(table: list[str]) -> str:
    """把字符表写成「与掩码异或后的数字」数组，运行期再还原成字符。"""
    codes = [ord(ch) ^ secret.JS_TABLE_MASK for ch in table]
    return js_hex_list(codes, per_line=8, indent=4)


def js_index_literal() -> str:
    rnd = random.Random(secret.JS_TABLE_SEED ^ 0x5A5A)
    items = [index_expr(i, rnd) for i in secret.SALT_INDEX]
    return "\n    " + ",\n    ".join(items) + "\n  "


def js_hex_list(values, per_line=8, indent=4) -> str:
    items = [f"0x{v:08x}" for v in values] if max(values) > 0xFFFF else \
            [f"0x{v:02x}" for v in values]
    pad = " " * indent
    lines = []
    for i in range(0, len(items), per_line):
        lines.append(pad + ", ".join(items[i:i + per_line]) + ",")
    return "\n".join(lines).rstrip(",")


TEMPLATE = r"""/* sign-lab synthetic signer — obfuscated build
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
/*@K@*/
    ];
    var _H0 = [/*@H@*/];

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
/*@TABLE@*/
  ];
  var _0xT = (function () {
    var _m = (0x2 ^ 0x3e), a = [], i;
    for (i = 0; i < _0xR.length; i++) { a.push(String.fromCharCode(_0xR[i] ^ _m)); }
    return a;
  })();
  var _0xI = [/*@INDEX@*/];

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
"""


def render() -> str:
    table = build_table()
    js = TEMPLATE
    js = js.replace("/*@K@*/", js_hex_list(SHA256_K))
    js = js.replace("/*@H@*/", ", ".join(f"0x{v:08x}" for v in SHA256_H))
    js = js.replace("/*@TABLE@*/", js_table_literal(table))
    js = js.replace("/*@INDEX@*/", js_index_literal())
    return js


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 sign-lab 混淆签名脚本")
    ap.add_argument("--stdout", action="store_true", help="打到标准输出，不写文件")
    args = ap.parse_args()

    js = render()
    if args.stdout:
        sys.stdout.write(js)
        return 0

    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(js)
    table = build_table()
    print(f"[ok] 已写入 {OUT_PATH}（{len(js)} 字节）")
    print(f"[ok] 盐长度 {len(secret.SERVER_SALT)}，下标 {list(secret.SALT_INDEX)}，"
          f"表长 {len(table)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
