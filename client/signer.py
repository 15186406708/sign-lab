#!/usr/bin/env python3
"""sign-lab 纯 Python 签名实现（不依赖 Node / execjs）。

这是「复算」的那一半：把 JS 里的签名算法用 Python 原样实现出来。
盐不在这里硬编码 —— 它由 client/recover.py 从混淆 JS 里静态还原后传进来。
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping


def canonical_query(params: Mapping[str, Any]) -> str:
    """把参数字典规范化成待签串。

    规则（从 signer.obf.js 的 canonical 实现还原）：
      1. 按参数名升序排序
      2. 拼成 k=v
      3. 用 & 连接
    注意：值是 URL 解码后的原始值，不做二次编码。
    """
    return "&".join(f"{key}={params[key]}" for key in sorted(params))


def sign(salt: str, params: Mapping[str, Any], ts: str | int, nonce: str) -> str:
    """复算签名：sha256(nonce + 盐 + 规范化查询串 + 毫秒时间戳)，小写十六进制。"""
    raw = f"{nonce}{salt}{canonical_query(params)}{ts}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sign_headers(salt: str, params: Mapping[str, Any], ts: str | int,
                 nonce: str) -> dict[str, str]:
    """组装成可以直接发给服务端的请求头。"""
    return {
        "X-Nonce": nonce,
        "X-Ts": str(ts),
        "X-Sign": sign(salt, params, ts, nonce),
    }
