#!/usr/bin/env python3
"""客户端限流治理：令牌桶 + 429 原地退避 + 指数退避（带抖动）。

这里的每一条都来自实战教训，不是教科书抄的：

  * **全局限速**：限速必须是「全局限速器」，不能是「每页 sleep」。
    并发一上来，每页 sleep 等于没有限速。
  * **429 原地退避**：被服务端拦下时，读服务端给的等待时长，原地睡够再重试同一页。
    绝不把 429 抛成异常交给上层/框架重试 —— 框架的自动重试会连点，
    把限流窗口拖得更长（连着 10 次 429 之后，恢复时间会从 2 秒变成几十秒）。
  * **等待时长优先读正文**：真实服务端经常只在 errmsg 里写「请在 N 秒后重试」，
    Retry-After 头反而是缺的，所以正文正则是一等公民。
  * **抖动**：等待时长加随机抖动，避免多个客户端同时醒来再次撞在一起。
"""

from __future__ import annotations

import random
import re
import threading
import time
from email.message import Message
from typing import Any, Mapping

__all__ = [
    "TokenBucket",
    "parse_retry_after",
    "Backoff",
]

# 「请在 3 秒后重试」「retry after 3s」「等待 2.5 秒」等常见写法
_WAIT_PATTERNS = (
    re.compile(r"(\d+(?:\.\d+)?)\s*秒"),
    re.compile(r"retry[\s\-_]*after[^\d]{0,8}(\d+(?:\.\d+)?)", re.I),
    re.compile(r"wait[^\d]{0,8}(\d+(?:\.\d+)?)", re.I),
    re.compile(r"(\d+(?:\.\d+)?)\s*(?:s|sec|seconds?)\b", re.I),
)


class TokenBucket:
    """按固定速率发令牌的全局限速器（线程安全）。"""

    def __init__(self, capacity: float = 1.0, refill_per_sec: float = 1.0):
        if refill_per_sec <= 0:
            raise ValueError("refill_per_sec 必须为正数")
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """取一个令牌，不足则阻塞等待。返回实际等待秒数。"""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity,
                                   self._tokens + (now - self._last) * self.refill)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return waited
                need = (1.0 - self._tokens) / self.refill
            time.sleep(need)
            waited += need


class Backoff:
    """网络类错误的指数退避（429 之外的兜底）。"""

    def __init__(self, base: float = 1.0, factor: float = 2.0,
                 cap: float = 30.0, jitter: float = 0.3):
        self.base, self.factor, self.cap, self.jitter = base, factor, cap, jitter
        self.attempt = 0

    def reset(self) -> None:
        self.attempt = 0

    def next_delay(self) -> float:
        raw = min(self.cap, self.base * (self.factor ** self.attempt))
        self.attempt += 1
        return raw + random.uniform(0, raw * self.jitter)


def _header_get(headers: Mapping[str, Any] | Message | None, name: str) -> str | None:
    if headers is None:
        return None
    if hasattr(headers, "get"):
        return headers.get(name)  # type: ignore[return-value]
    return None


def parse_retry_after(body: Any = None, headers: Mapping[str, Any] | None = None,
                      default: float = 5.0) -> float:
    """按优先级解析「该等多少秒」：正文文本 → retry_after 字段 → Retry-After 头 → 默认值。

    正文文本优先，因为真实服务端最常把等待时长写在 errmsg / message 里。
    """
    text_candidates: list[str] = []
    if isinstance(body, str):
        text_candidates.append(body)
    elif isinstance(body, Mapping):
        for key in ("errmsg", "err_msg", "message", "msg", "error", "detail"):
            value = body.get(key)
            if isinstance(value, str):
                text_candidates.append(value)

    for text in text_candidates:
        for pattern in _WAIT_PATTERNS:
            match = pattern.search(text)
            if match:
                return max(0.0, float(match.group(1)))

    if isinstance(body, Mapping):
        for key in ("retry_after", "retryAfter", "wait", "wait_seconds"):
            value = body.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return max(0.0, float(value))
            if isinstance(value, str):
                try:
                    return max(0.0, float(value))
                except ValueError:
                    pass

    header = _header_get(headers, "Retry-After")
    if header:
        try:
            return max(0.0, float(header))
        except ValueError:
            pass

    return default
