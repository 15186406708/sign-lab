#!/usr/bin/env python3
"""sign-lab 服务端：签名校验 + 令牌桶限流 + 429 原地退避提示。

零依赖，只用 Python 标准库。

启动：
    python server/app.py                      # 默认 127.0.0.1:8787
    SIGNLAB_PORT=9000 python server/app.py

接口：
    GET /health                存活探测
    GET /api/signer.js         下发混淆版客户端签名脚本（明文，供静态分析）
    GET /api/items?<params>    受保护的数据接口，必须带签名头

受保护接口的请求头：
    X-Nonce   一次性随机串（8~64 位，仅允许 [A-Za-z0-9_-]）
    X-Ts      毫秒级时间戳（13 位），与服务端时差不得超过 ±5 分钟
    X-Sign    小写十六进制签名，算法见 server/signer.obf.js

服务端的错误码：
    400 参数或请求头不合法
    401 签名错误 / 时间戳过期 / nonce 重放
    404 路径不存在
    429 触发限流（正文里带「N 秒后重试」，同时给 Retry-After 头）
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import secret  # noqa: E402  服务端机密（盐、限流参数）

ROOT = os.path.dirname(HERE)
LOG_DIR = os.path.join(ROOT, "logs")
ACCESS_LOG = os.path.join(LOG_DIR, "access.jsonl")
SIGNER_JS = os.path.join(HERE, "signer.obf.js")

HOST = os.environ.get("SIGNLAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIGNLAB_PORT", "8787"))

_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_TS_RE = re.compile(r"^\d{13}$")


# --------------------------------------------------------------------------
# 业务数据（合成，和任何真实站点无关）
# --------------------------------------------------------------------------
def make_items(page: int, size: int) -> list[dict]:
    items = []
    base = (page - 1) * size
    for offset in range(size):
        n = base + offset + 1
        if n > secret.TOTAL_ITEMS:
            break
        items.append({
            "id": f"ITM{n:06d}",
            "name": f"synthetic-item-{n}",
            "score": (n * 37) % 100,
            "updated_at": 1_760_000_000 + n * 60,
        })
    return items


def canonical_query(query_string: str) -> str:
    """规范化查询串：按参数名升序，拼成 k=v，用 & 连接。"""
    pairs = parse_qsl(query_string, keep_blank_values=True)
    pairs.sort(key=lambda kv: kv[0])
    return "&".join(f"{key}={value}" for key, value in pairs)


def expected_sign(nonce: str, canonical: str, ts: str) -> str:
    raw = f"{nonce}{secret.SERVER_SALT}{canonical}{ts}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 限流：按客户端 IP 的令牌桶
# --------------------------------------------------------------------------
class TokenBucket:
    """容量固定、匀速回填的令牌桶。返回 (是否放行, 建议等待秒数)。"""

    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = float(capacity)
        self.refill = float(refill_per_sec)
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    # 状态表按客户端建条目。放在内网自己用不会有问题，但**一旦对公网开放**，
    # 扫描器/爬虫会带来大量不同来源，条目数只增不减 —— 那就是一个缓慢的内存泄漏。
    #
    # 回收判据（这里我第一版写错了，被测试抓出来）：
    #   错：按"令牌已回满"判断 —— 但客户端用完就剩 capacity-1，**永远回不满**，判据失效。
    #   对：按**空闲时间**判断 —— 只要距上次使用已经超过"从空回满所需的时间"，
    #       这个条目再被用到时也会先回满，因此**删掉它和保留它在行为上完全等价**。
    #
    # 由此得到的内存上界：条目数只与"最近一个回满周期内活跃过的来源数"相关，
    # 更早的来源会在下次请求时被清掉。
    _SWEEP_THRESHOLD = 128

    def _idle_window(self) -> float:
        """从空回满需要多久 —— 超过这个时长没动过的条目可以安全删除。"""
        return self.capacity / self.refill if self.refill > 0 else float("inf")

    def _sweep(self, now: float) -> None:
        """条目数超过阈值时清理空闲条目。调用方需持锁。"""
        if len(self._state) < self._SWEEP_THRESHOLD:
            return
        window = self._idle_window()
        idle = [key for key, (_tokens, last) in self._state.items()
                if now - last >= window]
        for key in idle:
            del self._state[key]

    def take(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens >= 1.0:
                self._state[key] = (tokens - 1.0, now)
                allowed, wait = True, 0.0
            else:
                self._state[key] = (tokens, now)
                allowed = False
                wait = (1.0 - tokens) / self.refill if self.refill > 0 else 60.0
            # 两条路径都要触发清理：只在"被拦"时清理，正常放行的流量永远不会触发它
            self._sweep(now)
            return allowed, wait


class NonceStore:
    """一次性 nonce 缓存：验签通过后才登记，过期自动清理。"""

    def __init__(self, ttl: float):
        self.ttl = ttl
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str) -> bool:
        """未被用过则登记并返回 True；重放则返回 False。"""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, exp in self._seen.items() if exp <= now]
            for k in expired:
                del self._seen[k]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + self.ttl
            return True


limiter = TokenBucket(secret.RATE_CAPACITY, secret.RATE_REFILL_PER_SEC)
nonces = NonceStore(secret.NONCE_TTL_SEC)
_log_lock = threading.Lock()


def write_access_log(record: dict) -> None:
    """审计日志：append-only JSONL，方便事后复盘限流与失败模式。"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False)
        with _log_lock:
            with open(ACCESS_LOG, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except OSError:
        pass  # 日志失败不影响主流程


class Handler(BaseHTTPRequestHandler):
    server_version = "sign-lab/1.0"
    protocol_version = "HTTP/1.1"

    # --- 基础设施 ---------------------------------------------------------
    def log_message(self, fmt, *args):  # 关掉默认的 stderr 噪声
        return

    def _send(self, status: int, payload: dict, extra_headers: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, str(value))
        self.end_headers()
        self.wfile.write(body)

    def _send_js(self):
        try:
            with open(SIGNER_JS, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send(404, {"code": 404, "errmsg": "signer script not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # --- 路由 -------------------------------------------------------------
    def do_GET(self):  # noqa: N802  (标准库约定的方法名)
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, {"code": 0, "data": {"status": "ok", "port": PORT}})
            return
        if parsed.path == "/api/signer.js":
            self._send_js()
            return
        if parsed.path == "/api/items":
            self._handle_items(parsed.query)
            return
        self._send(404, {"code": 404, "errmsg": "not found"})

    # --- 受保护接口 -------------------------------------------------------
    def _handle_items(self, query_string: str):
        client = self.client_address[0]
        started = time.time()

        # 1) 限流放在验签之前：省算力，且被拦时客户端能立刻拿到等待时长
        allowed, wait = limiter.take(client)
        if not allowed:
            seconds = max(1, int(wait + 0.999))
            write_access_log({"ts": started, "client": client, "path": "/api/items",
                              "status": 429, "retry_after": seconds})
            self._send(429, {
                "code": 429,
                "errmsg": f"请求过于频繁，请在 {seconds} 秒后重试",
                "retry_after": seconds,
            }, {"Retry-After": seconds})
            return

        # 2) 参数
        try:
            raw = dict(parse_qsl(query_string, keep_blank_values=True))
            page = int(raw.get("page", "1"))
            size_raw = int(raw.get("size", "20"))
        except ValueError:
            self._send(400, {"code": 400, "errmsg": "page/size 必须是整数"})
            return
        if page < 1 or size_raw < 1:
            self._send(400, {"code": 400, "errmsg": "page/size 必须为正数"})
            return
        size = min(size_raw, secret.MAX_SIZE)

        # 3) 请求头
        nonce = self.headers.get("X-Nonce", "")
        ts = self.headers.get("X-Ts", "")
        sign = self.headers.get("X-Sign", "")
        if not (_NONCE_RE.match(nonce) and _TS_RE.match(ts)):
            self._send(400, {"code": 400,
                             "errmsg": "缺少或不合法的 X-Nonce / X-Ts"})
            return

        now_ms = int(time.time() * 1000)
        skew = abs(now_ms - int(ts))
        canonical = canonical_query(query_string)

        # 401 里回带规范化串：真实服务端未必给，但靶场刻意给，
        # 用来复现「两侧分别打印中间值、逐段对齐」的排错流程。
        def deny(reason: str):
            write_access_log({"ts": started, "client": client, "path": "/api/items",
                              "status": 401, "reason": reason,
                              "canonical": canonical})
            self._send(401, {"code": 401, "errmsg": reason, "canonical": canonical})

        if skew > secret.TS_SKEW_MS:
            deny(f"时间戳偏差 {skew}ms 超过上限 {secret.TS_SKEW_MS}ms")
            return

        want = expected_sign(nonce, canonical, ts)
        if not hmac.compare_digest(want, sign):
            deny("签名校验失败")
            return

        # 4) 防重放：验签通过后才消耗 nonce
        if not nonces.check_and_add(nonce):
            deny("nonce 已被使用（重放）")
            return

        items = make_items(page, size)
        write_access_log({"ts": started, "client": client, "path": "/api/items",
                          "status": 200, "page": page, "size": size})
        self._send(200, {
            "code": 0,
            "data": {
                "page": page,
                "size": size,
                "size_requested": size_raw,
                "size_capped": size != size_raw,
                "total": secret.TOTAL_ITEMS,
                "items": items,
            },
        })


def main() -> int:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"[sign-lab] 监听 http://{HOST}:{PORT}")
    print(f"[sign-lab] 限流：容量 {secret.RATE_CAPACITY}，"
          f"每 {1 / secret.RATE_REFILL_PER_SEC:.1f} 秒恢复 1 个令牌（按 IP）")
    print(f"[sign-lab] page_size 上限 {secret.MAX_SIZE}，数据集 {secret.TOTAL_ITEMS} 条")
    print(f"[sign-lab] 审计日志 {ACCESS_LOG}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[sign-lab] 收到 Ctrl+C，正在退出")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
