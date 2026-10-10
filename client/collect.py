#!/usr/bin/env python3
"""端到端采集：拉混淆 JS → 静态还原盐 → 纯 Python 复算签名 → 带限速采集。

    python client/collect.py --base-url http://127.0.0.1:8787 --pages 6 --size 20

做到的几件「能长期跑」的事：
  * **零 JS 运行时依赖**：不调 Node、不用 execjs，签名是纯 Python 算出来的；
  * **全局限速**：客户端主动留安全余量（默认 2.2s/次，比服务端的 2.0s/token 更保守）；
  * **429 原地退避**：读服务端给的等待时长，原地睡够重试同一页，绝不抛异常给上层；
  * **断点续跑**：checkpoint 记录已完成页，中断后重跑不会重头再来；
  * **幂等落盘**：按 id 去重，重复跑同一页不会写出重复行；
  * **审计报告**：把请求数、429 次数、累计等待时长落成 JSON，方便复盘。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import _bootstrap  # noqa: E402,F401  让 ratelimit_kit 可导入
import recover  # noqa: E402
import signer  # noqa: E402
from ratelimit_kit import Backoff, TokenBucket, parse_retry_after  # noqa: E402

DEFAULT_BASE = "http://127.0.0.1:8787"
# 服务端没写等待时长时的兜底退避（ratelimit_kit 刻意不替调用方猜这个数）
DEFAULT_RETRY_WAIT = 5.0


class Stats:
    def __init__(self):
        self.requests = 0
        self.http_429 = 0
        self.http_401 = 0
        self.errors = 0
        self.wait_seconds = 0.0
        self.items_written = 0
        self.duplicates_skipped = 0
        self.pages_done = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "http_429": self.http_429,
            "http_401": self.http_401,
            "errors": self.errors,
            "wait_seconds": round(self.wait_seconds, 3),
            "items_written": self.items_written,
            "duplicates_skipped": self.duplicates_skipped,
            "pages_done": self.pages_done,
        }


def http_get(url: str, headers: dict[str, str] | None = None,
             timeout: float = 15.0) -> tuple[int, dict[str, str], str]:
    """返回 (状态码, 响应头, 正文)。4xx/5xx 不抛异常，交给调用方判断。"""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, dict(exc.headers or {}), body


def load_json(path: str, default: Any) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)   # 原子替换：中断也不会留下半个文件


def load_seen_ids(out_path: str) -> set[str]:
    seen: set[str] = set()
    if not os.path.exists(out_path):
        return seen
    with open(out_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and "id" in record:
                seen.add(str(record["id"]))
    return seen


def fetch_page(base: str, salt: str, page: int, size: int, stats: Stats,
               limiter: ratelimit_kit.TokenBucket, backoff: ratelimit_kit.Backoff,
               *, timeout: float, max_retries: int) -> list[dict]:
    """取一页。429 → 原地退避；401 → 直接失败并打出对齐信息（签名算错了）。"""
    params = {"page": str(page), "size": str(size)}
    canonical_local = signer.canonical_query(params)

    for attempt in range(1, max_retries + 1):
        waited = limiter.acquire()
        stats.wait_seconds += waited

        ts = str(int(time.time() * 1000))
        nonce = uuid.uuid4().hex
        headers = signer.sign_headers(salt, params, ts, nonce)
        headers["Accept"] = "application/json"
        url = f"{base}/api/items?page={params['page']}&size={params['size']}"

        try:
            status, resp_headers, body = http_get(url, headers, timeout=timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            stats.errors += 1
            delay = backoff.next_delay()
            print(f"  [网络错误] {exc.__class__.__name__}: {exc} — {delay:.1f}s 后重试")
            stats.wait_seconds += delay
            time.sleep(delay)
            continue

        stats.requests += 1
        backoff.reset()

        if status == 200:
            payload = json.loads(body)
            data = payload.get("data", {})
            if data.get("size_capped"):
                print(f"  [注意] 请求 size={data.get('size_requested')} "
                      f"被服务端截断到 {data.get('size')}")
            return data.get("items", [])

        if status == 429:
            stats.http_429 += 1
            payload = load_json_str(body)
            # ratelimit_kit 解析不出来时返回 None —— 兜底值由调用方显式决定
            delay = parse_retry_after(payload, resp_headers) or DEFAULT_RETRY_WAIT
            jittered = delay + random.uniform(0, 0.5)
            print(f"  [429] 第 {attempt}/{max_retries} 次，服务端要求等 "
                  f"{delay:.0f}s（实际退避 {jittered:.1f}s）原地重试同一页")
            stats.wait_seconds += jittered
            time.sleep(jittered)
            continue          # 原地退避：不换页、不抛异常

        if status == 401:
            stats.http_401 += 1
            payload = load_json_str(body)
            server_canonical = payload.get("canonical")
            print(f"  [401] {payload.get('errmsg')} — 签名算错了，重试没意义，直接停")
            print(f"        本地规范化串 = {canonical_local!r}")
            if server_canonical is not None:
                print(f"        服务端规范化串 = {server_canonical!r}")
                if server_canonical != canonical_local:
                    print("        ↑ 两边不一致，问题出在拼接规则/参与字段，不是编码")
            raise SystemExit(2)

        stats.errors += 1
        print(f"  [HTTP {status}] {body[:200]}")

    print(f"  [放弃] 第 {page} 页重试 {max_retries} 次仍未成功")
    return []


def load_json_str(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


def main() -> int:
    ap = argparse.ArgumentParser(description="sign-lab 端到端采集器")
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    ap.add_argument("--pages", type=int, default=6, help="最多采集多少页")
    ap.add_argument("--size", type=int, default=20, help="每页条数（服务端上限 50）")
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "items.jsonl"))
    ap.add_argument("--state", default=os.path.join(ROOT, "data", "checkpoint.json"))
    ap.add_argument("--report", default=os.path.join(ROOT, "data", "collect_report.json"))
    ap.add_argument("--min-interval", type=float, default=2.2,
                    help="全局限速间隔秒数（服务端每 2.0s 恢复 1 个令牌，这里更保守）")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--max-retries", type=int, default=4)
    ap.add_argument("--restart", action="store_true", help="忽略 checkpoint，从第 1 页重来")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    stats = Stats()

    print(f"[1/4] 拉取混淆签名脚本 {base}/api/signer.js")
    try:
        salt = recover.load_salt_from_url(f"{base}/api/signer.js", timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001  靶场里给出足够信息更重要
        print(f"      失败：{exc.__class__.__name__}: {exc}")
        return 1
    print(f"      静态还原出签名盐：{salt!r}（没有执行任何 JS）")

    print(f"[2/4] 准备落盘：{os.path.relpath(args.out, ROOT)}")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    seen = load_seen_ids(args.out)
    state = {} if args.restart else load_json(args.state, {})
    start_page = int(state.get("last_page", 0)) + 1
    if start_page > 1:
        print(f"      发现断点，从第 {start_page} 页继续（已落盘 {len(seen)} 条）")
    else:
        print(f"      全新开始（已存在 {len(seen)} 条历史数据）")

    print(f"[3/4] 开始采集：第 {start_page} ~ {args.pages} 页，"
          f"每页 {args.size} 条，全局限速 {args.min_interval}s/次")
    limiter = TokenBucket(capacity=1.0,
                          refill_per_sec=1.0 / max(args.min_interval, 0.001))
    backoff = Backoff(base=1.0, factor=2.0, cap=30.0)

    with open(args.out, "a", encoding="utf-8") as fh:
        for page in range(start_page, args.pages + 1):
            items = fetch_page(base, salt, page, args.size, stats, limiter, backoff,
                              timeout=args.timeout, max_retries=args.max_retries)
            written = 0
            for item in items:
                key = str(item.get("id"))
                if key in seen:
                    stats.duplicates_skipped += 1
                    continue
                seen.add(key)
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
                written += 1
            fh.flush()
            os.fsync(fh.fileno())          # 落盘后再推进 checkpoint
            stats.items_written += written
            stats.pages_done += 1
            # checkpoint 只前进不后退：用 --restart 重跑旧页时不能被写回去
            checkpoint = max(page, int(state.get("last_page", 0)))
            save_json(args.state, {"last_page": checkpoint,
                                   "updated_at": int(time.time())})
            print(f"  第 {page:>2} 页：拿到 {len(items):>2} 条，写入 {written:>2} 条，"
                  f"跳过重复 {len(items) - written} 条")

    print("[4/4] 汇总")
    report = stats.as_dict()
    report["salt"] = salt
    report["base_url"] = base
    save_json(args.report, report)
    for key, value in report.items():
        print(f"      {key:<20} {value}")
    print(f"\n数据：{os.path.abspath(args.out)}")
    print(f"报告：{os.path.abspath(args.report)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
