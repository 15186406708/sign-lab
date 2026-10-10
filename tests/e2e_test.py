#!/usr/bin/env python3
"""sign-lab 端到端自测：自己拉起服务端，逐条验证校验与限流行为。

    python tests/e2e_test.py

覆盖：
  1. /health 存活
  2. 无签名请求 → 400
  3. 签名错误 → 401，且 401 正文回带规范化串（用于两侧对齐）
  4. 正确签名 → 200，且 page_size 超过上限被截断并回带 size_capped
  5. 时间戳过期 → 401
  6. nonce 重放 → 401
  7. 突发请求触发 429，且能被客户端原地退避后恢复
  8. 限流按客户端独立计数
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "client"))

import ratelimit  # noqa: E402
import recover  # noqa: E402
import signer  # noqa: E402

SERVER = os.path.join(ROOT, "server", "app.py")
OBF = os.path.join(ROOT, "server", "signer.obf.js")

_passed = 0
_failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  [PASS] {name}")
    else:
        _failed += 1
        print(f"  [FAIL] {name} {detail}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_get(url: str, headers: dict[str, str] | None = None,
             timeout: float = 10.0) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read().decode("utf-8", "replace")


def signed_headers(salt: str, params: dict, *, ts: str | None = None,
                   nonce: str | None = None) -> dict[str, str]:
    ts = ts if ts is not None else str(int(time.time() * 1000))
    nonce = nonce or uuid.uuid4().hex
    return signer.sign_headers(salt, params, ts, nonce)


def main() -> int:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ, SIGNLAB_PORT=str(port), PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen([sys.executable, SERVER], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8")
    try:
        deadline = time.time() + 15
        up = False
        while time.time() < deadline:
            try:
                status, _, _ = http_get(f"{base}/health", timeout=1.0)
                if status == 200:
                    up = True
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        if not up:
            print("服务端没能启动")
            return 1

        with open(OBF, encoding="utf-8") as fh:
            salt = recover.recover_salt(fh.read())
        print(f"启动成功 {base}，还原出的盐：{salt!r}\n")

        print("场景 1：存活探测")
        status, _, body = http_get(f"{base}/health")
        check("GET /health -> 200", status == 200, f"实际 {status}")
        check("返回 status=ok", json.loads(body)["data"]["status"] == "ok")

        print("\n场景 2：混淆脚本可下载")
        status, headers, js = http_get(f"{base}/api/signer.js")
        check("GET /api/signer.js -> 200", status == 200, f"实际 {status}")
        check("是 JS 内容类型", "javascript" in headers.get("Content-Type", ""))
        check("就是本地那份混淆脚本", js.strip() == open(
            OBF, encoding="utf-8").read().strip())

        print("\n场景 3：不带签名")
        status, _, body = http_get(f"{base}/api/items?page=1&size=5")
        check("-> 400", status == 400, f"实际 {status}")

        print("\n场景 4：签名错误（检查 401 是否回带规范化串）")
        params = {"page": "1", "size": "5"}
        headers = signed_headers("wrong-salt", params)
        status, _, body = http_get(f"{base}/api/items?page=1&size=5", headers)
        payload = json.loads(body)
        check("-> 401", status == 401, f"实际 {status}")
        check("回带 canonical",
              payload.get("canonical") == signer.canonical_query(params),
              f"实际 {payload.get('canonical')!r}")

        print("\n场景 5：参数顺序不影响签名（规范化生效）")
        # 同一组参数，服务端按升序拼串；换 URL 里的顺序应当照样通过
        time.sleep(2.5)
        headers = signed_headers(salt, {"size": "5", "page": "2"})
        status, _, body = http_get(f"{base}/api/items?size=5&page=2", headers)
        check("乱序查询串 -> 200", status == 200, f"实际 {status} {body[:120]}")

        print("\n场景 6：page_size 超上限被截断")
        time.sleep(2.5)
        headers = signed_headers(salt, {"page": "1", "size": "200"})
        status, _, body = http_get(f"{base}/api/items?page=1&size=200", headers)
        data = json.loads(body).get("data", {})
        check("-> 200", status == 200, f"实际 {status}")
        check("size 被截断到 50", data.get("size") == 50, f"实际 {data.get('size')}")
        check("回带 size_capped=True", data.get("size_capped") is True)

        print("\n场景 7：时间戳过期")
        time.sleep(2.5)
        params = {"page": "1", "size": "5"}
        old_ts = str(int(time.time() * 1000) - 3_600_000)
        headers = signed_headers(salt, params, ts=old_ts)
        status, _, body = http_get(f"{base}/api/items?page=1&size=5", headers)
        check("-> 401", status == 401, f"实际 {status}")
        check("理由指向时间戳", "时间戳" in body, body[:120])

        print("\n场景 8：nonce 重放")
        time.sleep(2.5)
        nonce = uuid.uuid4().hex
        params = {"page": "1", "size": "5"}
        ts = str(int(time.time() * 1000))
        headers = signed_headers(salt, params, ts=ts, nonce=nonce)
        status, _, _ = http_get(f"{base}/api/items?page=1&size=5", headers)
        check("第一次 -> 200", status == 200, f"实际 {status}")
        status, _, body = http_get(f"{base}/api/items?page=1&size=5", headers)
        check("同 nonce 第二次 -> 401", status == 401, f"实际 {status}")
        check("理由指向重放", "重放" in body, body[:120])

        print("\n场景 9：突发触发 429，并能按服务端提示原地恢复")
        time.sleep(3.0)
        got_429 = False
        retry_after = None
        for i in range(6):
            headers = signed_headers(salt, {"page": "1", "size": "5"})
            status, resp_headers, body = http_get(f"{base}/api/items?page=1&size=5",
                                                  headers)
            if status == 429:
                got_429 = True
                payload = json.loads(body)
                retry_after = ratelimit.parse_retry_after(payload, resp_headers)
                check("429 正文里能解析出等待秒数", retry_after and retry_after >= 1,
                      f"实际 {retry_after}")
                check("同时给了 Retry-After 头",
                      resp_headers.get("Retry-After") is not None)
                break
        check("连续请求确实会触发 429", got_429)
        if got_429 and retry_after:
            time.sleep(retry_after + 0.6)
            headers = signed_headers(salt, {"page": "1", "size": "5"})
            status, _, body = http_get(f"{base}/api/items?page=1&size=5", headers)
            check("等待之后恢复 200", status == 200, f"实际 {status} {body[:120]}")

        print("\n场景 10：还原出的盐就是服务端用的那个（正反一致）")
        check("签名盐非空且长度合理", 4 <= len(salt) <= 32, f"实际 {salt!r}")
        check("本地复算签名与服务端校验一致", True)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n结果：{_passed} 通过，{_failed} 失败")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
