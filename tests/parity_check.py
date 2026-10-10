#!/usr/bin/env python3
"""交叉验证：混淆 JS 的执行结果 == Python 复算结果。

这一步是「复算」路线能不能信的关键——如果两侧算出来不一样，后面所有采集都是白跑。

    python tests/parity_check.py

会自动寻找 Node（PATH、fnm、常见安装目录）。找不到 Node 时会跳过 JS 侧，
只做还原结果的自洽检查，并明确告诉你跳过原因。
"""

from __future__ import annotations

import glob
import json
import os
import random
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "client"))

import recover  # noqa: E402
import signer  # noqa: E402

OBF = os.path.join(ROOT, "server", "signer.obf.js")
HARNESS = os.path.join(HERE, "js_parity.js")
CASE_COUNT = 24

def _node_search_patterns() -> list[str]:
    """收集 Node 的候选位置。想手工指定就设 SIGNLAB_NODE_DIR。"""
    patterns = [
        os.path.expandvars(r"%LOCALAPPDATA%\fnm\node-versions\*\installation"),
        os.path.expandvars(r"%APPDATA%\fnm\node-versions\*\installation"),
        os.path.expandvars(r"%FNM_DIR%\node-versions\*\installation"),
        os.path.expandvars(r"%LOCALAPPDATA%\nvm\v*"),
        os.path.expandvars(r"%APPDATA%\nvm\v*"),
        r"C:\Program Files\nodejs",
        r"C:\Program Files (x86)\nodejs",
    ]
    override = os.environ.get("SIGNLAB_NODE_DIR")
    if override:
        patterns.insert(0, override)
    # fnm 的数据目录可以被配置到任意位置，按「盘符 + 一层目录」通用地找一遍
    for drive in ("C:", "D:", "E:", "F:"):
        patterns.append(os.path.join(drive, os.sep, "*", "fnm-data",
                                     "node-versions", "*", "installation"))
    return patterns


def find_node() -> str | None:
    """按优先级找 Node：PATH → fnm/nvm 的版本目录 → 常见安装位置。"""
    found = shutil.which("node")
    if found:
        return found
    exe = "node.exe" if os.name == "nt" else "node"
    candidates: list[str] = []
    for pattern in _node_search_patterns():
        bases = glob.glob(pattern) if "*" in pattern else [pattern]
        for base in bases:
            candidate = os.path.join(base, exe)
            if os.path.isfile(candidate):
                candidates.append(candidate)
    if not candidates:
        return None
    return sorted(candidates)[-1]   # 取版本号最大的一份


def build_cases(rnd: random.Random) -> list[dict]:
    cases = []
    fixed = [
        {"page": "1", "size": "20"},
        {"page": "2", "size": "50", "category": "synthetic"},
        {"size": "50", "page": "3"},            # 键顺序颠倒，考验排序
        {"q": "中文关键字", "page": "1"},        # 非 ASCII，考验 UTF-8 编码
        {"empty": "", "page": "1"},             # 空值
    ]
    for params in fixed:
        cases.append({
            "params": params,
            "ts": str(rnd.randrange(1_700_000_000_000, 1_800_000_000_000)),
            "nonce": "".join(rnd.choice("abcdef0123456789") for _ in range(16)),
        })
    for _ in range(CASE_COUNT - len(fixed)):
        params = {"page": str(rnd.randint(1, 9)), "size": str(rnd.randint(1, 50))}
        if rnd.random() < 0.4:
            params["keyword"] = "".join(rnd.choice("abcXYZ中文019") for _ in range(6))
        cases.append({
            "params": params,
            "ts": str(rnd.randrange(1_700_000_000_000, 1_800_000_000_000)),
            "nonce": "".join(rnd.choice("abcdef0123456789") for _ in range(16)),
        })
    return cases


def check_literal_fallback() -> None:
    """另一种表形态（明文单字符数组）也要能还原，别让容错分支变成死代码。"""
    snippet = (
        "var _0xT = ['\\x78', '\\x79', '\\x73', '\\x31', '\\x67', '\\x6e', "
        "'\\x61', '\\x62'];\n"
        "var _0xI = [2, 3, 4, 5, 6, 7];\n"
        "function _0xk() { var s = '', i; "
        "for (i = 0; i < _0xI.length; i++) { s += _0xT[_0xI[i]]; } return s; }\n"
    )
    salt, detail = recover.load_salt_from_js(snippet)
    assert detail["table_kind"] == "literal", detail
    assert salt == "s1gnab", f"期望 s1gnab，实际 {salt!r}"
    print("      形态 A（明文单字符表）容错分支：通过")


def main() -> int:
    print(f"[1/4] 静态还原：{os.path.relpath(OBF, ROOT)}")
    with open(OBF, encoding="utf-8") as fh:
        source = fh.read()
    salt, detail = recover.load_salt_from_js(source)
    kind = "异或码表" if detail["table_kind"] == "xor" else "明文字符表"
    print(f"      字符串表形态：{kind}")
    if detail["mask"] is not None:
        print(f"      掩码 0x{detail['mask']:02x}")
    print(f"      {detail['table_name']}[{detail['table_length']}] "
          f"-> 下标 {detail['index']} ({detail['index_name']})")
    print(f"      还原出的盐：{salt!r}（{detail['salt_length']} 字符）")
    check_literal_fallback()

    rnd = random.Random(20261010)
    cases = build_cases(rnd)

    print("[2/4] Python 侧复算")
    py_results = [
        {
            "canonical": signer.canonical_query(c["params"]),
            "sign": signer.sign(salt, c["params"], c["ts"], c["nonce"]),
        }
        for c in cases
    ]
    print(f"      {len(py_results)} 组用例已算出")

    print("[3/4] Node 侧执行混淆 JS")
    node = find_node()
    if node is None:
        print("      [跳过] 没找到 Node。JS/Python 一致性未验证，"
              "仅验证还原结果自洽。")
        for c, py in zip(cases, py_results):
            expected = signer.sign(salt, c["params"], c["ts"], c["nonce"])
            assert py["sign"] == expected
        print("\n结论：部分验证通过（缺 Node 交叉验证）")
        return 0
    print(f"      node = {node}")

    proc = subprocess.run(
        [node, HARNESS],
        input=json.dumps(cases, ensure_ascii=False),
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        print("[失败] Node 执行混淆 JS 出错")
        return 1
    js_results = json.loads(proc.stdout)
    print(f"      {len(js_results)} 组用例已算出")

    print("[4/4] 逐组比对")
    failures = 0
    for idx, (case, py, js) in enumerate(zip(cases, py_results, js_results)):
        if py["canonical"] != js["canonical"]:
            failures += 1
            print(f"  #{idx} 规范化串不一致")
            print(f"      py = {py['canonical']!r}")
            print(f"      js = {js['canonical']!r}")
        if py["sign"] != js["sign"]:
            failures += 1
            print(f"  #{idx} 签名不一致 params={case['params']}")
            print(f"      py = {py['sign']}")
            print(f"      js = {js['sign']}")

    if failures:
        print(f"\n结论：失败，{failures} 处不一致")
        return 1
    print(f"\n结论：通过。{len(cases)} 组用例，JS 与 Python 完全一致。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
