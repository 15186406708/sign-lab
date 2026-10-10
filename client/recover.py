#!/usr/bin/env python3
"""从混淆 JS 里静态还原签名盐 —— 全程不执行任何 JS。

为什么不用 Node/execjs 直接调：
  1. 真实目标的 SDK 往往有反调试、环境检测、异步初始化，抠出来跑通成本远高于复算；
  2. 复算能做到「长期稳定」：没有 Node 版本漂移、没有会话态、没有进程常驻；
  3. 面试里能讲清楚「我把它算出来了」，比「我把 JS 跑起来了」值钱。

还原四步（对应 signer.obf.js 里的四层混淆）：
  1. 定位「盐是怎么拼出来的」—— 即 `表[下标表[i]]` 这个取值模式；
  2. 判断字符串表是哪种形态：
       A. 明文单字符数组（'\\x6a', ...），直接用 Python 字面量规则解析；
       B. **异或编码的数字码表** —— 表在运行期才用 `String.fromCharCode(code ^ mask)`
          现算出来，所以要额外把码表和掩码都从源码里挖出来（掩码自身还是表达式）。
  3. 取出下标表：每一项是被常量折叠过的表达式（如 `(0x10 >> 1)`），
     用 AST 白名单求值 —— 只允许整数与位运算，杜绝 eval 任意代码；
  4. 按顺序取值拼出盐。

为什么不用 Node/execjs 直接调：
  1. 真实目标的 SDK 往往有反调试、环境检测、异步初始化，抠出来跑通成本远高于复算；
  2. 复算能做到「长期稳定」：没有 Node 版本漂移、没有会话态、没有进程常驻；
  3. 面试里能讲清楚「我把它算出来了」，比「我把 JS 跑起来了」值钱。
"""

from __future__ import annotations

import ast
import json
import operator
import re
import urllib.request
from typing import Any

__all__ = [
    "recover_salt",
    "load_salt_from_js",
    "load_salt_from_url",
    "safe_int_eval",
]

# 数组赋值：var _0xT = [ ... ];
_ARRAY_ASSIGN_RE = re.compile(
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[(.*?)\]\s*;",
    re.S,
)

# 取值模式：_0xT[_0xI[i]] —— 用它把「字符串表」和「下标表」配成一对
_PAIR_RE = re.compile(
    r"([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$]*)\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*\]"
)

# 解码模式：String.fromCharCode(_0xR[i] ^ _0xM)
# 说明表不是明文数组，而是「原始码表 + 掩码」在运行期现算出来的
_DECODER_RE = re.compile(
    r"String\s*\.\s*fromCharCode\s*\(\s*([A-Za-z_$][\w$]*)\s*\[\s*[A-Za-z_$][\w$]*\s*\]"
    r"\s*\^\s*([^)\]]+?)\s*\)"
)

# 变量赋值（用来把掩码变量名解析回它的表达式）
# 两个坑都要绕开：
#   1. `var _m = (0x2 ^ 0x3e), a = [], i;` —— 一条声明带多个变量，值不能跨逗号；
#   2. `var _0xT = (function () { var _m = ...` —— 值里嵌了新的声明，
#      不能让外层把内层整个吞掉，否则内层变量就找不到了。
_VAR_EXPR_RE = re.compile(
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"((?:(?!\b(?:var|let|const)\b)[^;,])+)"
)

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}


class RecoverError(RuntimeError):
    """静态还原失败：JS 结构与预期不符。"""


def safe_int_eval(expr: str) -> int:
    """对常量折叠表达式求值，只允许整数常量与算术/位运算。

    比 `eval` 更安全：任何函数调用、属性访问、名字引用、比较、下标都会被拒绝。
    """
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError as exc:
        raise RecoverError(f"表达式无法解析: {expr!r}") from exc

    def walk(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bool) or not isinstance(value, int):
                raise RecoverError(f"只允许整数常量，遇到 {value!r}")
            return value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -walk(node.operand)
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            return _BINOPS[type(node.op)](walk(node.left), walk(node.right))
        raise RecoverError(f"表达式里出现了不允许的语法: {type(node).__name__}")

    return walk(tree)


def _split_top_level(body: str) -> list[str]:
    """按顶层逗号切分数组内容（忽略括号内部的逗号）。"""
    parts, depth, buf = [], 0, []
    for ch in body:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf)
    if tail.strip():
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def _parse_string_table(body: str) -> list[str]:
    """把 '\\x6a', '\\x31', ... 解析成字符列表。

    这里能直接用 Python 的字面量规则：JS 的 '\\xNN' 转义与 Python 完全一致。
    """
    literal = "[" + body.rstrip().rstrip(",") + "]"
    try:
        value = ast.literal_eval(literal)
    except (SyntaxError, ValueError) as exc:
        raise RecoverError("字符串表不是可识别的字符字面量数组") from exc
    if not isinstance(value, list) or not all(
        isinstance(item, str) and len(item) == 1 for item in value
    ):
        raise RecoverError("字符串表里出现了非单字符元素")
    return value


def _parse_index_table(body: str) -> list[int]:
    return [safe_int_eval(part) for part in _split_top_level(body)]


def _parse_number_table(body: str) -> list[int]:
    """把 0x5b, 0x4c, ... 解析成整数列表（异或编码后的原始码表）。"""
    values = [safe_int_eval(part) for part in _split_top_level(body)]
    if not values:
        raise RecoverError("码表是空的")
    return values


def _resolve_mask(expr: str, assignments: dict[str, str]) -> int:
    """解析掩码：本身可能是字面量表达式，也可能是个变量名。"""
    text = expr.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", text):
        if text not in assignments:
            raise RecoverError(f"掩码变量 {text} 没有找到赋值")
        text = assignments[text].strip()
    return safe_int_eval(text)


def load_salt_from_js(source: str) -> tuple[str, dict[str, Any]]:
    """从混淆 JS 源码还原盐。

    返回 (salt, 还原过程详情)。详情用于自证与排错，也是测试断言的抓手。
    """
    pair = _PAIR_RE.search(source)
    if pair is None:
        raise RecoverError("没找到 `表[下标表[i]]` 这种取值模式，无法定位盐的来源")
    table_name, index_name = pair.group(1), pair.group(2)

    arrays = {name: body for name, body in _ARRAY_ASSIGN_RE.findall(source)}
    assignments = dict(_VAR_EXPR_RE.findall(source))

    if index_name not in arrays:
        raise RecoverError(f"找不到下标表 {index_name}")

    # --- 还原字符串表：两种形态 ---------------------------------------------
    if table_name in arrays:
        # 形态 A：直接就是字符字面量数组
        table = _parse_string_table(arrays[table_name])
        table_kind = "literal"
        mask = None
    else:
        # 形态 B：码表 + 掩码，运行期用 fromCharCode(code ^ mask) 现算
        decoder = _DECODER_RE.search(source)
        if decoder is None:
            raise RecoverError(
                f"{table_name} 不是字面量数组，也没找到 fromCharCode(... ^ ...) 解码逻辑")
        raw_name, mask_expr = decoder.group(1), decoder.group(2)
        if raw_name not in arrays:
            raise RecoverError(f"解码逻辑引用的码表 {raw_name} 没找到")
        mask = _resolve_mask(mask_expr, assignments)
        codes = _parse_number_table(arrays[raw_name])
        if not 0 <= mask <= 0xFF:
            raise RecoverError(f"掩码 {mask} 超出单字节范围，解码结果不可信")
        table = [chr(code ^ mask) for code in codes]
        table_kind = "xor"
        table_name = raw_name

    index = _parse_index_table(arrays[index_name])

    try:
        salt = "".join(table[i] for i in index)
    except IndexError as exc:
        raise RecoverError("下标越界：下标表与字符串表长度不匹配") from exc
    if not salt:
        raise RecoverError("还原出来的盐是空串")

    detail = {
        "table_name": table_name,
        "index_name": index_name,
        "table_kind": table_kind,
        "table_length": len(table),
        "mask": mask,
        "index": index,
        "salt_length": len(salt),
    }
    return salt, detail


def recover_salt(source: str, *, debug: bool = False) -> str:
    """只要盐的简化入口。"""
    salt, detail = load_salt_from_js(source)
    if debug:
        print(json.dumps(detail, ensure_ascii=False))
    return salt


def load_salt_from_url(url: str, timeout: float = 10.0) -> str:
    """从服务端拉混淆 JS 并还原盐（模拟真实的「扣 JS」入口）。"""
    req = urllib.request.Request(url, headers={"User-Agent": "sign-lab/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        source = resp.read().decode(charset, errors="replace")
    return recover_salt(source)
