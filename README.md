# sign-lab · 签名复算靶场

一个**自己写服务端、自己写混淆、自己还原**的接口签名靶场。
用来练习和展示「把混淆 JS 里的签名算法静态还原成纯 Python」这件事。

> **合规声明（先看这段）**
> 本仓库的目标服务器是**作者自己写的本地合成服务**，数据是程序生成的假数据，
> **不对应任何真实网站、真实接口或真实数据**。项目里没有任何针对第三方的
> 绕过代码、真实凭据或真实抓取结果。所有网络请求都指向 `127.0.0.1`。

---

## 它想解决的问题

大部分逆向练习项目只能做到「跑通一次」：要挂着可见浏览器、要 Node 参与、
cookie 有龄期、限流一到就崩、中断了得从头再来。招聘方要的是**能长期跑**的东西。

这个靶场就是按「能长期跑」的标准建的，三条硬指标：

| 目标 | 这里的做法 |
|---|---|
| 不依赖 JS 运行时 | 签名算法被静态还原成纯 Python，不用 Node、不用 execjs，主流程零第三方依赖 |
| 不会被限流打死 | 客户端全局限速 + 429 原地退避（读服务端给的等待时长，而不是抛异常让框架连点） |
| 中断可续、重复可幂 | checkpoint 断点续跑，落盘按 id 去重，写盘 `fsync` 后才推进进度 |

---

## 快速开始

```bash
# 1) 起服务端（零依赖，只用 Python 标准库）
python server/app.py                      # 默认 127.0.0.1:8787

# 2) 跑采集：拉混淆 JS → 还原盐 → 纯 Python 复算签名 → 带限速采集
python client/collect.py --pages 7 --size 20

# 3) 跑测试
python tests/parity_check.py              # JS 与 Python 两侧签名逐组比对
python tests/e2e_test.py                  # 自己拉起服务端，验校验与限流行为
```

采集结果落在 `data/items.jsonl`，审计报告落在 `data/collect_report.json`。

> **限流与退避原语已抽成独立库：** [ratelimit-kit](https://github.com/zxyin-dev/ratelimit-kit)。
> 本项目与另一个采集项目（gdzy-collector）现在共用同一份实现 —— 修一处两边都受益。
> 安装：`pip install git+https://github.com/zxyin-dev/ratelimit-kit`；
> 仓库里保留了一个"兄弟目录回退"（`client/_bootstrap.py`），方便本地同期开发。

---

## 目录结构

```
sign-lab/
├── server/
│   ├── app.py                 签名校验 + 令牌桶限流 + 429 提示（标准库手写）
│   ├── secret.py              服务端机密（盐、限流参数）
│   ├── signer.obf.js          下发给客户端的混淆签名脚本
│   └── tools/
│       └── gen_signer_js.py   生成上面那份混淆脚本（靶场自用，可复现）
├── client/
│   ├── recover.py             从混淆 JS 静态还原盐（不执行任何 JS）
│   ├── signer.py              纯 Python 签名实现
│   ├── ratelimit.py           令牌桶 + 429 退避解析 + 指数退避
│   └── collect.py             端到端采集（限速/续跑/去重/报告）
├── tests/
│   ├── parity_check.py        混淆 JS 执行结果 vs Python 复算结果
│   ├── js_parity.js           Node 侧签名执行器（给上面做交叉验证）
│   └── e2e_test.py            端到端行为自测（26 项断言）
└── docs/
    └── 设计说明.md             设计取舍、威胁模型、可讲的技术点
```

---

## 靶场设计

### 签名规则

```
sign = sha256( nonce + 盐 + 规范化查询串 + 毫秒时间戳 )
```

* `nonce`：一次性随机串，服务端验签通过后才登记，重复使用会被判重放
* `盐`：**不写在明文里**，编码进混淆 JS 的字符串表（就是本靶场要还原的东西）
* `规范化查询串`：参数名升序 → 拼 `k=v` → 用 `&` 连接
* 时间戳：与服务端偏差不得超过 ±5 分钟

请求头：`X-Nonce` / `X-Ts` / `X-Sign`。

### 混淆的四层

`server/signer.obf.js` 里，盐被这样藏起来：

```js
var _0xR = [                       // 层1：盐散在一张 80 字符的表里
  0x4b, 0x53, 0x6d, 0x66, ...
];
var _0xT = (function () {          // 层2：表内容是异或编码的数字，
  var _m = (0x2 ^ 0x3e), a = [], i;//       运行期才 fromCharCode(code ^ mask) 还原
  for (i = 0; i < _0xR.length; i++) { a.push(String.fromCharCode(_0xR[i] ^ _m)); }
  return a;
})();
var _0xI = [                       // 层3：下标写成常量折叠表达式
  (0x100 >> 5),                    //       (0x100 >> 5) 就是 8
  (0xe0 >> 3),  ...
];
function _0xk() {                  // 层4：掩码本身也是表达式 (0x2 ^ 0x3e) = 60
  var s = '', i;
  for (i = 0; i < _0xI.length; i++) { s += _0xT[_0xI[i]]; }
  return s;
}
```

### 还原思路

`client/recover.py` 全程**不执行 JS**，纯静态分析：

1. **定位取值模式**：正则找 `表[下标表[i]]` —— 这一步把两个数组配成一对，
   不靠变量名叫什么，所以混淆器改名也不影响。
2. **判断表的形态**：
   * 形态 A：明文单字符数组，直接用 Python 的字面量规则解析
     （JS 的 `'\x6a'` 转义与 Python 完全一致）；
   * 形态 B：异或码表 —— 再找 `String.fromCharCode(码表[i] ^ 掩码)`，
     把码表挖出来，掩码若是变量就回溯它的赋值表达式。
3. **下标表求值**：用 **AST 白名单**求值，只放行整数常量与 `+ - * | ^ & << >>`，
   函数调用、属性访问、名字引用一律拒绝 —— 比 `eval` 安全得多。
4. 按顺序取值拼出盐。

> 两个真实存在的坑，代码里都注释了原因：`var _m = ..., a = [], i;` 一条声明带多变量，
> 取值不能跨逗号；`var _0xT = (function () { var _m = ...` 值里嵌了新声明，
> 正则不能把内层整个吞掉，否则内层变量就再也找不到了。

### 服务端行为（刻意做成真实服务端的样子）

| 场景 | 响应 |
|---|---|
| 缺 `X-Nonce` / `X-Ts` | `400` |
| 签名错 / 时间戳过期 / nonce 重放 | `401`，**正文回带规范化串**（方便两侧对齐排错） |
| `size` 超过上限 50 | `200`，条数截断到 50，并回带 `size_capped: true` |
| 触发限流 | `429`，正文写「请在 N 秒后重试」，同时给 `Retry-After` 头 |

限流是**按客户端 IP 的令牌桶**：容量 3，之后每 2 秒恢复 1 个令牌。
客户端默认按 2.2 秒/次全局限速（比服务端更保守），所以正常采集不会撞 429；
把 `--min-interval` 调小就能人为压出 429，观察原地退避是否工作。

---

## 测试

```
$ python tests/parity_check.py
      字符串表形态：异或码表
      掩码 0x3c
      _0xR[80] -> 下标 [8, 28, 20, 42, 21, 53, 65, 6] (_0xI)
      还原出的盐：'s1gnlab7'（8 字符）
      形态 A（明文单字符表）容错分支：通过
      ...
结论：通过。24 组用例，JS 与 Python 完全一致。
```

* `parity_check.py`：24 组用例（含中文参数、空值、键顺序颠倒）在 Node 与 Python
  两侧分别算签名，逐组比对 —— 复算路线能不能信的底线。
* `e2e_test.py`：26 项断言，覆盖存活、无签名、错签名、规范化、截断、时间戳过期、
  nonce 重放、429 触发与恢复、限流状态表回收。

实测采集：7 页 × 20 条 = **137 条全部落盘，0 次 429，0 次 401，id 无重复**。

---

## 已知限制

* 靶场只有 HTTP GET 一种取证形态，没有 POST body 签名、没有 cookie 态、没有验证码环节；
* 盐是单段固定串，真实目标常有「时间片轮转 / 多段拼接 / 与设备指纹绑定」的变体；
* 限流是按 IP 的简单令牌桶，真实风控通常叠加设备指纹与行为特征；
* 混淆只有四层，真实目标会用 JSVMP 把控制流也打散。

这些是**后续要补的靶场关卡**，不是「本项目做不到」的辩解。

---

## English summary

**sign-lab** is a self-contained playground for reversing API request signatures.
The protected server is written by the author, runs on `127.0.0.1`, and serves
synthetic data only — there is no third-party target, credential, or scraped
result anywhere in this repository.

It demonstrates three things:

1. **Static recovery** — the signing salt is hidden behind four obfuscation
   layers (string table, XOR-encoded codes, constant-folded indices, expression
   mask). `client/recover.py` recovers it by pure static analysis with no JS
   engine, using an AST allowlist instead of `eval`.
2. **Pure-Python recomputation** — the signature is reimplemented in Python and
   cross-checked against the obfuscated JS on 24 cases (including non-ASCII
   parameters).
3. **Long-running engineering** — global rate limiting, in-place 429 backoff
   driven by the server's own hint, resumable checkpoints, and idempotent writes.

Zero third-party dependencies: Python standard library only.

---

## 授权

本项目为个人练习作品。靶场服务端与客户端均为原创，数据为程序生成。
