// sign-lab JS/Node 侧签名执行器：给 Python 侧做交叉验证用。
//
// 用法：node tests/js_parity.js [cases.json]
//   省略路径或传 "-" 时，从标准输入读 JSON（避免依赖临时目录）。
// 输出：JSON 数组，每项含 canonical 与 sign。
const fs = require('fs');
const path = require('path');

const obfPath = path.join(__dirname, '..', 'server', 'signer.obf.js');
const source = fs.readFileSync(obfPath, 'utf8');
eval(source); // IIFE 会把 __signer 挂到 globalThis

function readInput() {
  const arg = process.argv[2];
  if (!arg || arg === '-') {
    return fs.readFileSync(0, 'utf8');
  }
  return fs.readFileSync(arg, 'utf8');
}

const cases = JSON.parse(readInput());
const results = cases.map(function (c) {
  return {
    ts: c.ts,
    nonce: c.nonce,
    params: c.params,
    canonical: globalThis.__signer.canonical(c.params),
    sign: globalThis.__signer.sign(c.params, c.ts, c.nonce),
  };
});
process.stdout.write(JSON.stringify(results));
