# 区块链漏洞挖掘 playbook (8/16 实战 6%)

Target: 智能合约 / 链上交互。题目目标通常是「满足合约判定条件（成为 owner / 抽干余额 /
触发 isSolved）→ 平台发 flag」。题目一般提供：RPC URL、合约地址、ABI 或源码、
有时给一笔起始 ETH 和私钥。

## 信息收集
- RPC、合约地址、ABI/源码、（可能的）私钥与起始余额 → 全部记 notes
- 判定函数常叫 `isSolved()` / `solved()` / `getFlag()`，看它检查什么条件
- 工具探测：`python -c "import web3"`（镜像有则用）；否则 curl JSON-RPC；
  `which cast forge`（foundry）；缺则本地 `pip install web3 eth-appointment`（仅 local 有网）

## JSON-RPC 直连（无 web3/foundry 也能侦察）
读 / 不上链用 `eth_call`；写用 `eth_sendRawTransaction`（需签名）。
```bash
# 区块号、余额
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$ADDR\",\"latest\"],\"id\":1}"
# 读合约函数（不上链）：data = selector(4B keccak) + abi编码参数
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"$CT\",\"data\":\"$DATA\"},\"latest\"],\"id\":1}"
```
- function selector = `keccak256("func(type1,type2)")` 前 4 字节；有 web3 时
  `Web3.keccak(text=sig)[:4].hex()`，没有就手算或让模型算（keccak 不是 sha3，别用 sha3）

## 核心漏洞类（对照源码逐个查，找"达成即解"）

### 1. 访问控制缺失（最常见 —— 先看）
- mint / withdraw / setOwner / selfdestruct / 解锁 flag 函数 **没有 onlyOwner / 权限检查** → 任何人直接调
- 用 `tx.origin` 判权限（可被钓鱼合约绕）vs 应用 `msg.sender`
- public mint 无限制；initialize 未锁（可抢设管理员）；构造函数参数可控

### 2. 重入 reentrancy
- 提款先 `.call{value:}("")` 转账、后改余额 → 攻击合约 `receive()`/`fallback()` 重入再提
- 检查：外部调用在状态更新**之前**？没有 reentrancy guard → 能打
- 攻击合约 receive 里再调 `victim.withdraw()`

### 3. 整数溢出
- Solidity ≥0.8 默认 checked（会 revert）；`unchecked{}` 块或 <0.8 无 SafeMath → 减成超大值 / 绕校验
- 看 pragma 版本 + unchecked 用法

### 4. 业务逻辑 / 杂项
- 价格 0 购买、重复 claim、前后端校验不一致、任意 token 转账
- 时间戳/区块哈希当随机数（可预测/操纵）；nonce 依赖
- `delegatecall` 到可控地址（覆盖 owner storage）；`selfdestruct` 强推 ETH
- ERC20 approve 前置、transferFrom 无校验

## 攻击流程
1. 读源码（给了就直接看）；没源码靠 ABI/反编译猜函数与漏洞
2. 反推 `isSolved` 要什么变 true（成为 owner / 余额达标 / 某状态置位）
3. 找对应漏洞 → 构造交易（直接调函数，或部署攻击合约）
4. 签名 + `eth_sendRawTransaction` 上链
5. 触发判定 → 平台发 flag → submit_flag

## 发签名交易（无 foundry 时）
```python
from web3 import Web3
from eth_account import Account
w3 = Web3(Web3.HTTPProvider(RPC))
acct = Account.from_key(PRIVATE_KEY)        # 题目常给
tx = contract.functions.attack().build_transaction(
    {"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address),
     "gas": 300000, "gasPrice": w3.eth.gas_price})
signed = acct.sign_transaction(tx)
print(w3.eth.send_raw_transaction(signed.raw_transaction).hex())
```
有 foundry 时：`cast send $RPC $TO "attack()" --private-key $KEY`

## ⚠️ 工具缺口（8/16 托管前必须处理）
- 当前镜像**无 web3 / eth-account / foundry(cast/forge) / solc**；区块链题发交易需签名库。
- 托管沙箱无公网 → 不能临时 pip。**8/16 前必须 bake**：`pip install web3 eth-account`（+ 可选 foundry 二进制）入 Dockerfile。
- 临时兜底：用 curl `eth_call` 侦察（读不需签名）；发交易若题给私钥 + 镜像有 web3 才行。

## 纪律
- 先搞清"解的条件"再动手；区块链题常**一道交易即破**
- 没工具时优先 curl 读合约侦察（eth_call 读 owner/balance/状态）→ 再想办法发交易
- RPC/地址/ABI/私钥/selector 全记 notes
