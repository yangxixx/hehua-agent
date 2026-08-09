# XBOW 本地跑分复盘（2026-08-09，hehua v3，flash 两轮）

**终局：38/104 通关，8000 分**（easy 34×200 + medium 4×300），提交精度 97%（38/39）。
任务因平台 `invalid_state "already finished"` 结束（总时限到），非异常。

## 过程
- VPN 预检通过 → 换新 token（旧练习 token 终局）→ 本地模式 3 并发，两轮全覆盖 104 题。
- easy 批高效（多数 <2min）；medium 批放缓，hard 未解。
- 末尾 3 容器（xben-017/023/025）平台侧 close 持续 503，任务结束后随任务一并释放。

## 边跑边调优（实时生效项）
1. **调度**：未知前缀按难度预算排序 → easy 优先（原版先打 hard）；非平台前缀
   无条件二次重试；平台 502 启动失败不烧尝试次数；"成功启动后才计 attempts"。
2. **playbook**：Apache 2.4.49/50 双重编码穿越/RCE 配方（并修正为 canonical payload：
   `/cgi-bin/%%32%65%%32%65` 不带点、`/icons/.%%32%65` 带点）；Werkzeug/Flask；复合参数名；
   OOB 外带；flag 完整提取。
3. **本地工具补强**：词表 common.txt/big.txt + 线程化 `dirfuzz.py`——根治"大词表逐个
   curl 烧穿预算"（xben-001 教训：18.8 万词顺序扫）。

## 结论
- 38 题里 easy 占 34：flash 对 XBOW easy 命中率高；medium/hard 是能力墙，需更强模型。
- 直接催生 **2 flash + 1 GLM 升级分流**（已实现，见 HANDOFF）：flash 两轮攻不下的题
  自动交 GLM-5.2 专攻，预期回收 medium/hard 残局。
- 平台 close 偶发 503/挂起：lifecycle 已容错（start 失败不烧次数），任务终态容器随任务释放。
