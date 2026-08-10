# 荷花 Hehua — 自主渗透 Agent（Tsecbench / BSRC "Agent+" 攻防挑战赛）

一个自主解题的进攻型 AI Agent：**确定性编排层**（EV 调度 / 容器生命周期 / 断点续跑 /
预算外置 / 跨题知识库）+ **LLM tool-use 解题体**（bash/http/notes/submit 等工具 +
规则化看门狗 + 六维 playbook），用公开评测先验校准，支持 flash 广覆盖 + GLM-5.2 强模型
精准升级的**混合分层**架构。

## 战绩

- **托管官方认证 run（v2，deepseek-v4-flash）：70.02/100**（16320/23000，52/74 flags，
  3h52m）—— 超过托管榜 deepseek-v4-pro 头部解（66.13），且 token 量约其 1/3.6、
  flash 单价≈pro 的 1/10 ⇒ 单轮成本约 1/30，分反超。
- 本地优化轮：**c 利用 8/9**（从认证 run 的 4/9）、a Web 17、f 二进制 10；GLM-5.2 实战
  解出 flash 攻不下的 a-16/a-18/f1-04/f2-06/f2-07 等。

## 架构

```
编排层 (确定性, 不信任模型自述)                 解题体 (LLM tool-use 循环)
 EV 调度: 先验×分值÷限时 · 覆盖优先           10 工具: bash/port_scan/http/读写/grep
 优先级自校准 (learn.py 闭环回灌 priors)            /notes/submit_flag/finish
 lifecycle: 容器上限驱逐/孤儿清扫/必 close     8 维 playbook: Web/多阶段/利用/云/规避/
 state: 断点续跑 · 原子写 · resume 不重算            二进制/AI漏洞/区块链
 预算外置: 分级限时 · 自适应全局重分配          规则看门狗: 重复/无进展/预算注入
 三模式: normal / deep / auto                  验证闭环: submit→平台 correct 为唯一真值
```

### 三种运行模式（`HEHUA_DEEP`）
- **normal**：`HEHUA_POOL` 个并发容器，每槽 flash 扫完渐进切 GLM 清理（1 agent/题）。
- **deep**：每题 `HEHUA_PEERS` 个 peer（默认 2）共用靶标、分方向、共享 notes、首解即停
  —— 2 peer × 3 容器 = 6 agent 压满平台 3 容器上限，对标榜首多路并发。
- **auto（默认）**：flash 扫完 → 硬残部自动切深度（GLM）。兼顾便宜广覆盖与硬题深攻。

### 关键能力
- **混合分层升级**：flash 兜广度（省 token），仅硬残部按需升级 GLM-5.2（实测 token 占比 ~2%）。
- **GLM-5.2 走 Anthropic 端点**（`AnthropicGLMClient`）：内部 OpenAI↔Anthropic 翻译；
  余额耗尽自动熔断退纯 flash。
- **跨题配方知识库**（`hehua/core/knowledge.py`）：解出题落盘配方，同族新题开局注入"已验证打法"。
- **自动学习闭环**（`scripts/learn.py`）：跑完生成 `learned/{knowledge,priors,deadends}`，
  烘进镜像后下轮开局自动种子 KB + 用实测先验重排调度——越跑越准。
- **进程组级执行器**（`killpg`）：bash 子进程超时杀整个进程组，根治失控脚本卡死。
- 智能重试：死路注入、有进展微重试、0 进展统计止损、智能 hint、finish 前自检收割。

## 快速开始

```bash
python -m uv venv --python 3.12 .venv
.venv/Scripts/python -m pip install -e .[dev]   # linux: .venv/bin/python
cp .env.example .env                            # 填凭证
.venv/Scripts/python -m hehua smoke            # 离线全链路冒烟（无网无 key）
.venv/Scripts/python -m hehua run --mode local  # VPN 内真实跑分
```

## 模式

| 模式 | 用途 | 依赖 |
|---|---|---|
| mock | 离线回归（假平台 + 脚本化假 LLM，含两个真漏洞靶） | 无 |
| local | 本地经 VPN 直连靶场；可启 flash + GLM 升级 + 深度模式 | `BENCHMARK_TOKEN`/`BASE_URL` + VPN |
| hosted | 托管沙箱（entrypoint 自动 `MODEL_GATEWAY=1`） | docker 镜像 + 白名单 LLM |

## 配置要点

- `LLM_PROVIDER`: deepseek(默认)/qwen/glm/kimi —— 均 OpenAI 兼容
- `GLM_API_KEY` + `GLM_MODEL=glm-5.2`：启用 GLM-5.2 升级（仅 local；走智谱 Anthropic 端点）
- `HEHUA_POOL`(并发容器，默认 3) / `HEHUA_PEERS`(深度 peer，默认 2) / `HEHUA_DEEP`(auto|normal|deep)
- `HEHUA_MAX_ATTEMPTS`(默认 3 = 1 flash + 2 升级)
- `learned/`：`scripts/learn.py` 产出的先验包，烘进镜像后自动种子（`HEHUA_KB_SEED`）

## 目录

```
hehua/     config|gateway|llm(client/anthropic_client/budget/registry)
          core(agent/tools/sandbox/context/memory/knowledge) orchestrate(runner/scheduler/lifecycle/state)
          prompts(system + 8 维 playbook) metrics|cli
scripts/  scan/crawl/dirfuzz/paramgen/calibrate/monitor/seed_knowledge/learn
mock/     假平台(sqli+cmdi 真靶) + 脚本化假 LLM
docker/   Dockerfile + Dockerfile.overlay + entrypoint.sh + system.container.md
tests/    71 个（pytest 全绿）
docs/     设计方案/实施计划/榜单情报/复盘/postmortem
learned/  learn.py 产出的跨轮先验包（knowledge/priors/deadends）
```

## 合规

仅在**授权靶场 / SRC 范围**内运行；密钥全部走环境变量；全程事件日志可审计；案例脱敏。
本仓库不含任何真实凭证或非授权目标数据。
