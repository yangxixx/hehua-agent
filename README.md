# Hehua

自主渗透 agent。在**授权靶场 / SRC 范围**内自动完成 侦察 → 枚举 → 利用 → 拿 flag 的全流程：
LLM 工具循环驱动解题，外置的确定性编排层负责调度、容器生命周期、预算控制与断点续跑。

## 工作方式

- **解题体**：LLM 通过 bash / http / 文件读写 / grep / notes / submit 等工具自主攻击目标；
  规则看门狗检测重复命令和无进展，预算耗尽强制收尾。
- **编排层**：按期望价值排序目标，管理靶标容器（上限驱逐、孤儿清扫、必关），原子写状态、
  支持断点续跑（kill 后 resume 跳过已解、不重算）。
- **混合模型分层**：廉价快模型负责广覆盖，强模型仅在快模型攻不下的硬题上按需升级，
  实测升级模型 token 占比仅个位数百分点。
- **三模式**：
  - `normal`：N 个 worker 并发，各打一个目标；扫完后渐进切到强模型清理残部。
  - `deep`：同一目标派多个 agent 并行，各走不同攻击面、共享笔记、谁先拿到 flag 谁停。
  - `auto`（默认）：先 normal 广扫吃下易题，再对硬残部自动切 deep。
- **跨轮知识库**：每解出一题落盘「配方」，下一轮同类目标开局直接注入已验证打法，越跑越熟。

## 安装

需要 Python ≥ 3.10。

```bash
python -m uv venv --python 3.12 .venv          # 或任意 py>=3.10 venv
.venv/Scripts/python -m pip install -e .        # Linux: .venv/bin/python
# 会安装依赖：靶场平台 SDK、httpx
```

## 用法

### 三种运行模式

| 模式 | 用途 | 依赖 |
|---|---|---|
| `mock` | 离线全链路冒烟（内置假平台 + 脚本化假 LLM，含两个真漏洞靶） | 无 |
| `local` | 本地经 VPN 直连靶场，可用强模型升级与深度模式 | 平台凭证 + VPN |
| `hosted` | 托管沙箱（镜像 entrypoint 自动配置网关） | docker 镜像 |

### 命令

```bash
# 离线冒烟（无网无 key，验证整条链路：调度→起容器→工具循环→提交→关容器→报告）
python -m hehua smoke

# 真实跑分（local：本地 VPN 内）
python -m hehua run --mode local

# 托管模式（镜像内，沙箱自动置 MODEL_GATEWAY=1）
python -m hehua run --mode hosted

# 断点续跑（进程被杀后接着跑）
python -m hehua resume

# 重新生成报告
python -m hehua report
```

### 跨轮学习

跑完一轮后用学习脚本把解题经验提炼成先验包，烘进镜像即可让下一轮开局自带：

```bash
python scripts/learn.py out          # 读取 out/ 与 state/，生成 learned/ 三件套
# learned/ 烘进镜像后，下一轮启动自动种子知识库 + 用实测先验重排调度
```

## 配置（环境变量）

拷贝 `.env.example` 为 `.env` 填入：

| 变量 | 说明 |
|---|---|
| `BENCHMARK_TOKEN` / `BENCHMARK_BASE_URL` | 靶场平台凭证（local 必填；hosted 由平台注入） |
| `DEEPSEEK_API_KEY` / `LLM_PROVIDER` | 主模型（deepseek 默认；也支持 qwen / glm / kimi，均 OpenAI 兼容） |
| `GLM_API_KEY` / `GLM_MODEL` | 设上后启用强模型升级分流（仅 local；走智谱 Anthropic 端点） |
| `HEHUA_MODE` | `local` / `hosted` / `mock` |
| `HEHUA_POOL` | 并发靶标容器数（平台通常限 3） |
| `HEHUA_PEERS` | 深度模式每目标的并行 agent 数（默认 2） |
| `HEHUA_DEEP` | `auto` / `normal` / `deep` |
| `HEHUA_MAX_ATTEMPTS` | 单目标最大尝试数（默认 3 = 1 次快扫 + 2 次升级） |
| `MODEL_GATEWAY` | `1` = 沙箱网关改写（hosted 自动置） |
| `TOTAL_BUDGET_MIN` | 总预算分钟数（默认 360） |

## 目录结构

```
hehua/      主体：config / llm(client+anthropic_client+budget) / core
                  (agent+tools+sandbox+context+memory+knowledge)
                  / orchestrate(runner+scheduler+lifecycle+state)
                  / prompts(系统 + 各维度 playbook) / metrics / cli
scripts/    运行时工具：scan / crawl / dirfuzz / paramgen / calibrate
                  / monitor / seed_knowledge / learn
mock/       离线冒烟用的假平台（含 sqli、命令注入两个真靶）+ 脚本化假 LLM
docker/     Dockerfile + overlay + entrypoint + 容器内 prompt
learned/    learn.py 产出的跨轮先验包（自生成，不入库）
```

## 合规

**仅在授权靶场 / SRC 范围内运行。** 密钥全部走环境变量；全程事件日志可审计。
本仓库不含任何真实凭证或非授权目标数据。

## License

MIT
