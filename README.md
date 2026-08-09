# 荷花（Hehua）— 自主渗透 Agent（Tsecbench / BSRC "Agent+" 参赛作品）

自主解题的进攻型 AI Agent：确定性编排层（EV 调度/容器生命周期/断点续跑/预算外置）
+ LLM tool-use 解题体（bash/http/notes/submit 九工具 + 规则化看门狗），
六维 playbook（Web/多阶段/利用/云/规避/二进制）由公开评测先验校准。
支持 **2 flash + 1 GLM 混合升级**：flash 两攻不下的题自动交给更强的 GLM-5.2 专攻（仅 local）。

## 快速开始

```bash
python -m uv venv --python 3.12 .venv          # 或任意 py>=3.10 venv
.venv/Scripts/python -m pip install -e .[dev]  # linux: .venv/bin/python
cp .env.example .env                           # 填凭证
.venv/Scripts/python -m hehua smoke           # 离线全链路冒烟（无网无key）
.venv/Scripts/python -m hehua run --mode local   # VPN 内真实跑分
```

## 模式

| 模式 | 用途 | 依赖 |
|---|---|---|
| mock | 离线回归（假平台+假LLM，含两个真漏洞靶） | 无 |
| local | 本地经 VPN 直连靶场容器；可启 GLM 升级分流 | BENCHMARK_TOKEN/BASE_URL + VPN |
| hosted | 托管沙箱（entrypoint 自动置 MODEL_GATEWAY=1） | docker 镜像 + 白名单 LLM |

## 混合模型升级（local 模式）

设 `GLM_API_KEY` 且 `HEHUA_POOL=3` 后，runner 起 **2 个 flash worker + 1 个
GLM-5.2 升级 worker**：flash 两轮（R1+R2）攻不下的题自动入升级队列交 GLM 专攻，
flash 与 GLM 共享 token 预算记账。GLM 走智谱 OpenAI 兼容端点
`https://open.bigmodel.cn/api/paas/v4`（模型 `glm-5.2`）。托管沙箱无公网、该端点
不可达，故 hosted 模式自动禁用升级。

## 配置要点

- `LLM_PROVIDER`: deepseek(默认)/qwen/glm/kimi —— 均 OpenAI 兼容且在 Tsecbench 白名单
- `GLM_API_KEY`: 设置后启用 GLM-5.2 升级分流（仅 local 生效）
- 托管模式 LLM URL 自动改写 `http://<host>.tsecbench.gw<path>`
- `HEHUA_POOL`: 并发 worker 数（默认 2，平台容器上限 3；升级分流建议 3）
- `priors.json`: `python scripts/calibrate.py` 用自有跑分数据自校准先验

## 目录

```
hehua/   config|gateway|llm|orchestrate|core|prompts|metrics|cli
mock/     假平台(sqli+cmdi 真靶) + 脚本化假LLM
scripts/  scan.py(端口扫) crawl.py(爬虫) dirfuzz.py(线程化目录爆破)
          paramgen.py(复合参数名字典) calibrate.py(先验自校准) monitor.py(跑分监控)
docker/   Dockerfile(<=3GB 全烘焙) + entrypoint.sh
submit/   BSRC 作品材料（技术方案/writeups/视频脚本）
docs/     设计方案/实施计划/榜单情报/复盘/postmortem/HANDOFF
```

## 战绩

- **托管官方认证（run 6661，v2，deepseek-v4-flash）**：70.02/100（16320/23000，
  52/74 flags，3h52m）——超榜一 ez-claude(pro) 66.13。
- **XBOW 本地（v3 两轮，flash）**：38/104、8000 分（easy 34 + medium 4），精度 97%。
- round-0 彩排：11250/23000（48.9%），35/74 flags。复盘见 docs/postmortem-*.md。

## 合规

仅在授权靶场/SRC 范围运行；密钥走环境变量；全程事件日志可审计。
