# Hehua 荷花

对话式**全链路自动化**渗透 Agent。在**授权靶场 / SRC 范围**内，支持任意数量、类型模型组合，一句自然语言指令——
——即可触发从侦察到报告的**全自动闭环**，全程无人干预：

> 意图理解 → 多模型并行攻击 → 自动侦察 → 漏洞验证与利用 → 数据提取/凭证/提权 → 中文实时进度 → 标准渗透测试报告

多模型并行（flash / pro / glm / qwen 多路 agent 同时开打，共享情报），实时流式输出每一次工具调用，
测完自动生成含完整 HTTP 数据包原文的标准报告。

> 本仓库只包含 agent 本体（对话式渗透 / 一次性渗透），不含任何测试或跑分框架。

## 核心特性

- **全链路闭环**：一句话指令 → 自动渗透 → 自动报告，端到端无人工步骤（真机实测：单目标 20 分钟
  挖出 32 类漏洞含 2 条 RCE 链与全库数据；6 分钟快测亦产出完整数据包报告）
- **对话式操作**：操作员 LLM 理解自然语言意图（渗透目标、调整侧重、追问结果），自动调度
- **多模型并行**（deep 模式）：`flash / pro / glm / qwen` 各派一个 coding agent 同时打同一目标，
  共享 NOTES.md 情报（stigmergy 协作），配置了哪些 key 就启用哪些模型
- **连续工具循环引擎**：think → bash / HTTP / 文件操作 → 观察循环往复，附看门狗
  （重复检测 / 无进展换向 / 预算强制收尾）与上下文滚动压缩，长程任务不崩
- **8 维领域 playbook**：Web / 多阶段内网 / 组件利用 / 二进制 / 云 / 对抗规避 / AI 应用 / 区块链，
  按目标特征自动注入，附 payload 语料库
- **中文实时进度**：每个动作带模型名流式输出（`[glm] bash: ...`、`★ [glm] 发现漏洞: ...`），
  每 45 秒一条进度汇总（已报告漏洞数 + 各模型当前在测什么）
- **标准渗透测试报告**：测完自动生成 `out/<目标>/report.md` —— 风险汇总矩阵、
  逐漏洞利用过程（含完整 HTTP 请求包原文、响应证据、影响、修复建议）

## 快速开始

```bash
git clone https://github.com/yangxixx/hehua-agent && cd hehua-agent
python -m venv .venv
.venv/Scripts/python -m pip install -e .      # Linux/macOS: .venv/bin/python
cp .env.example .env                          # 填入 LLM API key
```

## 用法

### 对话式（推荐）

```bash
python -m hehua
```

```
hehua> 深度渗透http://10.0.0.5          ← 说"深度/深入/多模型"即启用多模型并行（也可 HEHUA_DEEP=deep 常开）
[hehua] ▶ pentesting http://10.0.0.5  (budget 30min, models: flash, pro, glm, qwen)
   [flash] bash: {"command": "curl -s -i http://10.0.0.5/ | head -100"}
   [pro] http_request: {"url": "http://10.0.0.5/index.php"}
   ★ [glm] 发现漏洞: sql-injection:/vul/sqli_str.php?name=
   [qwen] bash: {"command": "python sqli_dump.py --tables"}
   ── 进度 [16:20:33] 已报告 1 个漏洞 ── flash: bash fuzz目录 | pro: http_request | glm: 报告漏洞 | qwen: sqli_dump
[hehua] ✔ done http://10.0.0.5: 3 finding(s)
   ★ sql-injection:/vul/sqli_str.php?name=
   ★ idor:/api/order/{id}
   ★ weak-password:/admin/login.php
[hehua] 📄 渗透测试报告已生成: out/http___10.0.0.5_/report.md

hehua> 重点测一下 API 越权
[带侧重指令重新渗透…]

hehua> 上次找到什么了？
助手> 共 3 个发现：… 完整报告(含数据包/利用过程): out/http___10.0.0.5_/report.md

hehua> exit
```

支持的目标格式：`URL` | `IP:端口` | 网段 `CIDR`。中文动词（渗透/攻击/测试/扫/打…）均可引导。

### 一次性命令（脚本 / 自动化）

```bash
python -m hehua pentest http://10.0.0.5 --budget 30
python -m hehua pentest 10.0.0.0/24 --budget 15 --deep          # 网段：先 nmap 测绘再逐目标
python -m hehua pentest http://10.0.0.5 --instruction "重点测越权和JWT"
```

## 全链路流程

```
"深度渗透http://target"
   │
   ├─ ① 意图理解      operator LLM 解析目标 / 侧重 / 预算 / 深度模式
   ├─ ② 多模型编成    flash+pro+glm+qwen 各起一个 coding agent（按 key 自动组建）
   ├─ ③ 自动侦察      全站爬虫 → 目录/参数 fuzz → 指纹 → nmap → nuclei
   ├─ ④ 自动验证      注册双账号 → IDOR/越权/JWT/未授权；SQLi/命令注入/SSRF/LFI/
   │                  上传/反序列化/XXE/XSS/CSRF 逐类 PoC 验证
   ├─ ⑤ 自动利用      数据提取 → 凭证获取 → DB dump → 提权（SUID/cron）→ 深度链
   ├─ ⑥ 实时进度      [模型]动作流 + ★发现播报 + 45 秒进度汇总（中文）
   └─ ⑦ 自动报告      report.md：风险矩阵 + 每漏洞数据包原文/响应证据/影响/修复建议
                       （同类漏洞自动去重，风险等级按漏洞类别判定）
```

内网场景（killchain playbook）：立足点 → socat/chisel 隧道 → 内网测绘 → 主题化密码攻击
（品牌词×年份）→ 凭证横向复用 → 提权 → 横向移动。网段（CIDR）先 nmap 测绘再逐目标渗透。

## 多模型编成（deep 模式）

| 模型位 | 启用条件 | 说明 |
|---|---|---|
| `flash` | 有任一主 LLM key | 主力，快且便宜 |
| `pro` | `DEEPSEEK_API_KEY`（默认共用）| 深度推理模型，第二个并行 solver |
| `glm` | `GLM_API_KEY` | 智谱 GLM（Anthropic 兼容端点） |
| `qwen` | `ALIYUN_API_KEY` | 阿里百炼 DashScope（OpenAI 兼容） |
| `kimi` | `Kimi_API_KEY` | Kimi3） |

每个模型一个独立 coding agent，同一目标各自连续攻击、通过 NOTES.md 共享事实与死路，
任一 agent 拿到证明即汇总。未配置的模型自动跳过；只想单模型跑就不开 deep。

## 配置

`.env`（完整示例见 [.env.example](.env.example)）：

| 变量 | 说明 |
|---|---|
| `DEEPSEEK_API_KEY` | 主 LLM（OpenAI 兼容；也支持 qwen / glm / kimi 作主模型） |
| `DEEPSEEK_MODEL` | 主模型 id（默认 `deepseek-chat`） |
| `DEEPSEEK_PRO_MODEL` | deep 模式第 2 solver（默认 `deepseek-reasoner`） |
| `GLM_API_KEY` + `GLM_MODEL` | 可选，GLM 强模型（默认 `glm-5.2`） |
| `ALIYUN_API_KEY` (+ `ALIYUN_BASE_URL` / `QWEN_MODEL`) | 可选，DashScope 千问端点 |
| `HEHUA_DEEP` | `deep` 开启多模型并行；默认单模型 |
| `HEHUA_PEERS` | deep 模式并行 agent 上限（默认 2，最大 = 模型数） |
| `HEHUA_PENTEST_BUDGET` | 单目标默认预算（分钟，默认 30） |

## 它做什么

1. **侦察**：全站爬虫收集路由/参数/JS；目录与参数 fuzz；指纹识别；nuclei 扫已知 CVE
2. **认证测试**：自动注册双账号，测水平/垂直越权（IDOR）、JWT 篡改、未授权访问、隐藏 API
3. **漏洞利用**：SQLi / 命令注入 / SSRF / LFI / 文件上传 / 反序列化 / SSTI / RCE；PoC 证明 + 数据提取
4. **内网多阶段**：立足点 → socat/chisel 隧道 → 内网测绘 → 主题化密码攻击（品牌词×年份组合）
   → 凭证复用 → 提权（SUID/cron/capabilities）→ 横向移动
5. **报告**：渗透结束自动生成标准测试报告 `out/<目标>/report.md`（风险矩阵 + 每漏洞的利用过程/
   完整 HTTP 数据包/响应证据/影响/修复建议），附 `TRANSCRIPT.md` 原始命令日志与 `NOTES.md` 情报笔记
6. **对话**：操作员 LLM 理解自然语言，可追问发现、调整策略、闲聊技术问题

## 8 维渗透知识库（`hehua/prompts/`）

按目标特征自动选用的领域 playbook：

| Playbook | 覆盖 |
|---|---|
| `playbook_web` | SQLi 提取兜底梯子 / SSTI / 命令注入 / SSRF / LFI / 上传 / 反序列化 / 越权 / JWT / 请求走私 / JS chunk 分析 / 指纹直打 CVE |
| `playbook_killchain` | 多阶段内网：弱口令 → RCE → 提权 → 隧道 → 横向；**密码攻击标准流程**（socat 桥 + 主题化字典 + 凭证横向复用） |
| `playbook_exploit` | 已知组件 CVE（nuclei 优先）+ PoC 清单（`poc_inventory.md` 收录 Weaver/Confluence/Shiro/Weblogic…） |
| `playbook_binary` | 逆向 / pwn / ROP / 自研 VM 解释器还原 |
| `playbook_cloud` | 云元数据 / k8s / 容器逃逸 |
| `playbook_evasion` | WAF 绕过 / 编码变形 / payload 混淆 |
| `playbook_ai` | LLM 应用渗透：系统提示泄露 / 提示注入 / Agent 工具滥用 / 沙箱逃逸 + Web 侧攻击面 |
| `playbook_blockchain` | 智能合约审计：访问控制 / 重入 / 溢出 + foundry/solc/slither 工作流 |

`tools/payloads/` 内置注入 / XSS / AI 提示注入等 payload 语料，agent 运行时直接取用。

## 架构

```
python -m hehua
  └─ operator.py    对话操作员（意图理解 / 调度 / 结果问答）
       └─ pentest.py   单目标 / CIDR 网段调度，多模型 fan-out
            └─ core/coding_agent.py   连续工具循环（每模型一个实例）
                 ├─ core/tools.py     bash / http_request / 文件 / grep / notes / submit_flag / finish
                 ├─ core/sandbox.py   命令执行隔离（超时 kill / 输出落盘）
                 ├─ core/context.py   token 估算 + 滚动压缩
                 └─ NOTES.md          多 agent 共享情报（锁保护）
  llm/    多 provider 客户端（OpenAI 兼容 + Anthropic-GLM）+ 预算统计
  prompts/  系统提示 + 8 维 playbook + PoC 清单
```

## 目录

```
hehua/      agent 本体（operator / pentest / core / llm / prompts）
scripts/    scan / crawl / dirfuzz / paramgen / pivot（agent 运行时调用的辅助脚本）
tools/      payload 语料库
```
## 全自动流程输出
<img width="1694" height="1083" alt="image" src="https://github.com/user-attachments/assets/2d7aaa26-ac51-4908-91c3-c4a9c4f79220" />

<img width="1778" height="999" alt="image" src="https://github.com/user-attachments/assets/ddc473d0-56a4-4a3a-97ba-525bdcee2f61" />

## 合规

**仅在授权靶场 / SRC 授权范围内运行。** 。

## License

MIT
