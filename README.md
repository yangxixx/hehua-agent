# Hehua

自主渗透 agent。在**授权靶场 / SRC 范围**内，用自然语言指挥它渗透目标——它自动完成
侦察 → 枚举 → 利用 → 报告漏洞的全流程。对话式操作 + LLM 工具循环 + 规则看门狗。

## 快速开始

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .        # Linux: .venv/bin/python
cp .env.example .env                             # 填入 LLM API key
```

## 用法

### 对话式（推荐）

```bash
python -m hehua
```

启动后用自然语言对话——操作员 LLM 理解你的意图，自动调度渗透：

```
你> 你好
助手> 你好！给我一个授权目标就开始。

你> 渗透 http://10.0.0.5
[开始渗透… 实时输出工具调用 / 发现]
助手> 渗透完成。发现 2 个漏洞：
  - SQL 注入 (/login?user=)
  - 目录穿越 (/download?file=../)

你> 重点测一下 API 越权
[开始渗透(带侧重指令)…]

你> 上次找到什么了？
助手> 共 2 个发现：…

你> exit
```

支持的目标格式：URL | IP:端口 | 网段(CIDR)。

### 一次性命令（脚本 / 自动化）

```bash
python -m hehua pentest http://10.0.0.5 --budget 30
python -m hehua pentest 10.0.0.0/24 --budget 15 --deep
```

## 配置

`.env` 填入：

| 变量 | 说明 |
|---|---|
| `DEEPSEEK_API_KEY` | 主 LLM（OpenAI 兼容，也支持 qwen / glm / kimi） |
| `GLM_API_KEY` + `GLM_MODEL=glm-5.2` | 可选，启用 GLM-5.2 深度模式升级 |
| `HEHUA_DEEP` | `auto`(默认) / `deep` / `normal` |
| `HEHUA_PEERS` | 深度模式并行 agent 数（默认 2） |

## 它做什么

1. **侦察**：爬虫收集所有路由/参数/JS；目录扫描；指纹识别；nuclei 扫已知 CVE。
2. **认证测试**：自动注册双账号，测 IDOR / 越权 / JWT 篡改 / 未授权访问。
3. **漏洞利用**：SQLi / 命令注入 / SSRF / 文件上传 / 反序列化 / RCE；PoC 证明 + 数据提取。
4. **报告**：每个确认的漏洞记录（类型 + PoC + 影响），实时输出到终端。
5. **对话**：操作员 LLM 理解自然语言，可追问发现、调整策略、闲聊技术问题。

## 目录

```
hehua/      operator(对话式操作员) / pentest(单目标+CIDR) / core(agent+tools+sandbox)
            / llm(client+anthropic_client) / prompts(系统+8维playbook) / cli
scripts/    scan / crawl / dirfuzz / paramgen
```

## 合规

**仅在授权靶场 / SRC 范围内运行。** 密钥全部走环境变量。
<img width="1320" height="960" alt="image" src="https://github.com/user-attachments/assets/44aaed6d-dbee-4df3-bd1c-b75a8141081e" />

## License

MIT
