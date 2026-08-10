# Hehua

自主渗透 agent。在**授权靶场 / SRC 范围**内，给它一个目标（URL / IP / 网段），它自动完成
侦察 → 枚举 → 利用 → 报告漏洞的全流程。LLM 工具循环驱动 + 规则看门狗 + 预算控制。

## 快速开始

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .        # Linux: .venv/bin/python
cp .env.example .env                             # 填入 LLM API key
```

## 用法

### 交互式（推荐）

```bash
python -m hehua
```
启动后输入指令：
```
hehua> 渗透 http://10.0.0.5          # 渗透单个目标
hehua> 渗透 192.168.1.0/24           # 扫描网段并逐个渗透
hehua> 渗透 http://target 找注入     # 带额外指令
hehua> exit
```

### 一次性命令

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

## 目录

```
hehua/      pentest(REPL+单目标+CIDR) / core(agent+tools+sandbox+context+memory)
            / llm(client+anthropic_client+budget) / prompts(系统+8维playbook) / cli
scripts/    scan / crawl / dirfuzz / paramgen
```

## 合规

**仅在授权靶场 / SRC 范围内运行。** 密钥全部走环境变量。

## License

MIT
