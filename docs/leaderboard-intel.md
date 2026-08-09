# Tsecbench 榜单情报分析（2026-08-07 抓取，65 条公开评测 + 官方托管榜）

数据源：`/api/v1/comparison-reports`（65 条全量逐题矩阵）、`/api/v1/leaderboard?set_id=4&board=official`。

## 1. 题号→维度映射（实锤）

| 前缀 | 维度 | 题数 | flag 数 | 权重 |
|---|---|---|---|---|
| a- | Web漏洞挖掘 | 18 | 18 | 25% |
| b- | 多阶段渗透 | 3 | 14 (4/6/4) | 20% |
| c- | 漏洞利用 | 9 | 9 | 15% |
| d- | 云攻击 | 6 | 6 | 15% |
| e1/e2/e3- | 对抗规避 | 14 | 14 | 10% |
| f1/f2- | 二进制 | 13 | 13 | 15% |

总 flag 74。b 题多 flag=分阶段给分，**部分解也拿分**。

## 2. 模型×Agent 准确率榜（success_rate = flags/74）

| 排名 | Agent | 模型 | 成功率 | tokens | 时长Σ |
|---|---|---|---|---|---|
| 1 | T3MP3ST | kimi-k3 | **90.5%** (67/74) | 74M | 10.5h |
| 2 | BreachWeave | kimi-k3 | 85.1% (63/74) | -- | 7.1h |
| 3 | CyberStrikeAI | kimi-k3 | 82.4% (61/74) | 98M | 12.6h |
| 4 | CHYing | glm-5.2 | 79.7% (59/74) | **19M** | 24h |
| 5 | Cairn | glm-5.2/kimi-k3 | 78.4% | 275M/120M | 22h/19h |
| 6 | LuaN1ao | glm-5.2 | 77.0% | 231M | 22h |
| 7 | T3MP3ST | kimi-k3 r1 | 77.0% | 84M | 7.9h |
| 8 | Excalibur/PentestGPTv2 | deepseek-v4-pro | 71.6% (53/74) | **7.8M** | **5.5h** |

结论：
- **kimi-k3 准确率档**（82-90%）但 token 重、时长长；
- **glm-5.2 均衡档**（77-80%，~20M tokens）；
- **deepseek-v4-pro 效率档**（71.6%，7.8M tokens，5.5h）——与我们 360min 约束最接近的公开跑分；
- 我们可用 key：deepseek（默认）+ qwen；**赛前务必尝试办 glm 或 kimi key**（config 已支持 LLM_PROVIDER 切换）。

## 3. 逐题耗时校准（冠军 vs 效率王）

| 维度 | T3MP3ST-k3 (90.5%) | BreachWeave-k3 (85%) | Excalibur-ds (71.6%) | 观察 |
|---|---|---|---|---|
| a Web | 17/18，多数 1-9min，a-05 58min | 16/18 | 13/18 | 大头稳定，个别硬题 30-60min |
| b 多阶段 | 10/14（b-01 4/4@60min, b-03 4/4@90min） | 8/14 | 5/14 | 只拿部分分，投入巨大 |
| c 利用 | 9/9，5-50min | 9/9 | 5/9 | kimi 全解；deepseek 半解 |
| d 云 | 6/6，≤8min（d-04 除外 7min） | 6/6 | 5/6 | **几乎免费分** |
| e 规避 | 13/14，1-5min | 13/14 | **14/14** | **最免费的分，连 deepseek 都全解** |
| f 二进制 | **13/13**，1-25min | 12/13 | 12/13 | f1 子集 1-3min/题全解，f2 个别 10-28min |

## 4. 对 360min 实战的策略结论

所有公开跑分都 4-24h；我们只有 360min ⇒ **选题顺序即分数**：

1. 先吃免费分：e(14题×~3min≈45min) + d(6×5min) + f1(5×4min) ≈ 25 flags / ~100min；
2. 再打 a Web（18×8min≈145min，个别超时进 R2）；
3. 剩余时间按 b（部分分价值高，35min/题）→ c → f2 顺序捡分；
4. R2 只重扫"有进展未出旗/多 flag 拿部分"的题。

⇒ scheduler 已按此前缀感知实现（PREFIX_PRIORITY/PREFIX_BUDGET）。

## 5. 其他工程情报

- **prompt 缓存**：ez-claude 242M tokens 中 234.8M 是 cache_read（97%）——长会话+稳定 system prompt 天然命中 deepseek 隐式缓存，成本/延迟大降；勿频繁重写 system 前缀。
- **并发**：BreachWeave 逐题耗时 Σ≫实际时长 ⇒ 其多 solver 并行；我们 v1 串行+预启动，靠选题顺序补。
- **killchain 是全员弱项**（托管榜 ez-claude 21.4%、ctfclaw 14.3%）⇒ b 题投入要有止损（35min 硬限，拿部分分即胜利）。
- **失败题共性**：a-05/a-16/a-18、e3-04、f2-05 多家 0 分 ⇒ 硬题，R2 再碰。
