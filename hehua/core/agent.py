"""Engine helpers: playbook router + target boot grace (no benchmark loop)."""
from __future__ import annotations

import time
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


def pick_playbook(description: str, code: str = "", prior_notes: str = "") -> str:
    """Choose the playbook for a target — evidence-driven.

    Routes on the target description PLUS (on re-runs) the accumulated
    NOTES intel: first-pass recon evidence overrides a generic description.
    Web is the fallback; the MODEL can additionally load any other playbook
    itself (the system prompt carries the full index with paths)."""
    d = ((description or "") + "\n" + (prior_notes or "")).lower()
    if any(k in d for k in (
            "大模型", "语言模型", "提示注入", "智能体", "llm", "gpt",
            "prompt injection", "system prompt", "chatbot", "对话助手",
            "越狱", "rag", "langchain", "function calling", "mcp", "jailbreak")):
        return "playbook_ai.md"
    if any(k in d for k in (
            "区块链", "智能合约", "以太坊", "solidity", "ethereum",
            "web3", "evm", "dapp", "smart contract", "issolved",
            "链上", "代币", "dao", "reentrancy", "erc20", "erc-20")):
        return "playbook_blockchain.md"
    # NOTE: bare "pwn" deliberately ABSENT — English web descriptions use it
    # as a verb ("pwn this site") and would misroute; strong binary signals
    # (apk/dex/elf/逆向/反编译) suffice for real binary targets
    if any(k in d for k in (
            "apk", "android", "dex", "逆向", "反编译", "二进制", "elf",
            "复现协议", "mobile app", "reverse engineer")):
        return "playbook_binary.md"
    if any(k in d for k in (
            "域控", "域渗透", "active directory", "kerberos", "ntlm",
            "内网", "横向", "横向移动", "pivoting", "跳板")):
        return "playbook_killchain.md"
    if any(k in d for k in (
            "kubernetes", "docker", "容器逃逸", "云原生", "集群",
            "kubelet", "container registry", "k8s")):
        return "playbook_cloud.md"
    if any(k in d for k in (
            "免杀", "沙箱检测", "流量检测", "edr", "绕过检测", "规避检测")):
        return "playbook_evasion.md"
    return "playbook_web.md"


def _wait_targets_ready(addrs: list, events, grace_sec: float = 90.0) -> None:
    """TCP-probe target ports until one answers or the grace window expires.

    Slow services (Java apps, containers mid-boot...) take 30-90s to come up;
    an agent that sees connection-refused gives up inside minutes with zero
    facts. Waiting here costs nothing (it happens before the session clock)."""
    import socket
    targets = []
    for a in addrs or []:
        host, _, port = str(a).rpartition(":")
        if host and port.isdigit():
            targets.append((host, int(port)))
    if not targets:
        return
    deadline = time.time() + grace_sec
    waited = 0.0
    while True:
        for host, port in targets:
            s = socket.socket()
            s.settimeout(3)
            try:
                s.connect((host, port))
                if waited:
                    events.log("target_ready_after_wait",
                               addr=f"{host}:{port}", waited=round(waited))
                return
            except OSError:
                pass
            finally:
                s.close()
        if time.time() >= deadline:
            events.log("target_unreachable_grace",
                       addrs=[str(a) for a in addrs][:3], waited=round(waited))
            return
        time.sleep(5)
        waited += 5
