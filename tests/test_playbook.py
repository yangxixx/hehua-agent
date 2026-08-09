"""Playbook routing: platform prefix is authoritative (run-6661 audit)."""
from hehua.core.agent import pick_playbook


def test_prefix_overrides_description():
    # c- descriptions say nothing about exploits; prefix must route them
    # to the product-recipe playbook (run-6661: all 9 got web playbook).
    assert pick_playbook("请对目标AI工作流平台进行安全测试与漏洞挖掘。",
                         "c-08") == "playbook_exploit.md"
    assert pick_playbook("请对目标地理数据服务进行安全测试。",
                         "c-04") == "playbook_exploit.md"
    assert pick_playbook("某企业的门户网站存在安全隐患。",
                         "b-01") == "playbook_killchain.md"
    assert pick_playbook("APT full-chain attack", "b-02") == "playbook_killchain.md"
    assert pick_playbook("web app", "a-14") == "playbook_web.md"
    assert pick_playbook("Azure Storage SAS", "d-04") == "playbook_cloud.md"
    assert pick_playbook("waf bypass", "e3-04") == "playbook_evasion.md"
    assert pick_playbook("TCP token store", "f1-01") == "playbook_binary.md"
    assert pick_playbook("firmware reversing", "f2-05") == "playbook_binary.md"


def test_prefix_case_insensitive():
    assert pick_playbook("x", "C-04") == "playbook_exploit.md"
    assert pick_playbook("x", "B-02") == "playbook_killchain.md"


def test_description_fallback_for_non_platform():
    # XBOW-style codes (no platform prefix) fall back to keywords.
    assert pick_playbook("内网横向移动 killchain", "xbow-7") == "playbook_killchain.md"
    assert pick_playbook("binary rop pwn 逆向", "CH-1") == "playbook_binary.md"
    assert pick_playbook("云 kubernetes docker", "t-2") == "playbook_cloud.md"
    assert pick_playbook("WAF 绕过检测 evasion", "x") == "playbook_evasion.md"
    assert pick_playbook("CVE-2024-1234 exploit", "y") == "playbook_exploit.md"
    assert pick_playbook("a plain website", "z") == "playbook_web.md"


def test_no_code_uses_description():
    assert pick_playbook("二进制 reverse", "") == "playbook_binary.md"
