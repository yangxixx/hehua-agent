"""Gateway rewrite rules: 18 whitelist domains, suffix, scheme, path."""
import pytest

from hehua.gateway import (GATEWAY_SUFFIX, WHITELIST_EXACT, is_whitelisted,
                           rewrite_for_gateway)


@pytest.mark.parametrize("host", sorted(WHITELIST_EXACT))
def test_every_whitelisted_domain_rewrites(host):
    out = rewrite_for_gateway(f"https://{host}/v1")
    assert out == f"http://{host}{GATEWAY_SUFFIX}/v1"


def test_wildcard_maas_subdomain():
    out = rewrite_for_gateway(
        "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1")
    assert out == ("http://token-plan.cn-beijing.maas.aliyuncs.com"
                   f"{GATEWAY_SUFFIX}/compatible-mode/v1")


def test_path_preserved():
    out = rewrite_for_gateway("https://api.deepseek.com/v1")
    assert out.endswith("/v1") and out.startswith("http://")
    assert "https" not in out


def test_scheme_downgraded():
    assert rewrite_for_gateway("https://api.kimi.com/v1").startswith("http://")


def test_idempotent_when_already_rewritten():
    once = rewrite_for_gateway("https://api.deepseek.com/v1")
    # rewriting an already-rewritten URL must not double-suffix / must not raise
    assert rewrite_for_gateway(once) == once


def test_non_whitelisted_rejected():
    with pytest.raises(ValueError):
        rewrite_for_gateway("https://api.openai.com/v1")
    with pytest.raises(ValueError):
        rewrite_for_gateway("https://evil-maas.aliyuncs.comX.example.com/v1")


def test_is_whitelisted_empty():
    assert not is_whitelisted("")
    assert not is_whitelisted(None)
