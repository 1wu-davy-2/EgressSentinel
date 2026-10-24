"""用户环境变量单测（03 文档 T1.4）。

红线：注册表与广播全部走假实现（注入），绝不真实施改用户环境变量。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aaa.setup import envvars
from aaa.setup.state import StateFile


@pytest.fixture
def fake_env(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, str], list[int]]:
    registry: dict[str, str] = {}
    monkeypatch.setattr(envvars, "_env_read", lambda name: registry.get(name))
    monkeypatch.setattr(
        envvars, "_env_write", lambda name, value: registry.__setitem__(name, value)
    )
    monkeypatch.setattr(envvars, "_env_delete", lambda name: registry.pop(name, None))
    broadcasts: list[int] = []
    monkeypatch.setattr(envvars, "broadcast_env_change", lambda: broadcasts.append(1))
    return registry, broadcasts


def test_build_env_values_matches_design_d1(tmp_path: Path) -> None:
    values = envvars.build_env_values(
        "127.0.0.1", 8080, ca_cert_pem=tmp_path / "ca.pem", merged_pem=tmp_path / "bundle.pem"
    )
    assert set(values) == set(envvars.ENV_VAR_NAMES)  # 02 文档 D1 清单全覆盖
    assert values["HTTP_PROXY"] == values["HTTPS_PROXY"] == "http://127.0.0.1:8080"
    assert values["NO_PROXY"] == "localhost,127.0.0.1"  # 02 文档 D1 字面值
    assert values["NODE_USE_ENV_PROXY"] == "1"
    assert values["NODE_EXTRA_CA_CERTS"] == str(tmp_path / "ca.pem")
    assert values["REQUESTS_CA_BUNDLE"] == values["SSL_CERT_FILE"] == values["CURL_CA_BUNDLE"]


def test_apply_user_envvars_records_old_none(
    fake_env: tuple[dict[str, str], list[int]], tmp_path: Path
) -> None:
    registry, broadcasts = fake_env
    state = StateFile(tmp_path / "setup-state.json")
    values = envvars.build_env_values("127.0.0.1", 8080, tmp_path / "ca.pem", tmp_path / "b.pem")

    entries = envvars.apply_user_envvars(state, values)

    assert len(entries) == len(envvars.ENV_VAR_NAMES)
    assert registry["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert broadcasts == [1]
    by_key = {e.key: e for e in state.entries()}
    assert by_key["HTTP_PROXY"].old is None  # 原先不存在
    assert by_key["NODE_USE_ENV_PROXY"].new == "1"


def test_apply_twice_records_chained_old_values(
    fake_env: tuple[dict[str, str], list[int]], tmp_path: Path
) -> None:
    """逆序还原的语义基础：第二次下发的 old 是第一次的 new。"""
    registry, _broadcasts = fake_env
    state = StateFile(tmp_path / "setup-state.json")
    values = envvars.build_env_values("127.0.0.1", 8080, tmp_path / "ca.pem", tmp_path / "b.pem")
    envvars.apply_user_envvars(state, values)
    envvars.apply_user_envvars(state, values)
    entries = state.entries()
    assert len(entries) == 2 * len(envvars.ENV_VAR_NAMES)
    http_entries = [e for e in entries if e.key == "HTTP_PROXY"]
    assert http_entries[0].old is None
    assert http_entries[1].old == "http://127.0.0.1:8080"


def test_restore_user_envvar_deletes_when_old_absent(
    fake_env: tuple[dict[str, str], list[int]], tmp_path: Path
) -> None:
    registry, broadcasts = fake_env
    state = StateFile(tmp_path / "setup-state.json")
    (entry,) = envvars.apply_user_envvars(state, {"HTTP_PROXY": "http://127.0.0.1:8080"})

    envvars.restore_user_envvar(state, entry)

    assert "HTTP_PROXY" not in registry
    assert state.entries() == []
    assert len(broadcasts) == 2


def test_restore_user_envvar_restores_previous_value(
    fake_env: tuple[dict[str, str], list[int]], tmp_path: Path
) -> None:
    registry, _broadcasts = fake_env
    registry["HTTP_PROXY"] = "http://old:1"
    state = StateFile(tmp_path / "setup-state.json")
    (entry,) = envvars.apply_user_envvars(state, {"HTTP_PROXY": "http://127.0.0.1:8080"})
    envvars.restore_user_envvar(state, entry)
    assert registry["HTTP_PROXY"] == "http://old:1"


def test_file_created_roundtrip(tmp_path: Path) -> None:
    state = StateFile(tmp_path / "setup-state.json")
    target = tmp_path / "generated.pem"
    target.write_bytes(b"x")
    entry = envvars.record_file_created(state, target)
    envvars.restore_file_created(state, entry)
    assert not target.exists()
    assert state.entries() == []
    envvars.restore_file_created(state, entry)  # 幂等：文件已不在仍成功
