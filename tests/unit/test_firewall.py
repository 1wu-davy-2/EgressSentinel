"""firewall 加固单测（05 文档波次一 W2）：netsh 全 mock，绝不真实施改防火墙。

覆盖：规则清单（dry-run 不触系统）/ 创建调用序列与 journal-first / 创建失败保留
记录 / 还原幂等（容忍不存在、拒绝非本工具前缀）/ 非管理员拒绝。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aaa.setup import admin
from aaa.setup import firewall as fw
from aaa.setup.state import StateFile

PROXY_EXE = r"C:\Program Files\EgressSentinel\proxy.exe"


class FakeNetsh:
    """记录调用的假 netsh（注入 ``fw._run_netsh``）。

    - add/delete 默认成功（rc=0，与真实 netsh 的「确定。」一致）；
    - show 默认「规则不存在」（rc=1），``show_found=True`` 时返回 rc=0（仍在）；
    - ``fail_ops`` 按操作 token（args[2]：add/delete/show）注入失败。
    """

    def __init__(self, fail_ops: set[str] | None = None, show_found: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.fail_ops = fail_ops or set()
        self.show_found = show_found

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        op = args[2] if len(args) > 2 else ""
        if op in self.fail_ops:
            return subprocess.CompletedProcess(args, 1, "", "注入的失败（拒绝访问）")
        if op == "show":
            rc = 0 if self.show_found else 1
            return subprocess.CompletedProcess(args, rc, "规则名:" if rc else "", "")
        return subprocess.CompletedProcess(args, 0, "确定。", "")

    def ops(self, op: str) -> list[list[str]]:
        return [c for c in self.calls if len(c) > 2 and c[2] == op]


@pytest.fixture
def state(tmp_path: Path) -> StateFile:
    return StateFile(tmp_path / "setup-state.json")


@pytest.fixture
def proxy_exe(tmp_path: Path) -> Path:
    """临时代理可执行文件（apply 校验存在性：不依赖真实系统路径）。"""
    exe = tmp_path / "bin" / "proxy.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"MZ")
    return exe


@pytest.fixture
def elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fw, "is_current_process_elevated", lambda: True)


# --------------------------------------------------------------------------
# plan_harden：规则清单（dry-run 概念）
# --------------------------------------------------------------------------


def test_plan_harden_lists_expected_rules() -> None:
    rules = fw.plan_harden(PROXY_EXE)
    assert [r.name for r in rules] == [
        fw.RULE_ALLOW_PROXY,
        fw.RULE_ALLOW_SVCHOST,
        fw.RULE_BLOCK_TCP_ANY,
        fw.RULE_BLOCK_UDP_ANY,
    ]
    for rule in rules:
        assert rule.name.startswith(fw.RULE_NAME_PREFIX)
        assert rule.direction == "out"
        assert rule.remote_port == 443

    by_name = {r.name: r for r in rules}
    proxy_rule = by_name[fw.RULE_ALLOW_PROXY]
    assert (proxy_rule.action, proxy_rule.protocol) == ("allow", "TCP")
    assert proxy_rule.program == str(Path(PROXY_EXE))

    svchost_rule = by_name[fw.RULE_ALLOW_SVCHOST]
    assert (svchost_rule.action, svchost_rule.protocol) == ("allow", "TCP")
    assert svchost_rule.program.endswith("svchost.exe")  # Windows Update 白名单

    tcp_block = by_name[fw.RULE_BLOCK_TCP_ANY]
    assert (tcp_block.action, tcp_block.protocol) == ("block", "TCP")
    assert tcp_block.program is None  # any 程序

    udp_block = by_name[fw.RULE_BLOCK_UDP_ANY]
    assert (udp_block.action, udp_block.protocol) == ("block", "UDP")
    assert udp_block.program is None  # QUIC/H3


def test_plan_harden_allows_before_blocks() -> None:
    """Allow 在前、Block 在后：中途崩溃停留在「未加固」而非「全断 443」。"""
    names = [r.name for r in fw.plan_harden(PROXY_EXE)]
    assert names.index(fw.RULE_ALLOW_PROXY) < names.index(fw.RULE_BLOCK_TCP_ANY)
    assert names.index(fw.RULE_ALLOW_SVCHOST) < names.index(fw.RULE_BLOCK_TCP_ANY)


def test_plan_harden_is_pure_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """dry-run 概念：plan 绝不触达系统（netsh 零调用），且接受 Path 输入。"""

    def boom(args: list[str]) -> subprocess.CompletedProcess[str]:
        raise AssertionError("plan_harden 不允许调用 netsh")

    monkeypatch.setattr(fw, "_run_netsh", boom)
    rules = fw.plan_harden(Path(PROXY_EXE))
    assert len(rules) == 4
    assert rules[0].program == str(Path(PROXY_EXE))


def test_reuses_admin_elevation_check() -> None:
    """管理员门禁复用 setup.admin.is_current_process_elevated（同一函数对象）。"""
    assert fw.is_current_process_elevated is admin.is_current_process_elevated


# --------------------------------------------------------------------------
# apply_harden：创建调用序列 + journal-first
# --------------------------------------------------------------------------


def test_apply_harden_creates_rules_in_order_and_journals(
    monkeypatch: pytest.MonkeyPatch,
    state: StateFile,
    proxy_exe: Path,
    elevated: None,
) -> None:
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entries = fw.apply_harden(state, proxy_exe)

    assert [e.key for e in entries] == [
        fw.RULE_ALLOW_PROXY,
        fw.RULE_ALLOW_SVCHOST,
        fw.RULE_BLOCK_TCP_ANY,
        fw.RULE_BLOCK_UDP_ANY,
    ]
    assert all(e.kind == fw.KIND_FIREWALL_RULE for e in entries)
    assert len(state.entries()) == 4  # journal-first：每条规则一条记录

    # 每条规则：先删同名旧规则（可重复执行），再 add
    assert [c[2] for c in fake.calls] == ["delete", "add"] * 4
    adds = fake.ops("add")
    for name, call in zip((e.key for e in entries), adds, strict=True):
        assert f"name={name}" in call

    proxy_add = adds[0]
    assert "action=allow" in proxy_add
    assert "protocol=TCP" in proxy_add
    assert "remoteport=443" in proxy_add
    assert f"program={proxy_exe}" in proxy_add
    assert "dir=out" in proxy_add

    tcp_block_add = next(c for c in adds if f"name={fw.RULE_BLOCK_TCP_ANY}" in c)
    assert "action=block" in tcp_block_add
    assert "program=any" in tcp_block_add

    udp_block_add = next(c for c in adds if f"name={fw.RULE_BLOCK_UDP_ANY}" in c)
    assert "protocol=UDP" in udp_block_add

    # Allow 先于 Block 创建
    add_names = [next(a for a in c if a.startswith("name=")) for c in adds]
    assert add_names.index(f"name={fw.RULE_ALLOW_PROXY}") < add_names.index(
        f"name={fw.RULE_BLOCK_TCP_ANY}"
    )


def test_apply_harden_journals_rule_payload(
    monkeypatch: pytest.MonkeyPatch,
    state: StateFile,
    proxy_exe: Path,
    elevated: None,
) -> None:
    """journal 记录携带规则全字段（teardown 按名还原的依据）。"""
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    fw.apply_harden(state, proxy_exe)

    entry = next(e for e in state.entries() if e.key == fw.RULE_BLOCK_TCP_ANY)
    assert entry.new["name"] == fw.RULE_BLOCK_TCP_ANY
    assert entry.new["action"] == "block"
    assert entry.new["protocol"] == "TCP"
    assert entry.new["remote_port"] == 443
    assert entry.new["program"] is None


def test_apply_failure_keeps_journal_for_retry(
    monkeypatch: pytest.MonkeyPatch,
    state: StateFile,
    proxy_exe: Path,
    elevated: None,
) -> None:
    """创建失败抛 FirewallError；已记录条目保留（teardown/重试可清理）。"""
    fake = FakeNetsh(fail_ops={"add"})
    monkeypatch.setattr(fw, "_run_netsh", fake)
    with pytest.raises(fw.FirewallError, match=fw.RULE_ALLOW_PROXY):
        fw.apply_harden(state, proxy_exe)
    assert len(state.entries()) == 1  # 首条规则失败即停，journal 保留
    assert len(fake.ops("add")) == 1  # 不再尝试后续规则


def test_apply_without_admin_is_rejected(
    monkeypatch: pytest.MonkeyPatch, state: StateFile
) -> None:
    """非管理员直接拒绝：零 netsh 调用、零 journal 记录。"""
    monkeypatch.setattr(fw, "is_current_process_elevated", lambda: False)
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    with pytest.raises(fw.FirewallError, match="管理员"):
        fw.apply_harden(state, PROXY_EXE)
    assert fake.calls == []
    assert state.entries() == []


def test_apply_missing_proxy_exe_is_rejected(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, elevated: None, tmp_path: Path
) -> None:
    """代理程序不存在直接拒绝：不 journal、不 netsh。"""
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    with pytest.raises(fw.FirewallError, match="不存在"):
        fw.apply_harden(state, tmp_path / "no-such-proxy.exe")
    assert fake.calls == []
    assert state.entries() == []


# --------------------------------------------------------------------------
# restore_harden：按名精确删除 + 幂等
# --------------------------------------------------------------------------


def _record_rule(state: StateFile, name: str = fw.RULE_BLOCK_TCP_ANY):
    return state.record(
        kind=fw.KIND_FIREWALL_RULE,
        key=name,
        new={"name": name, "action": "block", "protocol": "TCP", "remote_port": 443},
    )


def test_restore_deletes_by_exact_name_and_drops_entry(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, elevated: None
) -> None:
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entry = _record_rule(state)
    fw.restore_harden(state, entry)
    deletes = fake.ops("delete")
    assert deletes == [
        ["advfirewall", "firewall", "delete", "rule", f"name={fw.RULE_BLOCK_TCP_ANY}"]
    ]
    assert state.entries() == []


def test_restore_is_idempotent_when_rule_absent(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, elevated: None
) -> None:
    """delete 返回非 0 + show 复核「规则已不在」→ 视为成功（幂等容忍不存在）。"""
    fake = FakeNetsh(fail_ops={"delete"}, show_found=False)
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entry = _record_rule(state)
    fw.restore_harden(state, entry)  # 不抛异常
    assert state.entries() == []


def test_restore_failure_when_rule_still_exists(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, elevated: None
) -> None:
    """delete 失败且 show 确认规则仍在 → 报错，记录保留供重试。"""
    fake = FakeNetsh(fail_ops={"delete"}, show_found=True)
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entry = _record_rule(state)
    with pytest.raises(fw.FirewallError, match=fw.RULE_BLOCK_TCP_ANY):
        fw.restore_harden(state, entry)
    assert len(state.entries()) == 1  # 记录保留


def test_restore_refuses_non_prefixed_rule_name(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, elevated: None
) -> None:
    """journal 记录被篡改时拒绝误删他名规则。"""
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entry = _record_rule(state, name="Other-Tool-Rule")
    with pytest.raises(fw.FirewallError, match="前缀"):
        fw.restore_harden(state, entry)
    assert fake.ops("delete") == []
    assert len(state.entries()) == 1


def test_restore_without_admin_is_rejected(
    monkeypatch: pytest.MonkeyPatch, state: StateFile
) -> None:
    """非提权 shell 实测 delete 报「需要提升」：还原前直接拒绝，零 netsh 调用。"""
    monkeypatch.setattr(fw, "is_current_process_elevated", lambda: False)
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entry = _record_rule(state)
    with pytest.raises(fw.FirewallError, match="管理员"):
        fw.restore_harden(state, entry)
    assert fake.calls == []
    assert len(state.entries()) == 1


def test_restore_falls_back_to_entry_key_when_payload_missing(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, elevated: None
) -> None:
    """new 载荷缺失时回落 entry.key（旧记录兼容）。"""
    fake = FakeNetsh()
    monkeypatch.setattr(fw, "_run_netsh", fake)
    entry = state.record(kind=fw.KIND_FIREWALL_RULE, key=fw.RULE_ALLOW_PROXY, new=None)
    fw.restore_harden(state, entry)
    assert fake.ops("delete") == [
        ["advfirewall", "firewall", "delete", "rule", f"name={fw.RULE_ALLOW_PROXY}"]
    ]
    assert state.entries() == []
