from unittest.mock import patch

import pytest

from cursed_proxy.__main__ import load_config
from cursed_proxy.proxy import CursedProxy


@pytest.fixture
def mock_proxy():
    # Mock ctypes.CDLL to avoid loading the real library and needing root
    with patch("ctypes.CDLL"):
        proxy = CursedProxy("/mock/path/libcursed_proxy.so")
        # Setup mock return values for success
        proxy.bpf_lib.load_ebpf.return_value = 0
        proxy.bpf_lib.add_managed_port.return_value = 0
        proxy.bpf_lib.remove_managed_port.return_value = 0
        proxy.bpf_lib.update_port_dfa.return_value = 0
        proxy.bpf_lib.remove_port_dfa.return_value = 0
        yield proxy


def test_compile_regex(mock_proxy):
    dfa_info = mock_proxy.compile_regex(".*david.*")
    assert "start_state" in dfa_info
    assert "accept_states" in dfa_info
    assert "transitions" in dfa_info
    assert dfa_info["total_states"] > 0
    assert len(dfa_info["transitions"]) > 0


def test_sync_config_adds_new_regex(mock_proxy):
    # Initial sync
    mock_proxy.sync_config({1234: ".*david.*"})
    assert 1234 in mock_proxy.ports
    assert mock_proxy.config[1234] == ".*david.*"
    assert mock_proxy.bpf_lib.update_port_dfa.called


def test_sync_config_caches_regex(mock_proxy):
    # Add
    mock_proxy.sync_config({1234: ".*david.*"})
    mock_proxy.bpf_lib.update_port_dfa.reset_mock()

    # Remove port but keep config
    mock_proxy.sync_config({})
    assert 1234 not in mock_proxy.ports
    assert 1234 in mock_proxy.config

    # Re-add same regex
    mock_proxy.sync_config({1234: ".*david.*"})
    assert 1234 in mock_proxy.ports
    # Should NOT have compiled or added DFA transitions again
    mock_proxy.bpf_lib.update_port_dfa.assert_not_called()


def test_sync_config_updates_changed_regex(mock_proxy):
    mock_proxy.sync_config({1234: ".*david.*"})
    mock_proxy.bpf_lib.update_port_dfa.reset_mock()
    mock_proxy.bpf_lib.remove_port_dfa.reset_mock()

    # Update regex
    mock_proxy.sync_config({1234: ".*newpattern.*"})
    assert mock_proxy.config[1234] == ".*newpattern.*"

    # Should have removed old transitions and added new ones
    # Should have removed old transitions and added new ones
    assert mock_proxy.bpf_lib.remove_port_dfa.called
    assert mock_proxy.bpf_lib.update_port_dfa.called


def test_load_config_valid_format(tmp_path):
    conf_file = tmp_path / "proxy.conf"
    conf_file.write_text("1234: .*david.*\n8080: ^GET.*\n")

    config = load_config(str(conf_file))
    assert config == {1234: ".*david.*", 8080: "^GET.*"}


def test_load_config_ignores_comments(tmp_path):
    conf_file = tmp_path / "proxy.conf"
    conf_file.write_text(
        "# This is a comment\n\n1234: .*david.*\n   # indented comment\n"
    )

    config = load_config(str(conf_file))
    assert config == {1234: ".*david.*"}


def test_load_config_invalid_port_ignored(tmp_path):
    conf_file = tmp_path / "proxy.conf"
    conf_file.write_text("notaport: .*david.*\n1234: .*david.*\nmissingcolon\n")

    config = load_config(str(conf_file))
    # Should only load the valid one
    assert config == {1234: ".*david.*"}


def test_load_config_missing_file():
    config = load_config("/does/not/exist.conf")
    assert config is None
