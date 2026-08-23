from unittest.mock import patch

import pytest

from cursed_proxy.__main__ import load_config
from cursed_proxy.proxy import CursedProxy


@pytest.fixture
def mock_proxy():
    # Mock CursedEngine to avoid loading the real library and needing root
    with patch("cursed_proxy.proxy.CursedEngine") as MockEngine:
        mock_engine_instance = MockEngine.return_value
        # Setup mock return values for success
        mock_engine_instance.load_ebpf.return_value = 0
        mock_engine_instance.add_managed_port.return_value = 0
        mock_engine_instance.remove_managed_port.return_value = 0
        mock_engine_instance.update_port_dfa.return_value = 0
        mock_engine_instance.remove_port_dfa.return_value = 0
        
        # We need to make compile_regex return a valid tuple since CursedProxy delegates to it
        # Wait, CursedProxy just delegates everything to engine.
        proxy = CursedProxy("/mock/path/libcursed_proxy.so")
        yield proxy


def test_compile_regex(mock_proxy):
    keys, values = mock_proxy.compile_regex(".*david.*")
    assert len(keys) > 0
    assert len(keys) == len(values)


def test_sync_config_adds_new_regex(mock_proxy):
    # Initial sync
    mock_proxy.sync_config({1234: ".*david.*"})
    assert 1234 in mock_proxy.config
    assert mock_proxy.config[1234] == ".*david.*"
    assert mock_proxy.bpf_lib.update_port_dfa.called


def test_sync_config_updates_changed_regex(mock_proxy):
    mock_proxy.sync_config({1234: ".*david.*"})
    mock_proxy.bpf_lib.update_port_dfa.reset_mock()
    mock_proxy.bpf_lib.remove_port_dfa.reset_mock()

    # Update regex
    mock_proxy.sync_config({1234: ".*newpattern.*"})
    assert mock_proxy.config[1234] == ".*newpattern.*"

    # Should have removed old transitions and added new ones
    # Should just atomically overwrite using update_port_dfa
    assert not mock_proxy.bpf_lib.remove_port_dfa.called
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


def test_invalid_regex_syntax(mock_proxy):
    # Testing an edge case where the regex has invalid syntax
    # This shouldn't crash the proxy, but rather log an error and not update BPF
    mock_proxy.add_regex(5555, "[a-")
    assert not mock_proxy.bpf_lib.update_port_dfa.called


def test_regex_too_complex(mock_proxy, monkeypatch):
    # Mock compile_regex to return a massive list of transitions (edge case)
    # This ensures we don't accidentally OOM the kernel map
    keys = [1] * 300_000
    values = [2] * 300_000
    
    def mock_compile(*args, **kwargs):
        return keys, values
    
    mock_compile.cache_info = lambda: type("CacheInfo", (), {"hits": 0})()
    monkeypatch.setattr(mock_proxy, "compile_regex", mock_compile)
    
    mock_proxy.add_regex(8888, ".*massive.*")
    
    # BPF map shouldn't be updated because it exceeds 262144
    assert not mock_proxy.bpf_lib.update_port_dfa.called


def test_caching_behavior(mock_proxy):
    # Test that the LRU cache is hit when assigning the same regex to a different port
    mock_proxy.compile_regex.cache_clear()
    
    mock_proxy.add_regex(1111, ".*hello.*")
    hits_after_first = mock_proxy.compile_regex.cache_info().hits
    
    mock_proxy.add_regex(2222, ".*hello.*")
    hits_after_second = mock_proxy.compile_regex.cache_info().hits
    
    assert hits_after_second > hits_after_first
    assert mock_proxy.bpf_lib.update_port_dfa.call_count == 2
