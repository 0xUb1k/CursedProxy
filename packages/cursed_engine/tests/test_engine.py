from unittest.mock import patch, MagicMock

import pytest

from cursed_engine.engine import CursedEngine

@pytest.fixture
def mock_engine():
    # Mock the internal C library
    with patch("cursed_engine.engine.ctypes.CDLL") as MockCDLL:
        mock_lib = MockCDLL.return_value
        mock_lib.load_ebpf.return_value = 0
        mock_lib.add_managed_port.return_value = 0
        mock_lib.remove_managed_port.return_value = 0
        mock_lib.update_port_dfa.return_value = 0
        mock_lib.remove_port_dfa.return_value = 0
        
        # Override finding the library
        with patch("cursed_engine.engine.os.path.exists", return_value=True):
            engine = CursedEngine("/mock/path/libcursed_engine.so")
            engine.bpf_lib = mock_lib
            yield engine

def test_compile_regex(mock_engine):
    keys, values = mock_engine.compile_regex(".*david.*")
    assert len(keys) > 0
    assert len(keys) == len(values)

def test_sync_config_adds_new_regex(mock_engine):
    # Initial sync
    mock_engine.sync_config({1234: ".*david.*"})
    assert 1234 in mock_engine.config
    assert mock_engine.config[1234] == ".*david.*"
    assert mock_engine.bpf_lib.update_port_dfa.called

def test_sync_config_updates_changed_regex(mock_engine):
    mock_engine.sync_config({1234: ".*david.*"})
    mock_engine.bpf_lib.update_port_dfa.reset_mock()
    mock_engine.bpf_lib.remove_port_dfa.reset_mock()

    # Update regex
    mock_engine.sync_config({1234: ".*newpattern.*"})
    assert mock_engine.config[1234] == ".*newpattern.*"

    assert not mock_engine.bpf_lib.remove_port_dfa.called
    assert mock_engine.bpf_lib.update_port_dfa.called

def test_invalid_regex_syntax(mock_engine):
    # Testing an edge case where the regex has invalid syntax
    mock_engine.add_regex(5555, "[a-")
    assert not mock_engine.bpf_lib.update_port_dfa.called

def test_regex_too_complex(mock_engine, monkeypatch):
    keys = [1] * 300_000
    values = [2] * 300_000
    
    def mock_compile(*args, **kwargs):
        return keys, values
    
    mock_compile.cache_info = lambda: type("CacheInfo", (), {"hits": 0})()
    monkeypatch.setattr(mock_engine, "compile_regex", mock_compile)
    
    mock_engine.add_regex(8888, ".*massive.*")
    
    assert not mock_engine.bpf_lib.update_port_dfa.called

def test_caching_behavior(mock_engine):
    mock_engine.compile_regex.cache_clear()
    
    mock_engine.add_regex(1111, ".*hello.*")
    hits_after_first = mock_engine.compile_regex.cache_info().hits
    
    mock_engine.add_regex(2222, ".*hello.*")
    hits_after_second = mock_engine.compile_regex.cache_info().hits
    
    assert hits_after_second > hits_after_first
    assert mock_engine.bpf_lib.update_port_dfa.call_count == 2
