from unittest.mock import patch

import pytest

from cursed_proxy.__main__ import load_config
from cursed_proxy.proxy import CursedProxy

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

def test_proxy_delegates_to_engine():
    with patch("cursed_proxy.proxy.CursedEngine") as MockEngine:
        proxy = CursedProxy("/mock/path")
        proxy.start("eth0", True)
        proxy.engine.start.assert_called_with(ifname="eth0", verbose=True)
        
        proxy.sync_config({1234: "test"})
        proxy.engine.sync_config.assert_called_with({1234: "test"})
        
        proxy.stop()
        proxy.engine.stop.assert_called_once()
