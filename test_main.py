import sys
from unittest.mock import MagicMock, patch
from cursed_proxy.__main__ import main
import os

with patch('cursed_proxy.__main__.CursedProxy') as mock_proxy, \
     patch('argparse.ArgumentParser.parse_args') as mock_args, \
     patch('os.geteuid', return_value=0), \
     patch('time.sleep', side_effect=InterruptedError):
    
    args = MagicMock()
    args.verbose = False
    args.config_path = "test.conf"
    args.interval = 1
    mock_args.return_value = args
    
    with open("test.conf", "w") as f:
        f.write("1234: .*david.*\n")
    
    try:
        main()
    except InterruptedError:
        pass
    
    proxy_instance = mock_proxy.return_value
    proxy_instance.sync_config.assert_called_once_with({1234: '.*david.*'})
    print("SUCCESS")
