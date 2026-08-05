import pytest
import socket
import threading
import time
import os
from cursed_proxy.proxy import CursedProxy

PORT = 54321

def echo_server(stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', PORT))
    server.listen(1)
    server.settimeout(1.0)
    
    while not stop_event.is_set():
        try:
            conn, addr = server.accept()
            conn.settimeout(5.0) # give client time to send data
            try:
                data = conn.recv(1024)
                if data:
                    conn.sendall(data)
            except (socket.timeout, BlockingIOError) as e:
                print(f"Recv error or timeout: {e}")
            finally:
                conn.close()
        except socket.timeout:
            continue
        except BlockingIOError:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"Server error: {e}")
            break
    server.close()

@pytest.fixture(scope="module")
def setup_echo_server():
    stop_event = threading.Event()
    server_thread = threading.Thread(target=echo_server, args=(stop_event,))
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(0.5)
    
    yield
    
    stop_event.set()
    server_thread.join(timeout=2.0)

@pytest.fixture(scope="module")
def ebpf_proxy():
    if os.geteuid() != 0:
        pytest.skip("Integration tests require root privileges")
        
    proxy = CursedProxy()
    proxy.start(verbose=False)
    proxy.sync_config({PORT: ".*DROPME.*"})
    
    # Give BPF a moment to attach to cgroup
    time.sleep(1)
    
    yield proxy
    
    proxy.sync_config({})
    proxy.stop()

def send_payload(payload):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(('127.0.0.1', PORT))
        client.sendall(payload)
        response = client.recv(1024)
        client.close()
        return response
    except socket.timeout:
        return None
    except ConnectionResetError:
        return None
    except BrokenPipeError:
        return None

def test_benign_traffic(setup_echo_server, ebpf_proxy):
    # This should pass right through and be echoed back
    payload = b"Hello World"
    response = send_payload(payload)
    assert response == payload

def test_malicious_traffic(setup_echo_server, ebpf_proxy):
    # This matches the regex and should be dropped by eBPF
    payload = b"This packet contains DROPME inside"
    response = send_payload(payload)
    # The SKB is dropped silently in the kernel, so the userspace socket will timeout
    # or the connection might be reset. We assert no response is received.
    assert response is None
