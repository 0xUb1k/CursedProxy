import os
import socket
import threading
import time

import pytest

from cursed_engine.engine import CursedEngine

PORT = 54321


def echo_server(stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(1)
    server.settimeout(1.0)

    while not stop_event.is_set():
        try:
            conn, _addr = server.accept()
            conn.settimeout(0.5)  # give client time to send data, but recover fast on drops
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
        except Exception as e:  # noqa: BLE001
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

    proxy = CursedEngine()
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
        client.connect(("127.0.0.1", PORT))
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
    # or the connection might be reset, or return EOF (b'').
    assert response in (None, b'')


def test_starts_with_traffic(setup_echo_server, ebpf_proxy):
    # Update config to test the starts-with behavior natively
    ebpf_proxy.sync_config({PORT: "GET /admin.*"})
    time.sleep(1)  # let bpf maps update

    # 1. This should PASS (doesn't start with GET)
    payload1 = b"POST /admin HTTP/1.1\n"
    response1 = send_payload(payload1)
    assert response1 == payload1

    # 2. This should DROP (starts with GET /admin)
    payload2 = b"GET /admin/settings HTTP/1.1\n"
    response2 = send_payload(payload2)
    assert response2 in (None, b'')

    # 3. This should PASS (has GET /admin inside, but doesn't start with it)
    payload3 = b"abc GET /admin/settings"
    response3 = send_payload(payload3)
    assert response3 == payload3


def test_big_payload_match(setup_echo_server, ebpf_proxy):
    # Update config to match anything containing DROPME
    ebpf_proxy.sync_config({PORT: ".*DROPME.*"})
    time.sleep(1)

    # Payload with DROPME at byte 1500 (within the 2048 byte MAX_SCAN_DEPTH limit)
    # Followed by 5 MB of random data to ensure the proxy can drop massive packets
    payload = (b"A" * 1500) + b"DROPME" + (b"B" * 5_000_000)
    
    # The packet should be ruthlessly dropped
    response = send_payload(payload)
    assert response in (None, b'')


def test_big_payload_no_bypass(setup_echo_server, ebpf_proxy):
    ebpf_proxy.sync_config({PORT: ".*DROPME.*"})
    time.sleep(1)

    # Payload with DROPME at byte 3500 (previously beyond the 2048 byte MAX_SCAN_DEPTH limit).
    # The proxy now uses bpf_for to scan the entire payload.
    # Therefore, the proxy will see this signature and will DROP it!
    payload = (b"A" * 3500) + b"DROPME" + (b"B" * 5000)
    
    response = send_payload(payload)
    
    # The proxy dropped it, so the userspace socket will timeout or return empty
    assert response in (None, b'')

def test_dynamic_regex_update(setup_echo_server, ebpf_proxy):
    # Test that updating the regex works correctly
    ebpf_proxy.sync_config({PORT: ".*APPLES.*"})
    time.sleep(1)
    
    # APPLES should be dropped
    assert send_payload(b"I love APPLES") in (None, b'')
    # ORANGES should pass
    assert send_payload(b"I love ORANGES") == b"I love ORANGES"
    
    # Update config
    ebpf_proxy.sync_config({PORT: ".*ORANGES.*"})
    time.sleep(1)
    
    # Now APPLES should pass
    assert send_payload(b"I love APPLES") == b"I love APPLES"
    # And ORANGES should be dropped
    assert send_payload(b"I love ORANGES") in (None, b'')

def test_dynamic_regex_removal(setup_echo_server, ebpf_proxy):
    # Setup dropping regex
    ebpf_proxy.sync_config({PORT: ".*BANANAS.*"})
    time.sleep(1)
    assert send_payload(b"I hate BANANAS") in (None, b'')
    
    # Remove all config
    ebpf_proxy.sync_config({})
    time.sleep(1)
    
    # Now the exact same payload should pass
    payload = b"I hate BANANAS"
    assert send_payload(payload) == payload

def test_short_payload(setup_echo_server, ebpf_proxy):
    # Edge case: Payload is extremely short, exact match of regex
    ebpf_proxy.sync_config({PORT: "BAD"})
    time.sleep(1)
    
    # Exactly matching string
    assert send_payload(b"BAD") in (None, b'')
    
    # Smaller string (should pass)
    assert send_payload(b"BA") == b"BA"

def test_case_sensitivity(setup_echo_server, ebpf_proxy):
    ebpf_proxy.sync_config({PORT: ".*SECRET.*"})
    time.sleep(1)
    
    # Exact match drops
    assert send_payload(b"this is a SECRET") in (None, b'')
    
    # Case mismatch passes (since regex is case sensitive by default)
    assert send_payload(b"this is a secret") == b"this is a secret"

