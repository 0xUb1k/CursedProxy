import argparse
import multiprocessing
import os
import sys
import time
import random
import statistics
import matplotlib

matplotlib.use('Agg')  # Fixes X11 authorization errors when running via sudo
import matplotlib.pyplot as plt
import iperf3
import subprocess

# Configuration defaults
DEFAULT_PORT = 5201
DEFAULT_TIME = 10
DEFAULT_WARMUP = 3
DEFAULT_PATTERN = ".*findme.*"
PROXY_CONF = "benchmark_proxy.conf"

SERVER_IP = "10.254.254.1"
CLIENT_IP = "10.254.254.2"
VETH_SERVER = "cproxy_veth0"
VETH_CLIENT = "cproxy_veth1"

def setup_veth_pair():
    print(f"Setting up veth pair: {VETH_SERVER} <-> {VETH_CLIENT}")
    subprocess.run(["ip", "link", "add", VETH_SERVER, "type", "veth", "peer", "name", VETH_CLIENT], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", f"{SERVER_IP}/24", "dev", VETH_SERVER], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", f"{CLIENT_IP}/24", "dev", VETH_CLIENT], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", VETH_SERVER, "up"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", VETH_CLIENT, "up"], check=True, stdout=subprocess.DEVNULL)
    # wait for interfaces to be fully ready
    time.sleep(1)

def teardown_veth_pair():
    subprocess.run(["ip", "link", "del", VETH_SERVER], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def run_iperf_server(port):
    """Run iperf3 server in an infinite loop."""
    while True:
        server = iperf3.Server()
        server.port = port
        server.bind_address = SERVER_IP
        server.run()
        # Clean up the server object to avoid state issues between connections
        del server


def run_iperf_client(port, duration, blksize=None):
    """Run iperf3 client and return bits per second."""
    cmd = ["iperf3", "-c", SERVER_IP, "-B", CLIENT_IP, "-p", str(port), "-t", str(duration), "-J"]
    if blksize:
        # Use TCP MSS (-M) to simulate small packets on the network without syscall overhead
        cmd.extend(["-M", str(blksize)])
        
    res = subprocess.run(cmd, capture_output=True, text=True)
    time.sleep(1)
    
    if res.returncode != 0:
        print(f"iperf3 client error: {res.stderr}")
        return 0
        
    try:
        import json
        data = json.loads(res.stdout)
        return data["end"]["sum_sent"]["bits_per_second"]
    except Exception as e:
        print(f"iperf3 json parsing error: {e}")
        return 0


def run_iperf_warmup(port, duration, blksize=None):
    """Short iperf3 run to warm up kernel caches."""
    cmd = ["iperf3", "-c", SERVER_IP, "-B", CLIENT_IP, "-p", str(port), "-t", str(duration), "-Z"]
    if blksize:
        cmd.extend(["-M", str(blksize)])
        
    res = subprocess.run(cmd, capture_output=True, text=True)
    time.sleep(1)
    
    if res.returncode != 0:
        print(f"iperf3 warmup error: {res.stderr}")


def create_proxy_conf(rules, port, conf_path):
    with open(conf_path, "w") as f:
        for rule in rules:
            f.write(f"{port}: {rule}\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark cursed-proxy eBPF Parsing Overhead")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help=f"iperf3 server port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--time", type=int, default=DEFAULT_TIME, help=f"iperf3 test duration in seconds (default: {DEFAULT_TIME})")
    parser.add_argument("-w", "--warmup", type=int, default=DEFAULT_WARMUP, help=f"warmup duration in seconds (default: {DEFAULT_WARMUP})")
    parser.add_argument("-r", "--runs", type=int, default=5, help="Number of times to run the suite for statistical significance (default: 5)")
    parser.add_argument("--pattern", type=str, default=DEFAULT_PATTERN, help=f"DFA pattern to benchmark (default: '{DEFAULT_PATTERN}')")
    parser.add_argument("--out-png", type=str, default="benchmark_results.png", help="Output PNG file for the chart")
    parser.add_argument("--out-txt", type=str, default="benchmark_results.txt", help="Output TXT file for the results")
    return parser.parse_args()


def plot_results(results, simulations, args):
    # Sort simulations back to canonical order since they were randomized
    labels = [sim["name"] for sim in simulations]

    fig, axes = plt.subplots(1, len(labels), figsize=(16, 6), sharey=True)
    if len(labels) == 1:
        axes = [axes]

    pastel_colors = ['#aec7e8', '#ffbb78', '#98df8a']

    # Calculate global max for padding text
    all_vals = [results["Baseline"].get(n, {}).get("mean", 0) / 1e9 for n in labels] + \
               [results["Proxy (No Rules)"].get(n, {}).get("mean", 0) / 1e9 for n in labels] + \
               [results["Proxy"].get(n, {}).get("mean", 0) / 1e9 for n in labels]
    global_max = max(all_vals) if all_vals else 1

    for i, sim_name in enumerate(labels):
        ax = axes[i]
        b_mean = results["Baseline"].get(sim_name, {}).get("mean", 0) / 1e9
        b_std = results["Baseline"].get(sim_name, {}).get("std", 0) / 1e9
        nr_mean = results["Proxy (No Rules)"].get(sim_name, {}).get("mean", 0) / 1e9
        nr_std = results["Proxy (No Rules)"].get(sim_name, {}).get("std", 0) / 1e9
        p_mean = results["Proxy"].get(sim_name, {}).get("mean", 0) / 1e9
        p_std = results["Proxy"].get(sim_name, {}).get("std", 0) / 1e9

        x_pos = [0, 0.6, 1.2]
        bars = ax.bar(x_pos, [b_mean, nr_mean, p_mean], yerr=[b_std, nr_std, p_std], color=pastel_colors, width=0.5, capsize=5)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(["Baseline", "Proxy\n(No Rules)", "Proxy\n(Rules)"])
        ax.set_xlim(-0.4, 1.6)

        ax.bar_label(bars, fmt='%.2f', padding=-20, fontsize=10, color='black', fontweight='bold')

        if b_mean > 0:
            diff_nr = ((nr_mean / b_mean) - 1) * 100
            diff_p = ((p_mean / b_mean) - 1) * 100
            ax.text(0.6, nr_mean + (global_max * 0.05) + nr_std, f"{diff_nr:+.1f}%", ha='center', va='bottom', color='#d62728', fontweight='bold')
            ax.text(1.2, p_mean + (global_max * 0.05) + p_std, f"{diff_p:+.1f}%", ha='center', va='bottom', color='#d62728', fontweight='bold')

        ax.set_title(sim_name)
        if i == 0:
            ax.set_ylabel("Throughput (Gbps)")

    fig.suptitle(f'cursed-proxy eBPF Parsing Overhead ({args.pattern})\nAggregated over {args.runs} runs', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(args.out_png, dpi=300, bbox_inches='tight')
    print(f"Plot saved successfully as '{args.out_png}'.")


def save_text_results(results, simulations, args):
    labels = [sim["name"] for sim in simulations]
    with open(args.out_txt, "w") as f:
        f.write("=== CURSED-PROXY BENCHMARK RESULTS ===\n\n")
        f.write(f"Pattern: {args.pattern}\n")
        f.write(f"Runs: {args.runs}\n\n")
        for sim_name in labels:
            b_val = results["Baseline"].get(sim_name, {}).get("mean", 0) / 1e9
            b_std = results["Baseline"].get(sim_name, {}).get("std", 0) / 1e9
            nr_val = results["Proxy (No Rules)"].get(sim_name, {}).get("mean", 0) / 1e9
            nr_std = results["Proxy (No Rules)"].get(sim_name, {}).get("std", 0) / 1e9
            p_val = results["Proxy"].get(sim_name, {}).get("mean", 0) / 1e9
            p_std = results["Proxy"].get(sim_name, {}).get("std", 0) / 1e9
            
            f.write(f"{sim_name}:\n")
            f.write(f"  Baseline:         {b_val:.2f} ± {b_std:.2f} Gbps\n")
            if b_val > 0:
                drop_nr = (1 - (nr_val / b_val)) * 100
                drop_p = (1 - (p_val / b_val)) * 100
                f.write(f"  Proxy (No Rules): {nr_val:.2f} ± {nr_std:.2f} Gbps (Drop: {drop_nr:.1f}%)\n")
                f.write(f"  Proxy (Rules):    {p_val:.2f} ± {p_std:.2f} Gbps (Drop: {drop_p:.1f}%)\n\n")
            else:
                f.write(f"  Proxy (No Rules): {nr_val:.2f} ± {nr_std:.2f} Gbps\n")
                f.write(f"  Proxy (Rules):    {p_val:.2f} ± {p_std:.2f} Gbps\n\n")
    print(f"Text results saved successfully as '{args.out_txt}'.")


def main():
    if os.geteuid() != 0:
        print("This script must be run as root to start cursed-proxy (eBPF).")
        sys.exit(1)

    args = parse_args()
    
    # Always clean up any existing broken veth state
    teardown_veth_pair()
    setup_veth_pair()

    print("Starting iperf3 server (multiprocessing)...")
    server_process = multiprocessing.Process(target=run_iperf_server, args=(args.port,), daemon=True)
    server_process.start()
    time.sleep(1)  # wait for server to bind and start

    try:
        simulations = [
            {"name": "Max (64KB)", "blksize": None},
            {"name": "4KB", "blksize": 4000},
            {"name": "256B", "blksize": 256},
            {"name": "88B", "blksize": 88},
        ]
        
        raw_results = {
            "Baseline": {s["name"]: [] for s in simulations},
            "Proxy (No Rules)": {s["name"]: [] for s in simulations},
            "Proxy": {s["name"]: [] for s in simulations},
        }

        print("Running global warm-up (discarded)...")
        run_iperf_warmup(args.port, args.warmup)

        for run in range(args.runs):
            print(f"\n--- Benchmark Run {run + 1}/{args.runs} ---")
            
            # Baseline
            print("Running baselines (no proxy)...")
            random.shuffle(simulations)
            for sim in simulations:
                print(f"  -> Baseline: {sim['name']}")
                bps = run_iperf_client(args.port, args.time, blksize=sim["blksize"])
                raw_results["Baseline"][sim["name"]].append(bps)

            # Proxy No Rules
            print("Running proxy (no rules)...")
            create_proxy_conf([], args.port, PROXY_CONF)
            proxy_cmd = [sys.executable, "-m", "cursed_proxy", "-c", PROXY_CONF, "-i", VETH_SERVER]
            proxy_proc = subprocess.Popen(proxy_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            
            random.shuffle(simulations)
            for sim in simulations:
                print(f"  -> Proxy (No Rules): {sim['name']}")
                bps = run_iperf_client(args.port, args.time, blksize=sim["blksize"])
                raw_results["Proxy (No Rules)"][sim["name"]].append(bps)
                
            # Proxy With Rules
            print(f"Running scenario: {args.pattern}")
            create_proxy_conf([args.pattern], args.port, PROXY_CONF)
            time.sleep(2)
            
            random.shuffle(simulations)
            for sim in simulations:
                print(f"  -> Proxy (With Rules): {sim['name']}")
                bps = run_iperf_client(args.port, args.time, blksize=sim["blksize"])
                raw_results["Proxy"][sim["name"]].append(bps)
                
            proxy_proc.terminate()
            proxy_proc.wait()
            
        # Process data
        # Sort simulations to canonical order for consistent output
        simulations = sorted(simulations, key=lambda x: {"Max (64KB)": 0, "4KB": 1, "256B": 2, "88B": 3}[x["name"]])
        results = {}
        for scenario, sims in raw_results.items():
            results[scenario] = {}
            for sim_name, vals in sims.items():
                if args.runs >= 3:
                    sorted_vals = sorted(vals)
                    # trimmed mean drops min and max if we have enough runs
                    if args.runs >= 5:
                        valid_vals = sorted_vals[1:-1]
                    else:
                        valid_vals = sorted_vals
                    mean = statistics.mean(valid_vals)
                    std = statistics.stdev(valid_vals) if len(valid_vals) > 1 else 0.0
                else:
                    mean = statistics.mean(vals) if vals else 0.0
                    std = 0.0
                results[scenario][sim_name] = {"mean": mean, "std": std}

    finally:
        print("Stopping iperf3 server...")
        server_process.terminate()
        server_process.join()
        if os.path.exists(PROXY_CONF):
            os.remove(PROXY_CONF)
        teardown_veth_pair()

    plot_results(results, simulations, args)
    save_text_results(results, simulations, args)


if __name__ == "__main__":
    main()
