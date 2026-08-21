import argparse
import multiprocessing
import os
import sys
import time
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


def run_iperf_server(port):
    """Run iperf3 server in an infinite loop."""
    while True:
        server = iperf3.Server()
        server.port = port
        server.run()
        # Clean up the server object to avoid state issues between connections
        del server


def run_iperf_client(port, duration, blksize=None):
    """Run iperf3 client and return bits per second."""
    cmd = ["iperf3", "-c", "127.0.0.1", "-p", str(port), "-t", str(duration), "-J"]
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
    cmd = ["iperf3", "-c", "127.0.0.1", "-p", str(port), "-t", str(duration), "-Z"]
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
    parser.add_argument("--pattern", type=str, default=DEFAULT_PATTERN, help=f"DFA pattern to benchmark (default: '{DEFAULT_PATTERN}')")
    parser.add_argument("--out-png", type=str, default="benchmark_results.png", help="Output PNG file for the chart")
    parser.add_argument("--out-txt", type=str, default="benchmark_results.txt", help="Output TXT file for the results")
    return parser.parse_args()


def plot_results(results, simulations, args):
    labels = [sim["name"] for sim in simulations]

    # We create subplots for each simulation. Sharing Y-axis as requested.
    fig, axes = plt.subplots(1, len(labels), figsize=(16, 6), sharey=True)
    if len(labels) == 1:
        axes = [axes]

    pastel_colors = ['#aec7e8', '#ffbb78', '#98df8a']  # Pastel Blue, Pastel Orange, Pastel Green

    # Calculate global max for padding text
    all_vals = [results["Baseline"].get(n, 0) / 1e9 for n in labels] + \
               [results["Proxy (No Rules)"].get(n, 0) / 1e9 for n in labels] + \
               [results["Proxy"].get(n, 0) / 1e9 for n in labels]
    global_max = max(all_vals) if all_vals else 1

    for i, sim_name in enumerate(labels):
        ax = axes[i]
        b_val = results["Baseline"].get(sim_name, 0) / 1e9
        nr_val = results["Proxy (No Rules)"].get(sim_name, 0) / 1e9
        p_val = results["Proxy"].get(sim_name, 0) / 1e9

        # Move bars closer together by specifying explicit, close X coordinates
        x_pos = [0, 0.6, 1.2]
        bars = ax.bar(x_pos, [b_val, nr_val, p_val], color=pastel_colors, width=0.5)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(["Baseline", "Proxy\n(No Rules)", "Proxy\n(Rules)"])

        # Set x limits to keep the grouped bars centered and looking thick/consistent
        ax.set_xlim(-0.4, 1.6)

        # Add labels inside bars
        ax.bar_label(bars, fmt='%.2f', padding=-15, fontsize=10, color='black', fontweight='bold')

        # Add percentage drop above the proxy bars
        if b_val > 0:
            diff_nr = ((nr_val / b_val) - 1) * 100
            diff_p = ((p_val / b_val) - 1) * 100
            ax.text(0.6, nr_val + (global_max * 0.02), f"{diff_nr:+.1f}%", ha='center', va='bottom', color='#d62728', fontweight='bold')
            ax.text(1.2, p_val + (global_max * 0.02), f"{diff_p:+.1f}%", ha='center', va='bottom', color='#d62728', fontweight='bold')

        ax.set_title(sim_name)

        if i == 0:
            ax.set_ylabel("Throughput (Gbps)")

    fig.suptitle(f'cursed-proxy eBPF Parsing Overhead ({args.pattern})', fontsize=14, fontweight='bold')
    plt.tight_layout()

    plt.savefig(args.out_png, dpi=300, bbox_inches='tight')
    print(f"Plot saved successfully as '{args.out_png}' in the current directory.")


def save_text_results(results, simulations, args):
    labels = [sim["name"] for sim in simulations]
    with open(args.out_txt, "w") as f:
        f.write("=== CURSED-PROXY BENCHMARK RESULTS ===\n\n")
        f.write(f"Pattern: {args.pattern}\n\n")
        for sim_name in labels:
            b_val = results["Baseline"].get(sim_name, 0) / 1e9
            nr_val = results["Proxy (No Rules)"].get(sim_name, 0) / 1e9
            p_val = results["Proxy"].get(sim_name, 0) / 1e9
            
            f.write(f"{sim_name}:\n")
            f.write(f"  Baseline:         {b_val:.2f} Gbps\n")
            if b_val > 0:
                drop_nr = (1 - (nr_val / b_val)) * 100
                drop_p = (1 - (p_val / b_val)) * 100
                f.write(f"  Proxy (No Rules): {nr_val:.2f} Gbps (Drop: {drop_nr:.1f}%)\n")
                f.write(f"  Proxy (Rules):    {p_val:.2f} Gbps (Drop: {drop_p:.1f}%)\n\n")
            else:
                f.write(f"  Proxy (No Rules): {nr_val:.2f} Gbps\n")
                f.write(f"  Proxy (Rules):    {p_val:.2f} Gbps\n\n")
    print(f"Text results saved successfully as '{args.out_txt}' in the current directory.")


def main():
    if os.geteuid() != 0:
        print("This script must be run as root to start cursed-proxy (eBPF).")
        sys.exit(1)

    args = parse_args()

    print("Starting iperf3 server (multiprocessing)...")
    server_process = multiprocessing.Process(target=run_iperf_server, args=(args.port,), daemon=True)
    server_process.start()
    time.sleep(1)  # wait for server to bind and start

    results = {}

    try:
        simulations = [
            {"name": "Max (64KB)", "blksize": None},
            {"name": "4KB", "blksize": 4000},
            {"name": "256B", "blksize": 256},
            {"name": "88B", "blksize": 88},
        ]

        # 1. Baselines
        print("Running baseline warm-up (discarded)...")
        run_iperf_warmup(args.port, args.warmup)

        print("Running baselines (no proxy)...")
        results["Baseline"] = {}
        for sim in simulations:
            print(f"  -> Baseline: {sim['name']}")
            bps = run_iperf_client(args.port, args.time, blksize=sim["blksize"])
            results["Baseline"][sim["name"]] = bps

        results["Proxy (No Rules)"] = {}
        results["Proxy"] = {}

        print("Running proxy (no rules)...")
        create_proxy_conf([], args.port, PROXY_CONF)

        # Start proxy using the module directly
        proxy_cmd = [sys.executable, "-m", "cursed_proxy", "-c", PROXY_CONF]
        proxy_proc = subprocess.Popen(proxy_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Give it time to compile DFA rules and load the eBPF program
        time.sleep(2)

        print("  -> Warming up proxy (discarded)...")
        run_iperf_warmup(args.port, args.warmup)

        for sim in simulations:
            print(f"  -> Simulation (No Rules): {sim['name']}")
            bps = run_iperf_client(args.port, args.time, blksize=sim["blksize"])
            results["Proxy (No Rules)"][sim["name"]] = bps

        print(f"Running scenario: {args.pattern}")
        create_proxy_conf([args.pattern], args.port, PROXY_CONF)
        
        # Give proxy time to detect config change and compile DFA
        time.sleep(2)

        for sim in simulations:
            print(f"  -> Simulation (With Rules): {sim['name']}")
            bps = run_iperf_client(args.port, args.time, blksize=sim["blksize"])
            results["Proxy"][sim["name"]] = bps

        # Stop proxy
        proxy_proc.terminate()
        proxy_proc.wait()

    finally:
        print("Stopping iperf3 server...")
        server_process.terminate()
        server_process.join()
        if os.path.exists(PROXY_CONF):
            os.remove(PROXY_CONF)

    plot_results(results, simulations, args)
    save_text_results(results, simulations, args)


if __name__ == "__main__":
    main()
