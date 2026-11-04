"""Run isolated loopback processes, benchmark rates, and exercise the runtime CLI."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
PORTS = (1080, 18080, 24443, 10085)


def require_free_ports():
    # Never reuse, attach to, or stop an existing user's lab process.
    for port in PORTS:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                raise RuntimeError(f"Port {port} is busy; stop that lab manually first") from error


def wait_ready(process, port):
    # Cold interpreter starts on hosted macOS can exceed ten seconds.
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Lab process exited with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Port {port} did not become ready")


def run(binary, size):
    require_free_ports()
    processes, logs, reports = [], [], []
    with tempfile.TemporaryDirectory(prefix="electrium-rate-") as temporary:
        folder = Path(temporary)
        node = json.loads((HERE / "node.example.json").read_text())
        client = json.loads((HERE / "client.example.json").read_text())
        identity = str(uuid.uuid4())
        node["inbounds"][0]["settings"]["clients"][0]["id"] = identity
        client["outbounds"][0]["settings"]["id"] = identity
        for name, data in (("node.json", node), ("client.json", client)):
            (folder / name).write_text(json.dumps(data), encoding="utf-8")

        def spawn(args, port):
            log = open(folder / f"process-{port}.log", "w+", encoding="utf-8")
            logs.append(log)
            process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            wait_ready(process, port)

        def api(command, *args, success=True):
            result = subprocess.run([str(binary), "api", command, "--server=127.0.0.1:10085", "--id=lab-account", *args],
                                    capture_output=True, text=True, timeout=10)
            if (result.returncode == 0) != success:
                raise RuntimeError(f"Unexpected API result: {result.stdout} {result.stderr}")
            return json.loads(result.stdout) if success else None

        def bench(direction="both", connections=2, success=True):
            result = subprocess.run([sys.executable, str(HERE / "bench_client.py"), "--bytes", str(size),
                                     "--connections", str(connections), "--direction", direction],
                                    capture_output=True, text=True, timeout=120)
            if (result.returncode == 0) != success:
                raise RuntimeError(f"Unexpected benchmark result: {result.stdout} {result.stderr}")
            return json.loads(result.stdout) if success else None

        def check_rates(report, down, up):
            for direction, expected in (("download", down), ("upload", up)):
                measured = report["aggregate_by_direction_Mbps"][direction]
                if not expected * 0.70 <= measured <= expected * 1.15:
                    raise RuntimeError(f"{direction}: {measured} Mbps, expected {expected} Mbps ± lab tolerance")
            reports.append(report)

        try:
            spawn([sys.executable, str(HERE / "http_bench.py"), "--port", "18080"], 18080)
            spawn([str(binary), "run", "-config", str(folder / "node.json")], 24443)
            spawn([str(binary), "run", "-config", str(folder / "client.json")], 1080)
            p = api("subscription-get")
            if int(p["revision"]) != 1:
                raise RuntimeError("Unexpected initial revision")
            check_rates(bench(), 10, 5)
            update = ("--expected-revision=1", "--revision=2", "--uplink-bps=312500", "--downlink-bps=625000", "--disabled=false")
            api("subscription-set", *update)
            api("subscription-set", *update)  # lost-response retry
            api("subscription-set", "--expected-revision=1", "--revision=2", "--uplink-bps=1", "--downlink-bps=1", "--disabled=false", success=False)
            check_rates(bench(connections=1), 5, 2.5)
            api("subscription-set", "--expected-revision=2", "--revision=3", "--uplink-bps=312500", "--downlink-bps=625000", "--disabled=true")
            bench(direction="download", connections=1, success=False)
            # An ordinary subscription API caller cannot restore unrestricted rates.
            # Rejecting this attempt must not advance the revision.
            api("subscription-set", "--expected-revision=3", "--revision=4", "--uplink-bps=0", "--downlink-bps=0", "--disabled=false", success=False)
            api("subscription-set", "--expected-revision=3", "--revision=4", "--uplink-bps=625000", "--downlink-bps=1250000", "--disabled=false")
            bench(direction="download", connections=1)
            print(json.dumps({"passed": True, "rates": reports, "runtime_retry_stale_disable_reenable": True, "unlimited_requires_admin": True}, indent=2))
        except BaseException:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read()[-2000:], file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            for log in logs:
                log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--bytes", type=int, default=2 * 1024 * 1024)
    args = parser.parse_args()
    if not 1024 * 1024 <= args.bytes <= 8 * 1024 * 1024:
        parser.error("--bytes must be 1..8 MiB per connection")
    binary = args.xray.resolve()
    if not binary.is_file():
        parser.error("--xray must point to the built lab executable")
    try:
        run(binary, args.bytes)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Lab failed: {error}\n")


if __name__ == "__main__":
    main()
