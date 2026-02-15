#!/usr/bin/env python3
"""
pool_exporter.py — Prometheus exporter for POOL metrics.

Reads POOL kernel module telemetry from /proc/pool/sessions and
/proc/pool/telemetry, then exposes it as Prometheus-compatible metrics
on an HTTP endpoint (default :9254/metrics).

Usage:
    python3 pool_exporter.py [--port 9254] [--interval 5]
"""

import argparse
import http.server
import os
import re
import sys
import time
import threading

DEFAULT_PORT = 9254
DEFAULT_INTERVAL = 5

PROC_SESSIONS = "/proc/pool/sessions"
PROC_TELEMETRY = "/proc/pool/telemetry"

# Metric storage
metrics = {}
metrics_lock = threading.Lock()


def parse_sessions():
    """Parse /proc/pool/sessions for session-level metrics."""
    result = []
    if not os.path.exists(PROC_SESSIONS):
        return result
    try:
        with open(PROC_SESSIONS, "r") as f:
            lines = f.readlines()
        for line in lines[1:]:  # skip header
            fields = line.split()
            if len(fields) < 8:
                continue
            result.append({
                "idx": fields[0],
                "state": fields[1],
                "peer_addr": fields[2],
                "packets_sent": int(fields[3]),
                "packets_recv": int(fields[4]),
                "bytes_sent": int(fields[5]),
                "bytes_recv": int(fields[6]),
                "rtt_us": int(fields[7]) if len(fields) > 7 else 0,
            })
    except (IOError, ValueError):
        pass
    return result


def parse_telemetry():
    """Parse /proc/pool/telemetry for global metrics."""
    result = {}
    if not os.path.exists(PROC_TELEMETRY):
        return result
    try:
        with open(PROC_TELEMETRY, "r") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()
                    try:
                        result[key] = float(val)
                    except ValueError:
                        result[key] = val
    except IOError:
        pass
    return result


def collect_metrics():
    """Collect all POOL metrics."""
    sessions = parse_sessions()
    telemetry = parse_telemetry()
    with metrics_lock:
        metrics["sessions"] = sessions
        metrics["telemetry"] = telemetry
        metrics["active_sessions"] = len(
            [s for s in sessions if s["state"] == "ESTABLISHED"]
        )
        metrics["total_packets_sent"] = sum(
            s["packets_sent"] for s in sessions
        )
        metrics["total_packets_recv"] = sum(
            s["packets_recv"] for s in sessions
        )
        metrics["total_bytes_sent"] = sum(s["bytes_sent"] for s in sessions)
        metrics["total_bytes_recv"] = sum(s["bytes_recv"] for s in sessions)


def format_prometheus():
    """Format metrics as Prometheus text exposition."""
    lines = []
    with metrics_lock:
        lines.append("# HELP pool_active_sessions Number of active POOL sessions")
        lines.append("# TYPE pool_active_sessions gauge")
        lines.append(f"pool_active_sessions {metrics.get('active_sessions', 0)}")
        lines.append("")

        lines.append("# HELP pool_packets_sent_total Total packets sent")
        lines.append("# TYPE pool_packets_sent_total counter")
        lines.append(
            f"pool_packets_sent_total {metrics.get('total_packets_sent', 0)}"
        )
        lines.append("")

        lines.append("# HELP pool_packets_recv_total Total packets received")
        lines.append("# TYPE pool_packets_recv_total counter")
        lines.append(
            f"pool_packets_recv_total {metrics.get('total_packets_recv', 0)}"
        )
        lines.append("")

        lines.append("# HELP pool_bytes_sent_total Total bytes sent")
        lines.append("# TYPE pool_bytes_sent_total counter")
        lines.append(
            f"pool_bytes_sent_total {metrics.get('total_bytes_sent', 0)}"
        )
        lines.append("")

        lines.append("# HELP pool_bytes_recv_total Total bytes received")
        lines.append("# TYPE pool_bytes_recv_total counter")
        lines.append(
            f"pool_bytes_recv_total {metrics.get('total_bytes_recv', 0)}"
        )
        lines.append("")

        # Per-session metrics
        for sess in metrics.get("sessions", []):
            labels = f'idx="{sess["idx"]}",peer="{sess["peer_addr"]}",state="{sess["state"]}"'

            lines.append("# HELP pool_session_rtt_microseconds Session RTT")
            lines.append("# TYPE pool_session_rtt_microseconds gauge")
            lines.append(
                f"pool_session_rtt_microseconds{{{labels}}} {sess['rtt_us']}"
            )
            lines.append("")

            lines.append(
                "# HELP pool_session_packets_sent Session packets sent"
            )
            lines.append("# TYPE pool_session_packets_sent counter")
            lines.append(
                f"pool_session_packets_sent{{{labels}}} {sess['packets_sent']}"
            )
            lines.append("")

            lines.append(
                "# HELP pool_session_packets_recv Session packets received"
            )
            lines.append("# TYPE pool_session_packets_recv counter")
            lines.append(
                f"pool_session_packets_recv{{{labels}}} {sess['packets_recv']}"
            )
            lines.append("")

        # Telemetry metrics
        tel = metrics.get("telemetry", {})
        for key, val in tel.items():
            if isinstance(val, (int, float)):
                safe_key = re.sub(r"[^a-zA-Z0-9_]", "_", key)
                lines.append(f"# TYPE pool_telemetry_{safe_key} gauge")
                lines.append(f"pool_telemetry_{safe_key} {val}")
                lines.append("")

    return "\n".join(lines) + "\n"


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for Prometheus /metrics endpoint."""

    def do_GET(self):
        if self.path == "/metrics":
            body = format_prometheus().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress request logs


def collector_loop(interval):
    """Background thread that periodically collects metrics."""
    while True:
        collect_metrics()
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        description="Prometheus exporter for POOL protocol metrics"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="HTTP port (default: 9254)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help="Collection interval in seconds (default: 5)",
    )
    args = parser.parse_args()

    print(f"POOL Prometheus exporter starting on :{args.port}")

    # Initial collection
    collect_metrics()

    # Background collector
    t = threading.Thread(target=collector_loop, args=(args.interval,), daemon=True)
    t.start()

    server = http.server.HTTPServer(("", args.port), MetricsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
