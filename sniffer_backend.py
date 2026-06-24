#!/usr/bin/env python3
"""
Visual Network Packet Sniffer - Backend
Uses Scapy for packet capture and Flask for the web dashboard.
Run with: sudo python3 sniffer_backend.py
"""

import threading
import time
import json
import logging
from datetime import datetime
from collections import deque
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

# Suppress Flask dev server warnings
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ── Scapy import (graceful fallback for environments without it) ──────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not installed. Running in DEMO mode with simulated packets.")
    print("          Install with:  pip install scapy")

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# ── Shared state ──────────────────────────────────────────────────────────────
MAX_PACKETS = 500          # Ring-buffer size
packets_store = deque(maxlen=MAX_PACKETS)
packet_id_counter = 0
sniff_thread = None
sniff_active = False
sniff_lock = threading.Lock()
stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}

# ── Packet processing ─────────────────────────────────────────────────────────

def process_packet(pkt):
    """Called by Scapy for every captured packet."""
    global packet_id_counter
    with sniff_lock:
        if not sniff_active:
            return

        packet_id_counter += 1
        now = datetime.now()

        record = {
            "id":        packet_id_counter,
            "timestamp": now.strftime("%H:%M:%S.%f")[:-3],
            "src_ip":    None,
            "dst_ip":    None,
            "protocol":  "OTHER",
            "src_port":  None,
            "dst_port":  None,
            "length":    len(pkt),
            "ttl":       None,
            "flags":     None,
            "payload":   None,
            "raw_summary": pkt.summary(),
        }

        if IP in pkt:
            record["src_ip"]  = pkt[IP].src
            record["dst_ip"]  = pkt[IP].dst
            record["ttl"]     = pkt[IP].ttl

        if TCP in pkt:
            record["protocol"] = "TCP"
            record["src_port"] = pkt[TCP].sport
            record["dst_port"] = pkt[TCP].dport
            record["flags"]    = str(pkt[TCP].flags)
            stats["tcp"] += 1
        elif UDP in pkt:
            record["protocol"] = "UDP"
            record["src_port"] = pkt[UDP].sport
            record["dst_port"] = pkt[UDP].dport
            stats["udp"] += 1
        elif ICMP in pkt:
            record["protocol"] = "ICMP"
            stats["icmp"] += 1
        else:
            stats["other"] += 1

        stats["total"] += 1

        # Extract printable payload (first 256 bytes)
        if Raw in pkt:
            try:
                raw_bytes = bytes(pkt[Raw].load)
                printable = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in raw_bytes[:256]
                )
                hex_dump = raw_bytes[:256].hex()
                record["payload"] = {"printable": printable, "hex": hex_dump}
            except Exception:
                pass

        packets_store.append(record)


def sniff_worker(iface, proto_filter):
    """Runs in a daemon thread; calls Scapy sniff() until flag cleared."""
    global sniff_active

    if not SCAPY_AVAILABLE:
        _demo_worker(iface, proto_filter)
        return

    # Build BPF filter string
    bpf_parts = []
    if proto_filter and proto_filter != "ALL":
        bpf_parts.append(proto_filter.lower())
    bpf = " or ".join(bpf_parts) if bpf_parts else None

    kwargs = dict(prn=process_packet, store=False)
    if iface and iface != "any":
        kwargs["iface"] = iface
    if bpf:
        kwargs["filter"] = bpf

    try:
        sniff(stop_filter=lambda _: not sniff_active, **kwargs)
    except Exception as e:
        print(f"[Scapy error] {e}")
    finally:
        with sniff_lock:
            sniff_active = False


# ── Demo / simulation mode ────────────────────────────────────────────────────
import random, ipaddress

_DEMO_IPS   = ["192.168.1." + str(i) for i in range(1, 20)] + ["8.8.8.8", "1.1.1.1", "172.217.3.110"]
_DEMO_PORTS = [80, 443, 22, 53, 8080, 3306, 5432, 8443, 25, 110, 143]

def _demo_worker(iface, proto_filter):
    """Generates realistic-looking fake packets for demo / no-root mode."""
    global sniff_active, packet_id_counter
    protos = ["TCP", "UDP", "ICMP"]
    if proto_filter and proto_filter != "ALL":
        protos = [proto_filter.upper()]

    payloads = [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
        b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03",  # TLS ClientHello prefix
        b"SSH-2.0-OpenSSH_8.9p1",
        b"\x00\x01\x00\x00\x00\x00\x00\x00",               # DNS query prefix
    ]

    while sniff_active:
        time.sleep(random.uniform(0.05, 0.35))
        if not sniff_active:
            break

        proto = random.choice(protos)
        src_ip = random.choice(_DEMO_IPS)
        dst_ip = random.choice(_DEMO_IPS)
        while dst_ip == src_ip:
            dst_ip = random.choice(_DEMO_IPS)

        packet_id_counter += 1
        now = datetime.now()

        record = {
            "id":        packet_id_counter,
            "timestamp": now.strftime("%H:%M:%S.%f")[:-3],
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "protocol":  proto,
            "src_port":  random.randint(1024, 65535) if proto != "ICMP" else None,
            "dst_port":  random.choice(_DEMO_PORTS)  if proto != "ICMP" else None,
            "length":    random.randint(40, 1500),
            "ttl":       random.choice([64, 128, 255]),
            "flags":     random.choice(["S", "SA", "A", "FA", "PA"]) if proto == "TCP" else None,
            "payload":   None,
            "raw_summary": f"[DEMO] {proto} {src_ip} → {dst_ip}",
        }

        if proto != "ICMP" and random.random() > 0.4:
            raw = random.choice(payloads)
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            record["payload"] = {"printable": printable, "hex": raw.hex()}

        with sniff_lock:
            if proto == "TCP":   stats["tcp"]   += 1
            elif proto == "UDP": stats["udp"]   += 1
            elif proto == "ICMP":stats["icmp"]  += 1
            else:                stats["other"] += 1
            stats["total"] += 1
            packets_store.append(record)


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/start", methods=["POST"])
def api_start():
    global sniff_thread, sniff_active
    data  = request.get_json(silent=True) or {}
    iface = data.get("interface", "any")
    proto = data.get("protocol",  "ALL")

    with sniff_lock:
        if sniff_active:
            return jsonify({"status": "already_running"})
        sniff_active = True

    sniff_thread = threading.Thread(
        target=sniff_worker, args=(iface, proto), daemon=True
    )
    sniff_thread.start()
    return jsonify({"status": "started", "demo": not SCAPY_AVAILABLE})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global sniff_active
    with sniff_lock:
        sniff_active = False
    return jsonify({"status": "stopped"})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    global packet_id_counter
    with sniff_lock:
        packets_store.clear()
        packet_id_counter = 0
        for k in stats:
            stats[k] = 0
    return jsonify({"status": "cleared"})


@app.route("/api/packets")
def api_packets():
    """Return packets, optionally filtered by protocol / IP."""
    since     = int(request.args.get("since",    0))
    proto_f   = request.args.get("protocol",  "").upper()
    ip_filter = request.args.get("ip",         "").strip()

    with sniff_lock:
        result = list(packets_store)

    if since:
        result = [p for p in result if p["id"] > since]
    if proto_f and proto_f != "ALL":
        result = [p for p in result if p["protocol"] == proto_f]
    if ip_filter:
        result = [
            p for p in result
            if ip_filter in (p.get("src_ip") or "") or ip_filter in (p.get("dst_ip") or "")
        ]

    return jsonify({"packets": result, "stats": stats, "running": sniff_active})


@app.route("/api/interfaces")
def api_interfaces():
    if SCAPY_AVAILABLE:
        ifaces = get_if_list()
    else:
        ifaces = ["eth0", "wlan0", "lo", "en0", "any"]
    return jsonify({"interfaces": ifaces, "demo": not SCAPY_AVAILABLE})


if __name__ == "__main__":
    print("=" * 60)
    print("  Visual Network Packet Sniffer")
    if not SCAPY_AVAILABLE:
        print("  [DEMO MODE — Scapy not installed]")
    else:
        print("  [LIVE MODE — requires root/sudo]")
    print("  Open http://127.0.0.1:49721  in your browser")
    print("=" * 60)
    app.run(host="0.0.0.0", port=49721, debug=False, threaded=True)
