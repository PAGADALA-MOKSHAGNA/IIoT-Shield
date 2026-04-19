import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import streamlit as st

# ================= CONFIG =================
NODE_A_IP = "192.168.31.242"
NODE_B_IP = "192.168.31.187"
IDS_NODE_URL = "http://192.168.31.47"

AUTH_A = ("Mokshagna", "MLG333")
AUTH_B = ("Mokshagna", "mokshagna@3")

REQUEST_TIMEOUT = 2
AUTO_REFRESH_SECONDS = 2
FLOOD_REQUEST_COUNT = 30
FLOOD_WORKERS = 10

NODES = {
    "Node A": {
        "ip": NODE_A_IP,
        "auth": AUTH_A,
        "status_path": "/status",
        "attack_path": "/cram",
        "description": "BMP280 + MPU6050 node",
    },
    "Node B": {
        "ip": NODE_B_IP,
        "auth": AUTH_B,
        "status_path": "/status",
        "attack_path": "/cram",
        "description": "Secondary ESP32 node",
    },
}


def build_node_url(ip, path):
    return f"http://{ip}{path}"


def normalize_endpoint(endpoint):
    cleaned = endpoint.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    return cleaned.rstrip("/")


def default_ids_event(message="Waiting..."):
    return {
        "type": "INIT",
        "message": message,
        "node": "-",
        "mac": "-",
        "peer": "-",
        "direction": "-",
        "time": 0,
    }


def normalize_ids_event(event):
    normalized = default_ids_event()
    if isinstance(event, dict):
        normalized.update(event)
    return normalized


def default_ids_connection(endpoint):
    return {
        "transport": "HTTP",
        "status": "OFFLINE",
        "endpoint": endpoint or "-",
        "ip": "-",
        "wifi": "-",
        "channel": "-",
        "uptime_ms": "-",
        "sniffing": False,
        "error": "Waiting for IDS node",
    }


def fetch_json(url, auth=None):
    response = requests.get(url, auth=auth, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()


def get_data(ip, auth):
    try:
        return fetch_json(build_node_url(ip, "/status"), auth=auth)
    except (requests.RequestException, ValueError):
        return {"status": "OFFLINE"}


def get_ids_snapshot(endpoint):
    endpoint = normalize_endpoint(endpoint)
    connection = default_ids_connection(endpoint)
    cached = st.session_state.get("ids_http_cache")

    if not endpoint:
        return default_ids_event("Enter the IDS node endpoint"), [], connection

    try:
        status_payload = fetch_json(f"{endpoint}/status")
        latest = normalize_ids_event(status_payload.get("latest", {}))

        connection.update(
            {
                "status": "ONLINE",
                "endpoint": endpoint,
                "ip": status_payload.get("ip", "-"),
                "wifi": status_payload.get("wifi", "-"),
                "channel": status_payload.get("channel", "-"),
                "uptime_ms": status_payload.get("uptime_ms", "-"),
                "sniffing": status_payload.get("sniffing", False),
                "error": "-",
            }
        )

        logs = []
        try:
            logs_payload = fetch_json(f"{endpoint}/logs")
            logs = [
                normalize_ids_event(item)
                for item in logs_payload.get("logs", [])
            ]
        except (requests.RequestException, ValueError) as exc:
            connection["error"] = f"Logs endpoint unavailable: {exc}"
            if cached:
                logs = list(cached.get("logs", []))

        if not logs:
            logs = [latest]

        logs = logs[-20:]
        snapshot = {
            "latest": latest,
            "logs": logs,
            "connection": dict(connection),
        }
        st.session_state["ids_http_cache"] = snapshot
        return latest, logs, connection
    except (requests.RequestException, ValueError) as exc:
        connection["error"] = str(exc)
        if cached:
            cached_connection = dict(cached.get("connection", {}))
            cached_connection.update(
                {
                    "status": "OFFLINE",
                    "endpoint": endpoint or cached_connection.get("endpoint", "-"),
                    "error": str(exc),
                }
            )
            return (
                normalize_ids_event(cached.get("latest", {})),
                list(cached.get("logs", [])),
                cached_connection,
            )
        return default_ids_event("IDS HTTP endpoint unreachable"), [], connection


def send_request(url, auth, params=None):
    try:
        response = requests.get(url, auth=auth, params=params, timeout=REQUEST_TIMEOUT)
        return {
            "ok": True,
            "status_code": response.status_code,
            "body": response.text.strip(),
        }
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status_code": None,
            "body": str(exc),
        }


def run_replay_attack(node_name):
    node = NODES[node_name]
    nonce = secrets.token_hex(8).upper()
    url = build_node_url(node["ip"], node["attack_path"])

    first = send_request(url, node["auth"], params={"nonce": nonce})
    second = send_request(url, node["auth"], params={"nonce": nonce})

    return {
        "type": "Replay",
        "target": node_name,
        "endpoint": url,
        "nonce": nonce,
        "first_status": first["status_code"],
        "second_status": second["status_code"],
        "detected": second["status_code"] == 403,
        "details": second["body"] or first["body"],
    }


def run_flood_attack(node_name, request_count):
    node = NODES[node_name]
    url = build_node_url(node["ip"], node["attack_path"])
    status_counts = {}
    error_count = 0
    first_error = ""

    def send_flood_request():
        nonce = secrets.token_hex(8).upper()
        return send_request(url, node["auth"], params={"nonce": nonce})

    started_at = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(FLOOD_WORKERS, request_count)) as executor:
        futures = [executor.submit(send_flood_request) for _ in range(request_count)]

        for future in as_completed(futures):
            result = future.result()
            status_code = result["status_code"]

            if status_code is None:
                error_count += 1
                if not first_error:
                    first_error = result["body"]
                continue

            status_counts[status_code] = status_counts.get(status_code, 0) + 1

    duration = round(time.perf_counter() - started_at, 2)

    return {
        "type": "Flood",
        "target": node_name,
        "endpoint": url,
        "request_count": request_count,
        "duration_s": duration,
        "status_counts": status_counts,
        "error_count": error_count,
        "details": first_error,
    }


def render_attack_result():
    report = st.session_state.get("attack_report")
    if not report:
        return

    st.markdown("### Last Attack Result")

    if report["type"] == "Replay":
        if report["detected"]:
            st.error(
                f"Replay detected on {report['target']} using nonce {report['nonce']} "
                f"({report['first_status']} -> {report['second_status']})."
            )
        else:
            st.warning(
                f"Replay response from {report['target']} was "
                f"{report['first_status']} -> {report['second_status']}."
            )
        st.write("Endpoint:", report["endpoint"])
        st.write("Response:", report["details"] or "-")
        return

    status_counts = ", ".join(
        f"{status}: {count}"
        for status, count in sorted(report["status_counts"].items())
    )
    if not status_counts:
        status_counts = "No HTTP responses"

    st.error(
        f"Flood burst sent to {report['target']} "
        f"({report['request_count']} requests in {report['duration_s']}s)."
    )
    st.write("Endpoint:", report["endpoint"])
    st.write("HTTP Status Counts:", status_counts)
    st.write("Errors:", report["error_count"])
    if report["details"]:
        st.write("First Error:", report["details"])


# ================= PAGE =================
st.set_page_config(layout="wide")
st.title("IIoT SHIELD")
st.subheader("Intelligent Security Framework for Industrial IoT")

if "attack_report" not in st.session_state:
    st.session_state["attack_report"] = None

with st.sidebar:
    st.markdown("### IDS Settings")
    ids_endpoint_input = st.text_input(
        "IDS Node Endpoint",
        value=st.session_state.get("ids_endpoint_input", IDS_NODE_URL),
    )
    st.caption(
        "Use the IP shown by the ESP32 Promiscuous IDS node, "
        "for example 192.168.31.240."
    )

st.session_state["ids_endpoint_input"] = ids_endpoint_input

col_top1, col_top2 = st.columns([3, 1])
with col_top2:
    st.image("Cover Page Image.png", width=200)

latest_ids, ids_logs, ids_connection = get_ids_snapshot(ids_endpoint_input)

# ================= LAYOUT =================
colA, colB, colIDS = st.columns(3)

with colA:
    st.markdown("### Node A Stats")
    dataA = get_data(NODE_A_IP, AUTH_A)

    if dataA.get("status") == "ONLINE":
        st.metric("Temperature", f"{dataA.get('temperature', 0)} C")
        st.metric("Pressure", f"{dataA.get('pressure', 0)} hPa")
        st.metric("Altitude", f"{dataA.get('altitude', 0)} m")
        st.metric("Auth", dataA.get("auth", "-"))
    else:
        st.error("Node A Offline")

with colB:
    st.markdown("### Node B Stats")
    dataB = get_data(NODE_B_IP, AUTH_B)

    if dataB.get("status") == "ONLINE":
        st.metric("Gas", dataB.get("gas", 0))
        st.metric("Temperature", f"{dataB.get('temp', 0)} C")
        st.metric("Distance", f"{dataB.get('dist', 0)} cm")
        st.metric("Auth", dataB.get("auth", "-"))
    else:
        st.error("Node B Offline")

with colIDS:
    st.markdown("### IDS Node Stats")
    st.metric("Event Type", latest_ids.get("type", "-"))
    st.write("Transport:", ids_connection.get("transport", "HTTP"))
    st.write("Connection:", ids_connection.get("status", "OFFLINE"))
    st.write("Endpoint:", ids_connection.get("endpoint", "-"))
    st.write("IDS IP:", ids_connection.get("ip", "-"))
    st.write("WiFi:", ids_connection.get("wifi", "-"))
    st.write("Channel:", ids_connection.get("channel", "-"))
    st.write("Sniffing:", "Yes" if ids_connection.get("sniffing") else "No")
    st.write("Message:", latest_ids.get("message", "-"))
    st.write("Node:", latest_ids.get("node", "-"))
    st.write("MAC:", latest_ids.get("mac", "-"))
    st.write("Peer:", latest_ids.get("peer", "-"))
    st.write("Direction:", latest_ids.get("direction", "-"))

    if ids_connection.get("status") != "ONLINE":
        st.warning(f"IDS HTTP unavailable: {ids_connection.get('error', '-')}")

    if latest_ids.get("type") in {"REPLAY", "FLOOD"}:
        st.error("Threat Detected")
    elif latest_ids.get("type") == "NORMAL":
        st.success("System Normal")
    else:
        st.info("Monitoring...")

# ================= ATTACK CONTROLS =================
st.markdown("---")
st.markdown("## Attack Simulation")
st.caption(
    "Replay sends the same CRAM nonce twice to the selected node. "
    "Flood sends many unique CRAM requests quickly so the IDS can observe a burst."
)

attack_target = st.radio("Target Node", tuple(NODES.keys()), horizontal=True)
flood_count = st.number_input(
    "Flood Request Count",
    min_value=10,
    max_value=100,
    value=FLOOD_REQUEST_COUNT,
    step=5,
)

col1, col2 = st.columns(2)

with col1:
    if st.button("Launch Replay Attack", use_container_width=True):
        st.session_state["attack_report"] = run_replay_attack(attack_target)

with col2:
    if st.button("Launch Flood Attack", use_container_width=True):
        st.session_state["attack_report"] = run_flood_attack(
            attack_target,
            int(flood_count),
        )

render_attack_result()

# ================= IDS LOGS =================
st.markdown("---")
st.markdown("## IDS Live Logs")

for log in reversed(ids_logs[-10:]):
    st.write(log)

# ================= AUTO REFRESH =================
time.sleep(AUTO_REFRESH_SECONDS)
st.rerun()
