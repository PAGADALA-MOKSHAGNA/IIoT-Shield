# blockchain_streamlit.py
# Streamlit IIoT -> Blockchain demo (CSV-first, aggressive parsing)
import threading
import time
import requests
import json
import random
import re
from datetime import datetime
from hashlib import sha256
from requests.auth import HTTPBasicAuth

import streamlit as st

# ---------- Configuration: Flask prediction URL (DO NOT CHANGE elsewhere) 

FLASK_PREDICT_URL_BASE = "http://172.29.150.145:5000"

# ---------- Blockchain classes ----------
class Block:
    def __init__(self, blockNo: int, data: dict, previous_hash: str = "0"):
        self.blockNo = blockNo
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.hash_value = None

    def compute_hash(self):
        h = sha256()
        payload = json.dumps({
            "blockNo": self.blockNo,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "timestamp": self.timestamp
        }, sort_keys=True, separators=(',', ':'))
        h.update(payload.encode('utf-8'))
        return h.hexdigest()

    def mine(self, difficulty=0, max_iter=100000):
        target_prefix = "0" * difficulty
        for i in range(max_iter):
            self.nonce = i
            h = self.compute_hash()
            if h.startswith(target_prefix):
                self.hash_value = h
                return True
        self.hash_value = self.compute_hash()
        return False

    def to_dict(self):
        return {
            "blockNo": self.blockNo,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "hash": self.hash_value or self.compute_hash()
        }

class Blockchain:
    def __init__(self, mining_difficulty=0):
        genesis = Block(0, {"genesis": True}, previous_hash="0")
        genesis.hash_value = genesis.compute_hash()
        self.chain = [genesis]
        self.lock = threading.Lock()
        self.mining_difficulty = mining_difficulty

    def last_block(self):
        return self.chain[-1]

    def add_block(self, block: Block):
        with self.lock:
            block.previous_hash = self.last_block().hash_value
            block.blockNo = self.last_block().blockNo + 1
            block.mine(difficulty=self.mining_difficulty, max_iter=200000)
            self.chain.append(block)

    def to_list(self):
        with self.lock:
            return [b.to_dict() for b in self.chain]

# ---------- CSV-based parsing configuration ----------
# CSV order in your dashboard (exact order requested)
CSV_FIELD_ORDER = [
    "Temperature_C",
    "Pressure_hPa",
    "Altitude_m",
    "AngleX",
    "AngleY",
    "AngleZ",
    "AccX_g",
    "AccY_g",
    "AccZ_g"
]

# ---------- Utility text helpers ----------
def _clean_text(s: str) -> str:
    if s is None:
        return ""
    # common artifacts
    s = s.replace('\xa0', ' ')
    s = s.replace('Â', '')
    # collapse whitespace
    return " ".join(s.split()).strip()

def _extract_span_by_id(html: str, span_id: str):
    pat = rf'<span[^>]\bid=["\']{re.escape(span_id)}["\'][^>]>(.*?)</span>'
    m = re.search(pat, html, re.IGNORECASE | re.DOTALL)
    if m:
        text = re.sub(r'<[^>]+>', '', m.group(1))
        return _clean_text(text)
    return None

def _to_floats_from_string(s: str):
    if not s:
        return []
    nums = re.findall(r'[+-]?[0-9]*\.?[0-9]+', s.replace(';', ','))
    try:
        return [float(x) for x in nums]
    except Exception:
        return []

# ---------- Aggressive CSV extraction ----------
def parse_csvline_aggressive(html_text: str):
    """
    Try multiple strategies (most to least strict) to find CSV numbers:
      1) <span id="csvline">...</span>
      2) 'Copy for ML Model' followed by numbers
      3) any sequence of at least 6-9 numbers separated by commas/spaces
    If found, map to CSV_FIELD_ORDER and return dict with only those named fields +
    'ml_input' and 'ml_input_csv'.
    Returns None if nothing found.
    """
    html = _clean_text(html_text or "")

    # 1) span id csvline
    csv_text = _extract_span_by_id(html_text, "csvline") or _extract_span_by_id(html_text, "csv")
    if csv_text:
        nums = _to_floats_from_string(csv_text)
        if nums:
            return _map_nums_to_fields(nums)

    # 2) Look for "Copy for ML Model" followed by numbers (flexible separators)
    m = re.search(r'Copy\s+for\s+ML\s+Model\s*[:\-]?\s*([0-9\-\.,\s]+)', html, re.IGNORECASE)
    if m:
        nums = _to_floats_from_string(m.group(1))
        if nums:
            return _map_nums_to_fields(nums)

    # 3) Generic: find sequences of numbers with separators; prefer runs of >=9 numbers
    candidate_runs = re.findall(r'([+-]?[0-9]\.?[0-9]+(?:[,\s]+[+-]?[0-9]\.?[0-9]+){4,})', html)
    best = None
    best_len = 0
    for run in candidate_runs:
        nums = _to_floats_from_string(run)
        if len(nums) > best_len:
            best = nums
            best_len = len(nums)
    if best and best_len >= 6:
        return _map_nums_to_fields(best)

    return None

def _map_nums_to_fields(nums):
    # Map to the CSV_FIELD_ORDER (use first N numbers)
    parsed = {}
    for i, field in enumerate(CSV_FIELD_ORDER):
        parsed[field] = round(nums[i], 6) if i < len(nums) else None
    parsed["ml_input"] = nums
    parsed["ml_input_csv"] = ",".join([str(x) for x in nums])
    return parsed

# ---------- Fetch helper that prefers csvline_aggressive ----------
def fetch_sensor_data(sensor_url: str, username: str = None, password: str = None, timeout=5):
    auth = None
    if username and password:
        auth = HTTPBasicAuth(username, password)

    # Try provided URL and the /predict alternate
    try_urls = [sensor_url]
    if sensor_url.rstrip('/').endswith('predict'):
        try_urls.append(sensor_url.rstrip('/predict'))
    else:
        if not sensor_url.rstrip('/').endswith('/'):
            try_urls.append(sensor_url.rstrip('/') + '/predict')
        else:
            try_urls.append(sensor_url.rstrip('/') + '/predict')

    last_exc = None
    for url in try_urls:
        try:
            r = requests.get(url, timeout=timeout, auth=auth)
            if r.status_code == 401:
                return {"from": "auth_error", "payload": {"error": "HTTP 401 Unauthorized - bad credentials"}}
            r.raise_for_status()

            # If JSON returned, and it already contains sensor keys, try to map to CSV fields or return JSON
            ctype = r.headers.get('content-type', '')
            text = r.text or ""
            if 'application/json' in ctype or text.strip().startswith('{'):
                try:
                    data = r.json()
                    # If JSON contains keys matching CSV_FIELD_ORDER, produce payload with those keys
                    if isinstance(data, dict) and any(k in data for k in CSV_FIELD_ORDER):
                        payload = {}
                        for f in CSV_FIELD_ORDER:
                            if f in data:
                                try:
                                    payload[f] = float(data[f])
                                except Exception:
                                    payload[f] = data[f]
                            else:
                                payload[f] = None
                        payload["ml_input_json"] = data
                        return {"from": "sensor_json_mapped", "payload": payload}
                    return {"from": "sensor_json", "payload": data}
                except Exception:
                    pass

            # HTML path: try aggressive csv extraction
            parsed_csv = parse_csvline_aggressive(text)
            if parsed_csv:
                return {"from": "sensor_csvline", "payload": parsed_csv}

            # If nothing parseable, try looser id-based parse as a last resort
            temp = _extract_span_by_id(text, "temp")
            pres = _extract_span_by_id(text, "pres")
            alt = _extract_span_by_id(text, "alt")
            ang = _extract_span_by_id(text, "ang")
            acc = _extract_span_by_id(text, "acc")
            fallback_payload = {}
            if temp:
                f = _to_floats_from_string(temp)
                if f: fallback_payload["Temperature_C"] = round(f[0], 6)
            if pres:
                f = _to_floats_from_string(pres)
                if f: fallback_payload["Pressure_hPa"] = round(f[0], 6)
            if alt:
                f = _to_floats_from_string(alt)
                if f: fallback_payload["Altitude_m"] = round(f[0], 6)
            if ang:
                f = _to_floats_from_string(ang)
                if len(f) >= 3:
                    fallback_payload["AngleX"], fallback_payload["AngleY"], fallback_payload["AngleZ"] = f[0], f[1], f[2]
            if acc:
                f = _to_floats_from_string(acc)
                if len(f) >= 3:
                    fallback_payload["AccX_g"], fallback_payload["AccY_g"], fallback_payload["AccZ_g"] = f[0], f[1], f[2]

            if fallback_payload:
                return {"from": "sensor_partial_ids", "payload": fallback_payload}

            last_exc = None
            break

        except requests.exceptions.RequestException as e:
            last_exc = e
            continue

    dummy = {
        "Temperature_C": round(20 + random.random() * 10, 2),
        "Pressure_hPa": round(980 + random.random() * 40, 2),
        "Altitude_m": None,
        "AngleX": None,
        "AngleY": None,
        "AngleZ": None,
        "AccX_g": None,
        "AccY_g": None,
        "AccZ_g": None,
        "note": f"fallback (err: {str(last_exc)[:120]})"
    }
    return {"from": "fallback", "payload": dummy}

# ---------- New: Aggregation function to merge ESP32 data and Flask model output ----------
def fetch_sensor_data_and_model_output(esp32_url: str, username: str = None, password: str = None, timeout=5):
    """
    Aggregates raw sensor data from ESP32 and model output from the Flask server.

    Steps:
      1) Fetch sensor JSON from esp32_url + "/data" using fetch_sensor_data with auth.
      2) If fetch_sensor_data returns 'auth_error' or 'fallback', return it immediately.
      3) Call Flask predict endpoint (FLASK_PREDICT_URL_BASE + "/predict") unauthenticated.
      4) Extract 'model_output' from Flask JSON and merge into the esp payload.
      5) Add 'model_source': 'Flask'. On Flask connection errors, add 'model_fetch_error' instead.
      6) Return {"from": "aggregated", "payload": merged_payload}
    """
    # Build the esp32 data endpoint
    esp_data_url = esp32_url.rstrip('/') + "/data"

    # 1) Fetch ESP32 data (may return wrappers like sensor_csvline, sensor_json, etc.)
    esp_result = fetch_sensor_data(esp_data_url, username=username, password=password, timeout=timeout)

    # 2) Immediate return on auth_error or fallback (as required)
    if isinstance(esp_result, dict) and esp_result.get("from") in ("auth_error", "fallback"):
        return esp_result

    # Ensure we have a payload dict to merge into
    merged_payload = {}
    if isinstance(esp_result, dict) and isinstance(esp_result.get("payload"), dict):
        merged_payload.update(esp_result.get("payload"))
    elif isinstance(esp_result, dict):
        # if esp_result is dict but doesn't have payload, try to use it directly
        merged_payload.update({k: v for k, v in esp_result.items() if k != "from"})
    else:
        # unexpected shape — return fallback-like error
        return {"from": "fallback", "payload": {"note": "unexpected esp_result shape"}}

    # 3) Fetch prediction from Flask (unauthenticated call per spec)
    try:
        flask_url = FLASK_PREDICT_URL_BASE.rstrip('/') + "/predict"
        r = requests.get(flask_url, timeout=timeout)
        r.raise_for_status()
        # Expect JSON; attempt to extract 'model_output'
        try:
            flask_json = r.json()
            # Primary key is 'model_output' — if present, take it
            if isinstance(flask_json, dict):
                if "model_output" in flask_json:
                    merged_payload["model_output"] = flask_json["model_output"]
                # in case Flask returns other key names, try common alternatives
                elif "prediction" in flask_json:
                    merged_payload["model_output"] = flask_json["prediction"]
                elif "label" in flask_json:
                    merged_payload["model_output"] = flask_json["label"]
                elif "model" in flask_json:
                    merged_payload["model_output"] = flask_json["model"]
                # If confidence present, keep it as well
                if "confidence" in flask_json:
                    merged_payload["model_confidence"] = flask_json["confidence"]
            else:
                # non-dict response — store as string
                merged_payload["model_output_raw"] = flask_json
            merged_payload["model_source"] = "Flask"
        except ValueError:
            # JSON parse error — record it
            merged_payload["model_source"] = "Flask"
            merged_payload["model_fetch_error"] = "Flask response not JSON"
    except requests.exceptions.RequestException as e:
        # Log error in payload but do not crash
        merged_payload["model_source"] = "Flask"
        merged_payload["model_fetch_error"] = str(e)[:200]

    # 5) Return aggregated wrapper
    return {"from": "aggregated", "payload": merged_payload}

# ---------- Background worker (poll & append) ----------
def polling_worker(sensor_url: str, interval: float, chain_key: str, stop_flag_key: str, username: str, password: str):
    global _thread_registry
    while True:
        if _thread_registry.get(stop_flag_key, False):
            break

        # CHANGE: use new aggregation function that merges ESP32 data and Flask model output
        data = fetch_sensor_data_and_model_output(sensor_url, username=username, password=password)

        bc: Blockchain = _thread_registry.get(chain_key)
        if bc is None:
            time.sleep(0.5)
            continue

        # Create block with payload exactly as returned by fetch_sensor_data_and_model_output()['payload']
        new_block = Block(blockNo=0, data=data)
        bc.add_block(new_block)

        slept = 0.0
        while slept < interval:
            if _thread_registry.get(stop_flag_key, False):
                break
            time.sleep(0.1)
            slept += 0.1

    _thread_registry[f"{stop_flag_key}_stopped"] = True

_thread_registry = {}

# ---------- Streamlit UI ----------
def main():
    st.set_page_config(page_title="IIoT Blockchain Demo (CSV-first)", layout="wide")
    st.title("IIoT → Blockchain demo (CSV-first payloads)")

    # Sidebar controls
    with st.sidebar:
        st.header("Settings")
        SENSOR_URL = st.text_input("Sensor base URL (ESP32)", value="http://172.29.150.152/")
        interval = st.number_input("Block interval (seconds)", min_value=1.0, max_value=60.0, value=5.0, step=1.0)
        difficulty = st.slider("Demo mining difficulty (leading hex zeros)", min_value=0, max_value=3, value=1)
        username = st.text_input("HTTP Basic Auth Username", value="Mokshagna")
        password = st.text_input("HTTP Basic Auth Password", value="MLG333", type="password")
        start = st.button("Start")
        stop = st.button("Stop")
        clear = st.button("Clear chain (keep genesis)")
        show_debug = st.checkbox("Show debug info (payload keys / source)", value=False)

    if "blockchain" not in st.session_state:
        st.session_state.blockchain = Blockchain(mining_difficulty=difficulty)
        st.session_state.thread_running = False
        st.session_state.thread_key = f"chain_{int(time.time() * 1000)}"
        st.session_state.stop_flag_key = f"stop_{int(time.time() * 1000)}"

    st.session_state.blockchain.mining_difficulty = difficulty

    if clear:
        st.session_state.blockchain = Blockchain(mining_difficulty=difficulty)
        st.success("Chain cleared (new genesis).")

    # Start worker
    if start and not st.session_state.thread_running:
        _thread_registry[st.session_state.thread_key] = st.session_state.blockchain
        _thread_registry[st.session_state.stop_flag_key] = False
        _thread_registry[f"{st.session_state.stop_flag_key}_stopped"] = False

        worker = threading.Thread(
            target=polling_worker,
            args=(SENSOR_URL, interval, st.session_state.thread_key, st.session_state.stop_flag_key, username, password),
            daemon=True
        )
        worker.start()
        st.session_state.thread_running = True
        st.success("Background polling started.")

    # Stop worker
    if stop and st.session_state.thread_running:
        _thread_registry[st.session_state.stop_flag_key] = True
        timeout = time.time() + 5
        while not _thread_registry.get(f"{st.session_state.stop_flag_key}_stopped", False) and time.time() < timeout:
            time.sleep(0.05)
        st.session_state.thread_running = False
        st.info("Background polling stopped.")

    # Status & latest block
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("Blocks", len(st.session_state.blockchain.chain))
        st.metric("Mining difficulty (hex zeros)", st.session_state.blockchain.mining_difficulty)
        running_text = "Yes" if st.session_state.thread_running else "No"
        st.write(f"Polling running: *{running_text}*")

    with col2:
        st.subheader("Latest Block (payload shows CSV fields when available)")
        latest = st.session_state.blockchain.last_block().to_dict()
        st.json(latest)

    st.markdown("---")
    st.subheader("Chain (newest last)")

    chain_list = st.session_state.blockchain.to_list()
    for b in chain_list:
        data_field = b.get("data")
        # normalize payload display (we expect data_field to be dict with 'from' and 'payload')
        payload = {}
        data_src = "unknown"
        if isinstance(data_field, dict):
            data_src = data_field.get("from", "sensor")
            if isinstance(data_field.get("payload"), dict):
                payload = data_field["payload"]
            else:
                payload = {k: v for k, v in data_field.items() if k != "from"}
        else:
            payload = {"value": data_field}

        # Ensure only CSV_FIELD_ORDER keys + ml_input/ml_input_csv are shown (if present)
        display_payload = {}
        for k in CSV_FIELD_ORDER:
            if k in payload:
                display_payload[k] = payload[k]
        if "ml_input" in payload:
            display_payload["ml_input"] = payload["ml_input"]
        if "ml_input_csv" in payload:
            display_payload["ml_input_csv"] = payload["ml_input_csv"]
        # include model_output/model_confidence or model_fetch_error if present
        if "model_output" in payload:
            display_payload["model_output"] = payload["model_output"]
        if "model_confidence" in payload:
            display_payload["model_confidence"] = payload["model_confidence"]
        if "model_fetch_error" in payload:
            display_payload["model_fetch_error"] = payload["model_fetch_error"]
        if "model_source" in payload:
            display_payload["model_source"] = payload["model_source"]

        with st.expander(f"Block {b['blockNo']} — {b['timestamp']}"):
            st.write("*Hash*:", b.get("hash"))
            st.write("*Previous Hash*:", b.get("previous_hash"))
            st.write("*Nonce*:", b.get("nonce"))
            if show_debug:
                st.write("DEBUG source:", data_src)
                if isinstance(payload, dict) and "note" in payload:
                    st.write("DEBUG note:", payload.get("note"))
            st.write("*Data source*:", data_src)
            st.json(display_payload)

    st.markdown("---")
    st.caption("Notes: This app aggressively extracts the CSV line (csvline or 'Copy for ML Model') and stores only the mapped CSV fields in each block's payload. Model output is fetched separately from Flask and merged.")

    # Auto-refresh while worker running
    if st.session_state.thread_running:
        st.info("Auto-refreshing to show new blocks...")
        time.sleep(1.0)
        if hasattr(st, "rerun"):
            st.rerun()
        elif hasattr(st, "experimental_rerun"):
            st.experimental_rerun()

if __name__ == "__main__":
    main()