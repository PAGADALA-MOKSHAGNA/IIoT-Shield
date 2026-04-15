import streamlit as st
import requests
import serial
import json
import time
from threading import Thread

# ================= CONFIG =================
NODE_A_IP = "192.168.31.242"
NODE_B_IP = "192.168.31.187"

AUTH_A = ("Mokshagna", "MLG333")
AUTH_B = ("Mokshagna", "mokshagna@3")

SERIAL_PORT = "COM9"   # CHANGE THIS
BAUD_RATE = 115200

# ================= PAGE =================
st.set_page_config(layout="wide")
st.title("🛡️ IIoT SHIELD")
st.subheader("Intelligent Security Framework for Industrial IoT")

# ================= THEME IMAGE =================
col_top1, col_top2 = st.columns([3,1])
with col_top2:
    st.image("Cover Page Image.png", width=200)

# ================= FETCH =================
def get_data(ip, auth):
    try:
        res = requests.get(f"http://{ip}/status", auth=auth, timeout=2)
        return res.json()
    except:
        return {"status": "OFFLINE"}

# ================= IDS SERIAL =================
ids_logs = []
latest_ids = {"type": "INIT", "message": "Waiting...", "mac": "-"}

def read_ids_serial():
    global latest_ids

    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)

        while True:
            line = ser.readline().decode().strip()
            if line:
                try:
                    data = json.loads(line)
                    latest_ids = data
                    ids_logs.append(data)

                    if len(ids_logs) > 20:
                        ids_logs.pop(0)

                except:
                    pass
    except:
        latest_ids = {"type": "ERROR", "message": "IDS Not Connected", "mac": "-"}

Thread(target=read_ids_serial, daemon=True).start()

# ================= LAYOUT =================
colA, colB, colIDS = st.columns(3)

# -------- NODE A --------
with colA:
    st.markdown("### 🟢 Node A Stats")

    dataA = get_data(NODE_A_IP, AUTH_A)

    if dataA.get("status") == "ONLINE":
        st.metric("Temperature", f"{dataA.get('temperature',0)} °C")
        st.metric("Pressure", f"{dataA.get('pressure',0)} hPa")
        st.metric("Altitude", f"{dataA.get('altitude',0)} m")
        st.metric("Auth", dataA.get("auth","-"))
    else:
        st.error("Node A Offline")

# -------- NODE B --------
with colB:
    st.markdown("### 🔵 Node B Stats")

    dataB = get_data(NODE_B_IP, AUTH_B)

    if dataB.get("status") == "ONLINE":
        st.metric("Gas", dataB.get("gas",0))
        st.metric("Temperature", f"{dataB.get('temp',0)} °C")
        st.metric("Distance", f"{dataB.get('dist',0)} cm")
        st.metric("Auth", dataB.get("auth","-"))
    else:
        st.error("Node B Offline")

# -------- IDS PANEL --------
with colIDS:
    st.markdown("### 🔴 IDS Node Stats")

    st.metric("Event Type", latest_ids.get("type","-"))
    st.write("Message:", latest_ids.get("message","-"))
    st.write("MAC:", latest_ids.get("mac","-"))

    # Color indicator
    if latest_ids.get("type") in ["ROGUE", "FLOOD"]:
        st.error("⚠️ Threat Detected")
    elif latest_ids.get("type") == "NORMAL":
        st.success("System Normal")
    else:
        st.info("Monitoring...")

# ================= ATTACK CONTROLS =================
st.markdown("---")
st.markdown("## ⚡ Attack Simulation")

col1, col2 = st.columns(2)

with col1:
    if st.button("Simulate Replay"):
        try:
            requests.get(f"http://{NODE_A_IP}/auth", auth=AUTH_A)
            st.warning("Replay Attempt Sent")
        except:
            st.error("Failed")

with col2:
    if st.button("Simulate Flood"):
        try:
            for _ in range(10):
                requests.get(f"http://{NODE_A_IP}/auth", auth=AUTH_A)
            st.error("Flood Triggered")
        except:
            st.error("Failed")

# ================= IDS LOGS =================
st.markdown("---")
st.markdown("## 📜 IDS Live Logs")

for log in reversed(ids_logs[-10:]):
    st.write(log)

# ================= AUTO REFRESH =================
time.sleep(2)
st.rerun()