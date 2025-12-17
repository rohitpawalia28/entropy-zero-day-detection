import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import math
from scapy.all import rdpcap
import os

# -------------------------------------------------
# Page Config
# -------------------------------------------------
st.set_page_config(page_title="Entropy-Based Zero-Day Detection", layout="wide")

st.title("Entropy-Driven Network Traffic Analysis")
st.subheader("Zero-Day Attack Detection System (NIS Project)")

st.markdown("""
This system performs **entropy-based anomaly detection** on network traffic
to identify **potential zero-day attacks**.
""")

# -------------------------------------------------
# Utility Functions
# -------------------------------------------------
def shannon_entropy(values):
    counter = Counter(values)
    total = sum(counter.values())
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def pcap_to_dataframe(pcap_path):
    packets = rdpcap(pcap_path)
    data = []

    for pkt in packets:
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst
            proto = pkt["IP"].proto
            length = len(pkt)

            src_port = None
            dst_port = None
            if pkt.haslayer("TCP"):
                src_port = pkt["TCP"].sport
                dst_port = pkt["TCP"].dport
            elif pkt.haslayer("UDP"):
                src_port = pkt["UDP"].sport
                dst_port = pkt["UDP"].dport

            data.append([src_ip, dst_ip, src_port, dst_port, proto, length])

    return pd.DataFrame(
        data,
        columns=["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_length"]
    )

def compute_baseline(df, window_size=100):
    features = ["src_ip", "dst_ip", "src_port", "dst_port", "packet_length"]
    values = {f: [] for f in features}

    for i in range(0, len(df), window_size):
        w = df.iloc[i:i+window_size]
        if len(w) == window_size:
            values["src_ip"].append(shannon_entropy(w["src_ip"]))
            values["dst_ip"].append(shannon_entropy(w["dst_ip"]))
            values["src_port"].append(shannon_entropy(w["src_port"].fillna(0)))
            values["dst_port"].append(shannon_entropy(w["dst_port"].fillna(0)))
            values["packet_length"].append(shannon_entropy(w["packet_length"]))

    baseline = {}
    for f, v in values.items():
        mean = sum(v) / len(v)
        std = (sum((x-mean)**2 for x in v) / len(v))**0.5
        baseline[f] = {"mean": mean, "std": std}

    return baseline

def detect_anomalies(df, baseline, window_size=100):
    alerts = []

    for i in range(0, len(df), window_size):
        w = df.iloc[i:i+window_size]
        if len(w) == window_size:
            ent = {
                "src_ip": shannon_entropy(w["src_ip"]),
                "dst_ip": shannon_entropy(w["dst_ip"]),
                "src_port": shannon_entropy(w["src_port"].fillna(0)),
                "dst_port": shannon_entropy(w["dst_port"].fillna(0)),
                "packet_length": shannon_entropy(w["packet_length"])
            }

            for f, val in ent.items():
                if abs(val - baseline[f]["mean"]) > 2 * baseline[f]["std"]:
                    alerts.append({
                        "Window": i // window_size,
                        "Feature": f,
                        "Entropy": round(val, 3),
                        "Status": "ANOMALY"
                    })

    return pd.DataFrame(alerts)

# -------------------------------------------------
# MODE SELECTOR
# -------------------------------------------------
st.markdown("### 🔀 Select Analysis Mode")

mode = st.radio(
    "Choose traffic source:",
    ["Demo Mode (Preloaded CSV)", "User Upload Mode (PCAP/PCAPNG)"]
)

# -------------------------------------------------
# DATA LOADING BASED ON MODE
# -------------------------------------------------
df = None

if mode == "Demo Mode (Preloaded CSV)":
    st.info("Using preloaded CSV traffic for demonstration.")
    import pathlib
    BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
    CSV_PATH = BASE_DIR / "data" / "processed_csv" / "normal_traffic.csv"
    df = pd.read_csv(CSV_PATH)


else:
    uploaded = st.file_uploader(
        "Upload PCAP or PCAPNG file",
        type=["pcap", "pcapng"]
    )

    if uploaded:
        temp = f"temp_{uploaded.name}"
        with open(temp, "wb") as f:
            f.write(uploaded.read())

        df = pcap_to_dataframe(temp)
        os.remove(temp)

        st.success("PCAP file processed successfully")

# -------------------------------------------------
# ANALYSIS PIPELINE
# -------------------------------------------------
if df is not None:

    st.info(f"Total packets loaded: {len(df)}")
    WINDOW_SIZE = 100

    # -------- Entropy Graphs --------
    st.markdown("### 📊 Entropy Visualization")

    src_ent, dst_ent = [], []
    for i in range(0, len(df), WINDOW_SIZE):
        w = df.iloc[i:i+WINDOW_SIZE]
        if len(w) == WINDOW_SIZE:
            src_ent.append(shannon_entropy(w["src_ip"]))
            dst_ent.append(shannon_entropy(w["dst_ip"]))

    col1, col2 = st.columns(2)

    with col1:
        fig, ax = plt.subplots(figsize=(5,4))
        ax.plot(src_ent)
        ax.set_title("Source IP Entropy")
        st.pyplot(fig)

    with col2:
        fig, ax = plt.subplots(figsize=(5,4))
        ax.plot(dst_ent)
        ax.set_title("Destination IP Entropy")
        st.pyplot(fig)

    # -------- Anomaly Detection --------
    st.markdown("### 🚨 Anomaly Detection Output")

    baseline = compute_baseline(df)
    alerts = detect_anomalies(df, baseline)

    if alerts.empty:
        st.success("No anomalies detected.")
    else:
        st.error("Anomalies detected!")
        st.dataframe(alerts)

else:
    st.warning("Please select a mode and load traffic data.")
