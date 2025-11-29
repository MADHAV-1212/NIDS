# app.py
# Live IDS dashboard (Streamlit) for your AI agents

import time
from pathlib import Path
from dataclasses import dataclass

import numpy as np
import pandas as pd
import streamlit as st
from joblib import load
import plotly.express as px
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from pathlib import Path
import pandas as pd
import streamlit as st
# --- Simple topology/semantics mapping ---

SERVICE_TO_ZONE = {
    # DMZ-facing
    "http": "DMZ", "https": "DMZ", "www": "DMZ",
    "smtp": "DMZ", "pop_3": "DMZ",

    # R&D-ish
    "ssh": "R&D", "rshell": "R&D", "imap4": "R&D",

    # Corporate-ish
    "domain_u": "Corporate", "eco_i": "Corporate", "ftp_data": "Corporate",

    # OT-ish (rare in NSL-KDD; we’ll bucket “other” here to demo variety)
    "other": "OT", "ntp_u": "OT"
}

ZONE_TO_DEPT = {
    "DMZ": "DMZ",
    "R&D": "R&D",
    "Corporate": "Corporate",
    "OT": "Production/OT"
}

# fallback helpers
def map_zone(service: str) -> str:
    s = (service or "").lower()
    return SERVICE_TO_ZONE.get(s, "Corporate")  # default Corporate for stability

def map_dept(zone: str) -> str:
    return ZONE_TO_DEPT.get(zone, "Corporate")


# ---------- Paths / constants ----------
ART = Path("artifacts")
DATA = Path("data")
COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent',
    'hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
    'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

# ---------- Cache loaders ----------
@st.cache_resource
def load_models():
    rf  = load(ART / "nslkdd_rf_pipeline.joblib")
    ann = load(ART / "nslkdd_ann_pipeline.joblib")
    return rf, ann

@st.cache_resource
def load_test():
    df_test = pd.read_csv(DATA / "KDDTest+.txt", names=COLS)

    # --- Map attack labels into general attack classes ---
    label_to_class = {
        "neptune": "DoS", "smurf": "DoS", "back": "DoS", "teardrop": "DoS", "pod": "DoS", "land": "DoS",
        "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
        "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "phf": "R2L",
        "warezclient": "R2L", "warezmaster": "R2L",
        "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R"
    }

    def map_label_to_class(lbl):
        if lbl == "normal":
            return "normal"
        return label_to_class.get(lbl, "Other")

    df_test["attack_class"] = df_test["label"].apply(map_label_to_class)

    X_test = df_test.drop(columns=["label", "difficulty"])
    y_test = (df_test["label"] != "normal").astype(int).values
# enrich topology fields
    if "service" in df_test.columns:
        df_test["zone"] = df_test["service"].apply(map_zone)
        df_test["dept"] = df_test["zone"].apply(map_dept)
    else:
        df_test["zone"] = "Corporate"
        df_test["dept"] = "Corporate"

    # (optional) coarser readable class
    def coarse_class(lbl: str) -> str:
        if lbl == "normal": return "Normal"
        s = str(lbl).lower()
        if "dos"   in s: return "DoS"
        if "probe" in s: return "Probe"
        if "r2l"   in s: return "R2L"
        if "u2r"   in s: return "U2R"
        return "Attack"
    df_test["attack_class"] = df_test["label"].apply(coarse_class)

    return df_test, X_test, y_test


# ---------- Agent data classes ----------
# -------- Agent data classes --------
from dataclasses import dataclass

@dataclass
class Packet:
    index: int
    features: pd.Series
    true_label: int


# -------- Capture agent --------
class CaptureAgent:
    def __init__(self, X, y):
        self.X = X.reset_index(drop=True)
        self.y = pd.Series(y).reset_index(drop=True)
        self.ptr = 0

    def fetch(self, n=200):
        """Return next n packets as a list; wraps at end."""
        if self.ptr >= len(self.X):
            self.ptr = 0
        end = min(self.ptr + n, len(self.X))
        batch_idx = list(range(self.ptr, end))
        self.ptr = end
        return [Packet(i, self.X.iloc[i], int(self.y.iloc[i])) for i in batch_idx]


# -------- Analysis agent --------
class AnalysisAgent:
    def __init__(self, model, threshold=0.5):
        self.model = model
        self.threshold = threshold

    def analyze(self, packets: list[Packet]):
        if not packets:
            return []

        Xb = pd.DataFrame([p.features for p in packets])
        probs = self.model.predict_proba(Xb)[:, 1]
        preds = (probs >= self.threshold).astype(int)

        df_test = st.session_state.df_test  # reference table by index

        rows = []
        for p, pr, pd_ in zip(packets, probs, preds):
            idx = p.index
            service = df_test.loc[idx, "service"] if "service" in df_test.columns else ""
            label   = df_test.loc[idx, "label"]   if "label"   in df_test.columns else ""
            aclass  = df_test.loc[idx, "attack_class"] if "attack_class" in df_test.columns else ""
            zone    = df_test.loc[idx, "zone"]    if "zone"    in df_test.columns else ""
            dept    = df_test.loc[idx, "dept"]    if "dept"    in df_test.columns else ""

            rows.append({
                "index": idx,
                "prob":  float(pr),
                "pred":  int(pd_),
                "true":  int(p.true_label),
                "service": service,
                "zone": zone,
                "dept": dept,
                "label": label,
                "attack_class": aclass,
            })

        return rows


# -------- Manager agent --------
# -------- Manager agent --------
class ManagerAgent:
    def __init__(self, alert_threshold=0.9):
        self.alert_threshold = alert_threshold
        self.rows = []  # Store analysis results as rows

    def ingest(self, rows):
        self.rows.extend(rows)

    @property
    def df(self):
        # Return all collected rows as a DataFrame
        return pd.DataFrame(self.rows) if self.rows else pd.DataFrame(
            columns=["index", "prob", "pred", "true", "service", "zone", "dept", "label", "attack_class"]
        )

    @property
    def alerts(self):
        # Return rows considered alerts based on threshold
        df = self.df
        if df.empty:
            return df
        return df[df["prob"] >= self.alert_threshold].copy()


# ---------- UI ----------
st.set_page_config(page_title="AI Agent NIDS", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Agent Network Intrusion Detection — Live Dashboard")
# --- Interactive topology (Plotly) ---
import networkx as nx
import plotly.graph_objects as go

# Minimal topology definition (customize nodes/edges to match your real layout)
# Node ids must match how you choose to map services -> nodes below
TOPO_NODES = [
    ("Cambridge-Router", (0, 0)),
    ("Cambridge-SwitchA", (-0.8, -1.2)),
    ("Cambridge-SwitchB", (0.8, -1.2)),
    ("London-Router", (3.0, 0)),
    ("London-SwitchA", (2.2, -1.2)),
    ("Manchester-Router", (6.0, 0)),
    ("Manchester-SwitchA", (5.2, -1.2)),
]
TOPO_EDGES = [
    ("Cambridge-Router", "Cambridge-SwitchA"),
    ("Cambridge-Router", "Cambridge-SwitchB"),
    ("Cambridge-Router", "London-Router"),
    ("London-Router", "London-SwitchA"),
    ("London-Router", "Manchester-Router"),
    ("Manchester-Router", "Manchester-SwitchA"),
]

# A mapping from alert "service" (or zone/department) to a topology node id.
# Customize these keys to match your dataset (service names or zones).
# A mapping from alert "service" (or zone/department) to a topology node id.
# Keys MUST be lowercased because we call str(svc).lower() when looking them up.
SERVICE_TO_NODE = {
    # DMZ / corporate web services -> Cambridge switch A
    "http": "Cambridge-SwitchA",
    "https": "Cambridge-SwitchA",
    "www": "Cambridge-SwitchA",

    # mail -> Cambridge switch B (example)
    "smtp": "Cambridge-SwitchB",
    "pop_3": "Cambridge-SwitchB",
    "imap4": "Cambridge-SwitchB",

    # R&D-ish / ssh -> Cambridge SwitchB
    "ssh": "Cambridge-SwitchB",
    "rshell": "Cambridge-SwitchB",

    # Corporate data -> London switch
    "ftp_data": "London-SwitchA",
    "domain_u": "London-Router",
    "eco_i": "London-Router",

    # OT / other -> Manchester
    "other": "Manchester-SwitchA",
    "ntp_u": "Manchester-SwitchA",

    # fallback keys you may see in your df
    "probe": "Cambridge-SwitchA",
    "dos": "Cambridge-Router",
    "r2l": "London-SwitchA",
    "u2r": "Manchester-Router",
}
# ---- mapping + helpers ----
def service_to_node_id(service: str) -> str:
    """Map a service name (e.g., 'smtp') to a topology node id; fallback to London-Router."""
    if not service:
        return "London-Router"
    return SERVICE_TO_NODE.get(str(service).lower(), "London-Router")


def compute_topo_counts(alert_df: pd.DataFrame, window_span: int = 800) -> tuple[dict, set]:
    if alert_df is None or alert_df.empty:
        return {}, set()

    df = alert_df.copy()

    if "service" in df.columns:
        df["node_id"] = df["service"].map(service_to_node_id)
    else:
        df["node_id"] = "London-Router"  # fallback

    max_idx = int(df["index"].max())
    recent_mask = df["index"].astype(int) >= max(0, max_idx - window_span)

    counts = df.groupby("node_id")["prob"].count().to_dict()
    recent_nodes = set(df.loc[recent_mask, "node_id"].unique())
    return counts, recent_nodes



def draw_topology(topo_counts: dict | None = None, recent_nodes: set | None = None):
    """
    Build a small Plotly graph of your topology.
    - Node color = alert count severity (blue→yellow→orange→red).
    - Node size 'pulses' (bigger) if it fired in the recent window this tick.
    """
    topo_counts = topo_counts or {}
    recent_nodes = recent_nodes or set()

    # positions from your TOPO_NODES list like: [("Cambridge-Router",(0,0)), ...]
    pos = {name: coords for (name, coords) in TOPO_NODES}

    # edges
    edge_x, edge_y = [], []
    for a, b in TOPO_EDGES:
        x0, y0 = pos[a]; x1, y1 = pos[b]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    # nodes
    def sev_to_color(c: int) -> str:
        if c >= 9: return "#cc0000"   # red
        if c >= 4: return "#ff7f0e"   # orange
        if c >= 1: return "#ffd94d"   # yellow
        return "#a6bddb"              # light blue

    node_x, node_y, node_text, node_size, node_color = [], [], [], [], []
    for name, (x, y) in pos.items():
        c = int(topo_counts.get(name, 0))
        node_x.append(x); node_y.append(y)
        node_text.append(f"{name}<br>alerts: {c}")
        node_size.append(20 if name in recent_nodes else 12)
        node_color.append(sev_to_color(c))

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=edge_x, y=edge_y, mode="lines",
            line=dict(width=2, color="#999"), hoverinfo="skip"
        )
    )
    fig.add_trace(
        go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            text=[n for n in pos.keys()],
            textposition="bottom center",
            marker=dict(size=node_size, color=node_color, line=dict(width=1, color="#222")),
            hovertext=node_text, hoverinfo="text",
        )
    )

    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        height=260,
        showlegend=False,  # hides trace legend
    )

    return fig   # <-- make sure this line is indented at same level as fig.update_layout


# draw current topology using manager alerts (if exist)
alerts_df = (
    st.session_state.manager.alerts
    if "manager" in st.session_state else pd.DataFrame()
)

st.subheader("Network Topology (live)")
topo_area = st.empty()          # one placeholder only
# topo_area.empty()             # optional; you can comment this out

# initial paint (safe even if no alerts yet)
alerts_df = st.session_state.manager.alerts if "manager" in st.session_state else pd.DataFrame()

rf, ann = load_models()
df_test, X_test, y_test = load_test()
st.session_state.df_test = df_test  # so AnalysisAgent can look up service/label/attack_class

with st.sidebar:
    st.header("⚙️ Controls")
    model_choice = st.selectbox("Model", ["Random Forest", "ANN (MLP)"])
    use_model = rf if model_choice == "Random Forest" else ann

    # helpful defaults: RF ~0.10 best F1; ANN ~0.10 (from your sweep)
    decision_th = st.slider("Decision threshold (attack)", 0.01, 0.99, 0.10, 0.01)
    alert_th    = st.slider("Alert threshold (display)", 0.50, 0.99, 0.90, 0.01)
    batch_size  = st.slider("Batch size (packets/tick)", 50, 1000, 300, 50)
    tick_delay  = st.slider("Tick delay (seconds)", 0.0, 1.0, 0.3, 0.1)
    clear_btn   = st.button("Clear session")
    start_btn   = st.button("Start / Step")
    auto_run    = st.checkbox("Auto-run", value=False)

# choose model by sidebar selection
use_model = rf if model_choice == "Random Forest" else ann

# --- initialize agents ONCE, else update live ---
if ("capture" not in st.session_state) or clear_btn:
    st.session_state.capture = CaptureAgent(X_test, y_test)
    st.session_state.manager = ManagerAgent(alert_threshold=float(alert_th))
    st.session_state.analysis = AnalysisAgent(use_model, threshold=float(decision_th))

    # for service/label/attack_class access inside the agent
    st.session_state.df_test = df_test

    # history with all columns you will use later
    st.session_state.history = pd.DataFrame(
        columns=["index", "prob", "pred", "true", "service", "zone", "dept", "label", "attack_class"]
    )


else:
    # live updates without clearing
    st.session_state.analysis.model = use_model
    st.session_state.analysis.threshold = float(decision_th)
    st.session_state.manager.alert_threshold = float(alert_th)

    # re-evaluate predictions so metrics & alert counts react instantly
    hist = st.session_state.history
    if not hist.empty and "prob" in hist.columns:
        st.session_state.history.loc[:, "pred"] = (
            hist["prob"] >= float(decision_th)
        ).astype(int)

# tiny safety guard in case Streamlit reruns mid-initialize
if "capture" not in st.session_state:
    st.stop()
    
# --- Top status cards (live) ---
c1, c2, c3 = st.columns(3)

with c1:
    st.subheader("CaptureAgent")
    st.metric("Packets total", len(X_test))
    st.metric("Pointer", st.session_state.capture.ptr)

with c2:
    st.subheader("AnalysisAgent")
    st.metric("Model", model_choice)
    st.metric("Decision th", decision_th)

with c3:
    st.subheader("ManagerAgent")
    st.metric("Alert th", alert_th)
    st.metric("Alerts so far", len(st.session_state.manager.alerts))


# --- Live chart + tables containers (keep these above the function) ---
chart_area = st.empty()
alert_area = st.empty()
table_area = st.empty()


def step_once():
    # 1) fetch + analyze one tick
    batch = st.session_state.capture.fetch(batch_size)
    st.toast(f"Stepping {len(batch)} packets…", icon="▶️")
    rows  = st.session_state.analysis.analyze(batch)
    st.session_state.manager.ingest(rows)

    # 2) accumulate history
    if rows:
        st.session_state.history = pd.concat(
            [st.session_state.history, pd.DataFrame(rows)],
            ignore_index=True
        )

    hist = st.session_state.history
    if hist.empty:
        return

    # 3) line chart of probabilities
    fig = px.line(hist, x="index", y="prob", title="Attack Probability over Packet Index")
    fig.add_hline(y=decision_th, line_dash="dash", line_color="orange", annotation_text="decision th")
    fig.add_hline(y=alert_th,    line_dash="dash", line_color="red",    annotation_text="alert th")
    chart_area.plotly_chart(fig, use_container_width=True)

    # 4) live metrics at current decision threshold
    p = hist["pred"].astype(int)
    y = hist["true"].astype(int)
    prec = precision_score(y, p, zero_division=0)
    rec  = recall_score(y, p, zero_division=0)
    f1   = f1_score(y, p, zero_division=0)

    m1, m2, m3 = st.columns(3)
    m1.metric("Precision", f"{prec:.2f}")
    m2.metric("Recall",    f"{rec:.2f}")
    m3.metric("F1-score",  f"{f1:.2f}")

    # 5) confusion matrix (cumulative)
    cm = confusion_matrix(y, p)
    st.write("Confusion matrix (cumulative):")
    st.dataframe(pd.DataFrame(
        cm,
        index   = ["True Normal (0)", "True Attack (1)"],
        columns = ["Pred Normal (0)", "Pred Attack (1)"]
    ))
# --- alert distribution + recent table ---
alert_df = st.session_state.manager.alerts.sort_values("prob", ascending=False)

# update live topology with current alerts
topo_counts, recent_nodes = compute_topo_counts(alert_df, window_span=400)
fig_topo = draw_topology(topo_counts, recent_nodes)
topo_area.plotly_chart(fig_topo, use_container_width=True)   # <-- no key

# A) Dept/Zone split + Recent Alerts table
if not alert_df.empty:
    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by department")
        if "dept" in alert_df.columns:
            st.bar_chart(alert_df["dept"].value_counts())
        else:
            st.caption("No 'dept' in alerts yet.")
    with right:
        st.subheader("Alerts by zone")
        if "zone" in alert_df.columns:
            st.bar_chart(alert_df["zone"].value_counts())
        else:
            st.caption("No 'zone' in alerts yet.")

    table_area.subheader("Recent Alerts (top 300)")
    table_area.dataframe(alert_df.head(300), use_container_width=True)
else:
    table_area.info("No alerts yet at this threshold.")

# B) Alert-class summary chart (guarded)
if (not alert_df.empty) and ("attack_class" in alert_df.columns):
    class_counts = (
        alert_df["attack_class"]
        .value_counts()
        .rename_axis("attack_class")
        .reset_index(name="count")
    )
    alert_area.subheader("Alert classes (counts)")
    alert_area.bar_chart(class_counts.set_index("attack_class"))
else:
    alert_area.info("No alert-class data yet (no alerts or 'attack_class' missing).")

# C) Download + optional auto-save  (ONE copy only)
st.download_button(
    label="Download alerts as CSV",
    data=alert_df.to_csv(index=False).encode("utf-8"),
    file_name="alerts_detected.csv",
    mime="text/csv",
    key="download_alerts_main",
)
save_alerts = st.sidebar.checkbox(
    "Auto-save alerts to artifacts/alerts_live.csv", value=False
)
if save_alerts and not alert_df.empty:
    out = ART / "alerts_live.csv"
    alert_df.to_csv(out, index=False)

# D) Top services among alerts (guarded)
if not alert_df.empty:
    idx = alert_df["index"].astype(int).clip(0, len(df_test) - 1).values
    svc = df_test.loc[idx, ["service", "protocol_type"]].copy()
    svc["prob"] = alert_df["prob"].values
    top = (
        svc.groupby("service")["prob"]
        .count()
        .sort_values(ascending=False)
        .head(10)
        .reset_index(name="count")
    )
    st.subheader("Top services among alerts")
    st.bar_chart(top.set_index("service"))

# E) Recent packets table (always safe)
table_area.subheader("Recent Packets (last 300)")
hist = st.session_state.history if "history" in st.session_state else pd.DataFrame()
if not hist.empty:
    table_area.dataframe(hist.tail(300), use_container_width=True)
else:
    table_area.info("No packet history yet — press Start / Step.")

# === RUN CONTROL ===
if start_btn or auto_run:
    if auto_run:
        for _ in range(10):
            step_once()
            time.sleep(tick_delay)
            st.experimental_rerun()
    else:
        step_once()
# ==========================
# 🔍 FEATURE IMPORTANCE VIEW
# ==========================

ART = Path("artifacts")

st.subheader("🔎 Random Forest Feature Importance")

@st.cache_data
def load_rf_importance(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Keep only what we need and pretty-print
    cols = ["feature", "importance_mean", "importance_std"]
    df = df[cols].copy()
    df["importance_mean"] = df["importance_mean"].round(6)
    df["importance_std"]  = df["importance_std"].round(6)
    return df.sort_values("importance_mean", ascending=False)

try:
    fi = load_rf_importance(ART / "rf_permutation_importance.csv")
    top = fi.head(15)
    st.dataframe(top.reset_index(drop=True), use_container_width=True)

    st.bar_chart(
        top.set_index("feature")["importance_mean"],
        use_container_width=True,
    )
    st.caption("Permutation importance based on decrease in model score (higher = more important).")

except FileNotFoundError:
    st.warning("⚠️ No feature importance file found. Please run the training notebook to create `rf_permutation_importance.csv` in `/artifacts`.")
