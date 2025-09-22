import pandas as pd
from joblib import load
import nmap 

# ---- Config ----
PORTS = [21,22,23,80,443,3389,3306,1433,27017,502,161]
VENDORS = ["Growatt","Fronius","Huawei","Sungrow","Generic"]
HIGH_RISK_PORTS = {23,3389,21,3306,1433,27017}

# ---- Port to Service Mapping ----
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    3306: "MySQL",
    1433: "MSSQL",
    27017: "MongoDB",
    502: "Modbus",
    161: "SNMP"
}

# ---- Load model ----
clf = load(r"path_inverter_rf.joblib") #add the model path
feature_cols = load(r"path_feature_columns.joblib") #add the model path

def build_features_from_portlist(open_ports_list, vendor="Generic", max_cvss=5.0):
    feat = {}
    for p in PORTS:
        feat[f"p_{p}"] = 1 if p in open_ports_list else 0
    feat["num_open_ports"] = sum(feat[f"p_{p}"] for p in PORTS)
    feat["high_risk_count"] = sum(1 for p in open_ports_list if p in HIGH_RISK_PORTS)
    feat["max_cvss"] = max_cvss
    for v in VENDORS:
        col = "vendor_" + v
        feat[col] = 1 if vendor == v else 0
    return pd.DataFrame([feat])[feature_cols]

def scan_ports(ip, vendor="Generic", max_cvss=5.0):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-p " + ",".join(str(p) for p in PORTS))
    open_ports = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            if nm[ip][proto][port]['state'] == 'open':
                open_ports.append(port)
    return build_features_from_portlist(open_ports, vendor, max_cvss), open_ports

if __name__ == "__main__":
    target_ip = "127.0.0.1"   # change to device/container IP
    vendor = "Generic"
    max_cvss = 9.0

    features, open_ports = scan_ports(target_ip, vendor, max_cvss)

    prob = clf.predict_proba(features)[0,1]
    pred = clf.predict(features)[0]

    # Pretty-print ports with names
    open_ports_named = [f"{p} - {PORT_SERVICE_MAP.get(p, 'Unknown')}" for p in open_ports]

    print("Scanned device:", target_ip)
    print("open_ports: ", open_ports_named)
    print(f"Vendor: {vendor}, Max CVSS: {max_cvss}")
    print("Prediction:", "VULNERABLE" if pred==1 else "SAFE", f"(prob={prob:.3f})")

    # ---- Reasons for classification ----
    reasons = []
    if features["p_3389"].iloc[0] == 1: reasons.append("3389 (RDP) open")
    if features["p_23"].iloc[0] == 1: reasons.append("23 (Telnet) open")
    if features["p_21"].iloc[0] == 1: reasons.append("21 (FTP) open")
    if features["high_risk_count"].iloc[0] >= 2: reasons.append(f"{int(features['high_risk_count'].iloc[0])} high-risk ports open")
    if features["max_cvss"].iloc[0] >= 8.0: reasons.append("max CVSS ≥ 8.0")

    if reasons:
        print("Reasons:", "; ".join(reasons))
    else:
        print("Reasons: No critical ports or risks detected.")
