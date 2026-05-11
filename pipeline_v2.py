import pandas as pd
import ipaddress
import re

print("RUNNING pipeline.py")

# 1) Load the cicids file 
data = pd.read_csv("cicids.csv", low_memory=False)
data.columns = data.columns.astype(str).str.strip()


required_columns = ["Timestamp", "Source IP", "Destination IP", "Label"]

for col in required_columns:
    if col not in data.columns:
        raise ValueError(f"missing required column: {col}")

alerts = data.copy()
alerts.rename(
    columns={
        "Source IP": "Source_IP",
        "Destination IP": "Destination_IP",
        "Destination Port": "Destination_Port"
    },
    inplace=True
)

alerts["Timestamp"] = pd.to_datetime(alerts["Timestamp"], errors="coerce")
alerts["Label"] = alerts["Label"].astype(str).str.strip()




# 2) Load Spamhaus DROP list 
drop_ranges = []
with open("spamhouse_drop.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", line)
        if m:
            try:
                drop_ranges.append(ipaddress.ip_network(m.group(1), strict=False))
            except ValueError:
                pass

def in_drop(ip):
    try:
        ip_obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return 0
    for net in drop_ranges:
        if ip_obj in net:
            return 1
    return 0

# 3) Enrichment: TI_Score for every row 
alerts["TI_Flag"] = alerts["Source_IP"].apply(in_drop)
alerts["TI_Score"] = alerts["TI_Flag"] * 5

#Asset criticality
critical_ports = {
    80: 4,      # Web server
    443: 4,     # HTTPS service
    53: 4,      # DNS
    22: 3,      # SSH
    3389: 4,    # RDP
    445: 5,     # SMB / Windows file sharing
    1433: 5,    # SQL Server
    3306: 5     # MySQL
}

def asset_criticality(row):
    score = 2  # default standard system

    dest_ip = str(row.get("Destination_IP", ""))
    dest_port = row.get("Destination_Port", None)

    # Known CICIDS internal server-style destination seen in your output
    if dest_ip.startswith("192.168.10."):
        score = max(score, 3)

    try:
        port = int(dest_port)
        if port in critical_ports:
            score = max(score, critical_ports[port])
    except:
        pass

    return score

alerts["Asset_Criticality"] = alerts.apply(asset_criticality, axis=1)



#Exposure
source_stats = alerts.groupby("Source_IP").agg(
    Unique_Destinations=("Destination_IP", "nunique"),
    Flow_Count=("Destination_IP", "count")
).reset_index()
if "Destination_Port" in alerts.columns:
    port_stats = alerts.groupby("Source_IP").agg(
        Unique_Ports=("Destination_Port", "nunique")
    ).reset_index()
    source_stats = source_stats.merge(port_stats, on="Source_IP", how="left")
else:
    source_stats["Unique_Ports"] = 0

alerts = alerts.merge(source_stats, on="Source_IP", how="left")

def exposure_score(row):
    unique_destinations = row.get("Unique_Destinations", 0)
    unique_ports = row.get("Unique_Ports", 0)
    flow_count = row.get("Flow_Count", 0)

    score = 1

    if unique_destinations >= 5:
        score += 1
    if unique_ports >= 10:
        score += 1
    if flow_count >= 100:
        score += 1
    if flow_count >= 1000:
        score += 1

    return min(score, 5)

alerts["Exposure_Blast_Radius"] = alerts.apply(exposure_score, axis=1)


#threat impact score
def safe_numeric(series_name):
    if series_name in alerts.columns:
        return pd.to_numeric(alerts[series_name], errors="coerce").fillna(0)
    return pd.Series([0] * len(alerts))

flow_duration = safe_numeric("Flow Duration")
fwd_packets = safe_numeric("Total Fwd Packets")
bwd_packets = safe_numeric("Total Backward Packets")
fwd_length = safe_numeric("Total Length of Fwd Packets")
bwd_length = safe_numeric("Total Length of Bwd Packets")

alerts["Total_Packets"] = fwd_packets + bwd_packets
alerts["Total_Bytes"] = fwd_length + bwd_length
alerts["Flow_Duration"] = flow_duration

def threat_impact(row):
    score = 1

    packets = row.get("Total_Packets", 0)
    total_bytes = row.get("Total_Bytes", 0)
    duration = row.get("Flow_Duration", 0)
    unique_ports = row.get("Unique_Ports", 0)
    flow_count = row.get("Flow_Count", 0)

    # Port scanning style behaviour: many ports contacted
    if unique_ports >= 10:
        score = max(score, 2)

    # High volume behaviour: possible DoS/DDoS style impact
    if packets >= 1000 or total_bytes >= 1_000_000:
        score = max(score, 4)

    # Very high flow count from a source: operational concern
    if flow_count >= 1000:
        score = max(score, 4)

    # Very short high-packet/byte flows may indicate flood behaviour
    if duration > 0 and packets >= 500:
        packets_per_second = packets / (duration / 1_000_000)
        if packets_per_second > 1000:
            score = max(score, 5)

    return min(score, 5)

alerts["Threat_Impact_Potential"] = alerts.apply(threat_impact, axis=1)




#Risk score
alerts["Risk_Score"] = (
    (alerts["Asset_Criticality"] * 2)
    + (alerts["Threat_Impact_Potential"] * 3)
    + (alerts["Exposure_Blast_Radius"] * 2)
    + (alerts["TI_Score"] * 3)
)

def recommendation(score):
    if score >= 30:
        return "High Priority - Containment / Escalation"
    elif score >= 20:
        return "Medium Priority - Investigation"
    elif score >= 12:
        return "Low Priority - Monitor"
    else:
        return "No Immediate Action / Log"

alerts["Recommendation"] = alerts["Risk_Score"].apply(recommendation)



#Evaluation
alerts["Ground_Truth_Attack"] = (
    alerts["Label"].str.lower() != "benign"
).astype(int)

# Use first 80% for threshold selection, last 20% for testing
split_index = int(len(alerts) * 0.8)

train = alerts.iloc[:split_index].copy()
test = alerts.iloc[split_index:].copy()

best_threshold = None
best_f1 = -1

possible_thresholds = sorted(train["Risk_Score"].unique())

def calculate_metrics(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    accuracy = (tp + tn) / max((tp + tn + fp + fn), 1)
    precision = tp / max((tp + fp), 1)
    recall = tp / max((tp + fn), 1)
    f1 = 2 * precision * recall / max((precision + recall), 1e-9)

    return accuracy, precision, recall, f1, tp, tn, fp, fn

for threshold in possible_thresholds:
    pred = (train["Risk_Score"] >= threshold).astype(int)
    acc, prec, rec, f1, tp, tn, fp, fn = calculate_metrics(
        train["Ground_Truth_Attack"], pred
    )

    if f1 > best_f1:
        best_f1 = f1
        best_threshold = threshold

test["Predicted_Attack"] = (test["Risk_Score"] >= best_threshold).astype(int)

accuracy, precision, recall, f1, tp, tn, fp, fn = calculate_metrics(
    test["Ground_Truth_Attack"], test["Predicted_Attack"]
)





# OUTPUT
out = alerts.sort_values("Risk_Score", ascending=False)

print("\nPREVIEW (top 20):")
print(out[["Timestamp", "Source_IP", "Destination_IP", "Label",
           "Asset_Criticality", "Threat_Impact_Potential",
           "Exposure_Blast_Radius", "TI_Score", "Risk_Score",
           "Recommendation"]].head(20))

out.to_csv("prioritised_alerts.csv", index=False)
print("\nSaved: prioritised_alerts.csv")

#output
output_columns = [
    "Timestamp",
    "Source_IP",
    "Destination_IP",
    "Label",
    "Asset_Criticality",
    "Threat_Impact_Potential",
    "Exposure_Blast_Radius",
    "TI_Score",
    "Risk_Score",
    "Recommendation",
    "Ground_Truth_Attack",
    "Predicted_Attack"
]

available_output_columns = [col for col in output_columns if col in alerts.columns]

prioritised = alerts.sort_values("Risk_Score", ascending=False)
prioritised[available_output_columns].to_csv("prioritised_alerts_v2.csv", index=False)

with open("evaluation_results.txt", "w") as f:
    f.write("AIRR Framework Evaluation Results\n")
    f.write("---------------------------------\n")
    f.write(f"Dataset rows: {len(alerts)}\n")
    f.write(f"Training rows: {len(train)}\n")
    f.write(f"Testing rows: {len(test)}\n")
    f.write(f"Selected risk threshold: {best_threshold}\n\n")

    f.write("Test Set Metrics\n")
    f.write(f"Accuracy: {accuracy:.4f}\n")
    f.write(f"Precision: {precision:.4f}\n")
    f.write(f"Recall: {recall:.4f}\n")
    f.write(f"F1 Score: {f1:.4f}\n\n")

    f.write("Confusion Matrix\n")
    f.write(f"True Positives: {tp}\n")
    f.write(f"True Negatives: {tn}\n")
    f.write(f"False Positives: {fp}\n")
    f.write(f"False Negatives: {fn}\n\n")

    f.write("Interpretation\n")
    f.write(
        "The Label column was not used to calculate the risk score. "
        "It was only used as ground truth for evaluation. "
        "The risk score was generated using asset criticality, threat impact potential, "
        "exposure/blast radius, and threat intelligence enrichment.\n"
    )

print("\nPREVIEW OF PRIORITISED ALERTS:")
print(prioritised[available_output_columns].head(20))

print("\nEVALUATION RESULTS:")
print(f"Selected Threshold: {best_threshold}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"True Positives: {tp}")
print(f"True Negatives: {tn}")
print(f"False Positives: {fp}")
print(f"False Negatives: {fn}")

print("\nSaved files:")
print("- prioritised_alerts_v2.csv")
print("- evaluation_results.txt")