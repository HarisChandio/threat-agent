import pandas as pd
import sys
import pickle
import os

# Get current script directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load the trained model
with open(os.path.join(BASE_DIR, 'rf_model.pkl'), 'rb') as model_file:
    rf_model = pickle.load(model_file)

# Load the label encoder
with open(os.path.join(BASE_DIR, 'label_encoder.pkl'), 'rb') as encoder_file:
    le = pickle.load(encoder_file)
model_columns = rf_model.feature_names_in_

# Rename map (same as before)
rename_map = {
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Packet Length Min': 'Min Packet Length',
    'Packet Length Max': 'Max Packet Length',
    'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
    'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
    'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
    'FWD Init Win Bytes': 'Init_Win_bytes_forward',
    'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'CWR Flag Count': 'CWE Flag Count',
}

# Get CSV path from shell
csv_path = sys.argv[1]

try:
    df = pd.read_csv(csv_path, header=1)
    df.columns = df.columns.str.strip()
    df.rename(columns=rename_map, inplace=True)

    drop_cols = ['Flow ID', 'Timestamp', 'Src IP', 'Src Port',
                 'Dst IP', 'Dst Port', 'Protocol', 'Source IP',
                 'Destination IP', 'Destination Port']
    df.drop(columns=[col for col in drop_cols if col in df.columns], inplace=True)

    df = df[model_columns]
    df = df.apply(pd.to_numeric, errors='coerce').dropna()

    preds = rf_model.predict(df)
    labels = le.inverse_transform(preds)
    df['Predicted Label'] = labels

    threats = df[df['Predicted Label'] != 'BENIGN']
    if not threats.empty:
        print("🚨 Anomaly Detected 🚨")
        print(threats['Predicted Label'].value_counts())

    else:
        print("✅ No threats in this capture.")

    threats.to_csv("logs/threat_" + csv_path.split('/')[-1], index=False)
except Exception as e:
    print(f"[!] Error processing {csv_path}: {e}")
