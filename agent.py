import pandas as pd
import numpy as np
import glob
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from joblib import dump

# Display settings
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

print("📂 Searching for datasets in '../data-sets/' ...")
file_paths = glob.glob("./data-sets/*.csv")
print(f"✅ Found {len(file_paths)} dataset(s).")

print("📊 Reading and combining datasets ...")
dfs = [pd.read_csv(file, low_memory=False) for file in file_paths]
df = pd.concat(dfs, ignore_index=True)
print(f"🧮 Total rows combined: {len(df)}")

# Clean column names and remove duplicates
print("🧹 Cleaning dataset: stripping column names, dropping duplicates ...")
df.columns = df.columns.str.strip()
df.drop_duplicates(inplace=True)

# Initial label cleanup
df["Label"] = df["Label"].str.replace("�", "-", regex=False).str.strip()

# Downsample BENIGN, retain all attacks
print("🎯 Balancing dataset: sampling 200,000 BENIGN rows ...")
non_benign = df[df["Label"] != "BENIGN"]
benign_sampled = df[df["Label"] == "BENIGN"].sample(200_000, random_state=42)
df = pd.concat([benign_sampled, non_benign], ignore_index=True)

# Drop NaNs and infinite values
print("🧹 Removing NaNs and infinite values ...")
df.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
df.dropna(inplace=True)

# Drop unnecessary columns
print("🗑️ Dropping unused columns ...")
df.drop(columns=['Flow ID', 'Timestamp', 'Source IP', 'Destination IP', 'Destination Port',
                 'Fwd Header Length.1'], errors='ignore', inplace=True)

# Group rare and similar labels
print("🔁 Grouping similar and rare attack labels ...")
label_map = {
    'BENIGN': 'BENIGN',
    'DDoS': 'DDoS',
    'PortScan': 'PortScan',
    'Bot': 'Bot',
    'Infiltration': 'Rare Attack',
    'Heartbleed': 'Rare Attack',
    'FTP-Patator': 'Brute Force',
    'SSH-Patator': 'Brute Force',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'Web Attack - Brute Force': 'Web Attack',
    'Web Attack - XSS': 'Web Attack',
    'Web Attack - Sql Injection': 'Web Attack',
}
df["Label"] = df["Label"].replace(label_map)

# Encode labels
print("🔢 Encoding labels ...")
le = LabelEncoder()
df["Label"] = le.fit_transform(df["Label"])

# Train-test split
print("🧪 Splitting data into training and test sets ...")
X = df.drop("Label", axis=1)
y = df["Label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)

# Apply SMOTE
print("🔄 Balancing training data using SMOTE ...")
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
print("✅ Resampling complete.")

# Train Random Forest model
print("🧠 Training Random Forest model ...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train_resampled, y_train_resampled)
print("✅ Model training complete.")

# Evaluate
print("📏 Evaluating model on test set ...")
y_pred = rf_model.predict(X_test)
print(f"🎯 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

dump(rf_model, "rf_model.joblib")
dump(le, "label_encoder.joblib")

print("✅ Model and label encoder saved.")
