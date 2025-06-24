#!/bin/bash

echo "🔁 Starting Agent..."

# Paths (adjust if needed)
CICFLOWMETER_DIR="/root/CICFlowMeter"
PCAP_DIR="$CICFLOWMETER_DIR/data/in/"
CSV_DIR="$CICFLOWMETER_DIR/data/out/"
PYTHON_SCRIPT="/root/threat-agent/predictor.py"

while true; do
    rm -f /root/CICFlowMeter/data/in/*.pcap
    rm -f /root/CICFlowMeter/data/out/*.csv

    echo "⏱️  Checking for PCAPs..."

    # If no PCAP files found, capture a new one
    pcap_files=("$PCAP_DIR"*.pcap)
    if [ ${#pcap_files[@]} -eq 0 ] || [ ! -e "${pcap_files[0]}" ]; then
        echo "🆕 No PCAP found. Capturing new traffic..."

        timestamp=$(date +"%Y%m%d_%H%M%S")
        new_pcap="${PCAP_DIR}test_$timestamp.pcap"

        # Adjust eth0 if your interface is different
        tcpdump -i any -w "$new_pcap" -G 30 -W 1 >/dev/null 2>&1

        echo "⏳ Capturing for 10 seconds..."
        wait $!
        echo "✅ Capture complete: $new_pcap"
    fi

    # Convert pcap to csv
    cd "$CICFLOWMETER_DIR" || exit
    java -Djava.library.path=jnetpcap/linux/jnetpcap-1.3.0 \
         -cp "build/libs/CICFlowMeter-4.0.jar:jnetpcap/linux/jnetpcap-1.3.0/jnetpcap.jar:libs/slf4j-api.jar:libs/slf4j-simple.jar:libs/commons-math3.jar" \
         cic.cs.unb.ca.ifm.CICFlowMeter "$PCAP_DIR" "$CSV_DIR"

    # Run prediction on generated CSVs
    for csv in "$CSV_DIR"*.csv; do
        echo "🔍 Predicting threats in: $csv"
        python3 "$PYTHON_SCRIPT" "$csv"
        base_name=$(basename "$csv" | cut -d'_' -f1)  # e.g., test_ISCX.csv → test
        pcap_to_delete="${PCAP_DIR}${base_name}.pcap"
    done

    echo "✅ Done. Sleeping for 2 seconds..."
    sleep 2
done

