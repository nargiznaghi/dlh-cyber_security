#!/bin/bash
endpoints="pcap api/pcap api/v0/pcap capture.pcap traffic/pcap pcap/download pcap/file"
for ep in $endpoints
do
    echo "Testing /$ep ..."
    curl -s http://10.42.51.4/$ep -o test.pcap
    if file test.pcap | grep -q "tcpdump"
    then
        echo "FOUND: /$ep"
        mv test.pcap task1-basic-analysis.pcap
        exit 0
    fi
done
echo "No valid endpoint found"

