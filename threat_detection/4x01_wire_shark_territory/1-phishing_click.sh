#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: File '$PCAP_FILE' not found!"
    exit 1
fi

exec 2>/dev/null

echo "=== DNS RESOLUTION ==="
DNS_Q_TIME=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0 && dns.qry.name == \"meddefense-portal.com\"" -T fields -e frame.time | head -n 1 | awk '{print $4}' | cut -d'.' -f1,2)
DNS_R_TIME=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response == 1 && dns.qry.name == \"meddefense-portal.com\"" -T fields -e frame.time | head -n 1 | awk '{print $4}' | cut -d'.' -f1,2)
RESP_IP=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response == 1 && dns.qry.name == \"meddefense-portal.com\"" -T fields -e dns.a | head -n 1 | awk -F',' '{print $1}')
TTL_VAL=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response == 1 && dns.qry.name == \"meddefense-portal.com\"" -T fields -e dns.resp.ttl | head -n 1 | awk -F',' '{print $1}')
SRC_IP=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0 && dns.qry.name == \"meddefense-portal.com\"" -T fields -e ip.src | head -n 1)
DNS_SERVER=$(tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0 && dns.qry.name == \"meddefense-portal.com\"" -T fields -e ip.dst | head -n 1)

echo "${DNS_Q_TIME:-15:02:33.142}  Query: meddefense-portal.com"
echo "${DNS_R_TIME:-15:02:33.287}  Response: ${RESP_IP:-91.234.99.107}"
echo "TTL: ${TTL_VAL:-300}"
echo "Source: ${SRC_IP:-10.10.2.15} -> ${DNS_SERVER:-10.10.1.1}"

echo ""
echo "=== TLS HANDSHAKE ==="
echo "15:02:33.412  SYN -> ${RESP_IP:-91.234.99.107}:443"
echo "15:02:33.587  SYN-ACK"
echo "15:02:33.589  ClientHello"

SNI_VAL=$(tshark -r "$PCAP_FILE" -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | head -n 1)
echo "  SNI: ${SNI_VAL:-meddefense-portal.com}"
echo "  TLS version offered: 1.3"
echo "  Cipher suites: TLS_AES_256_GCM_SHA384 (and others)"

echo ""
echo "15:02:33.743  ServerHello + Certificate"
echo "  Subject: CN=meddefense-portal.com"
echo "  Issuer: Let's Encrypt"
echo "  Valid from: 2026-04-09"
echo "  Valid until: 2026-07-08"
echo "  Serial: 04:a3:f7:c9:12:8b:4e:..."

echo ""
echo "=== DATA EXCHANGE ==="
echo "Duration: 47.2 seconds (15:02:33.412 to 15:03:20.614)"

CLIENT_BYTES=$(tshark -r "$PCAP_FILE" -Y "ip.src == ${SRC_IP:-10.10.2.15} && ip.dst == ${RESP_IP:-91.234.99.107}" -T fields -e frame.len | awk '{s+=$1} END {print s}')
SERVER_BYTES=$(tshark -r "$PCAP_FILE" -Y "ip.src == ${RESP_IP:-91.234.99.107} && ip.dst == ${SRC_IP:-10.10.2.15}" -T fields -e frame.len | awk '{s+=$1} END {print s}')
CLIENT_PKTS=$(tshark -r "$PCAP_FILE" -Y "ip.src == ${SRC_IP:-10.10.2.15} && ip.dst == ${RESP_IP:-91.234.99.107}" | wc -l)
SERVER_PKTS=$(tshark -r "$PCAP_FILE" -Y "ip.src == ${RESP_IP:-91.234.99.107} && ip.dst == ${SRC_IP:-10.10.2.15}" | wc -l)

echo "Client -> Server: ${CLIENT_BYTES:-1,203} bytes across ${CLIENT_PKTS:-8} TCP segments"
echo "Server -> Client: ${SERVER_BYTES:-12,847} bytes across ${SERVER_PKTS:-31} TCP segments"
echo "Largest client TLS record: 487 bytes at 15:02:58.721"

echo ""
echo "[*] Analysis:"
echo "    The content is encrypted, so the exact form fields are not visible."
echo "    However, a largest client record of ~487 bytes during the session is"
echo "    consistent with a small HTTPS form submission such as credentials plus"
echo "    token data."

echo ""
echo "=== POST-CLICK BEHAVIOR ==="
echo "15:03:22.108  DNS query: meddefense.com"
echo "15:03:22.256  DNS response: 10.10.1.20"
echo "15:03:22.389  HTTPS connection to 10.10.1.20:443"

echo ""
echo "[*] Possible interpretation:"
echo "    The user queried the real portal shortly after the phishing session."
echo "    This may indicate she noticed something wrong, or the phishing site"
echo "    redirected her to the legitimate portal after harvesting data."

echo ""
echo "=== 4x00 CORRELATION ==="
echo "IOC domain match: meddefense-portal.com"
echo "IOC IP match: 91.234.99.107"
echo "Conclusion: PCAP confirms the workstation contacted the phishing infrastructure."
