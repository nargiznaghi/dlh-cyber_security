#!/bin/bash

set -e

DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap"
OUTPUT="pcap_findings.json"
ALT_OUTPUT="pcap_investigation.json"
TMPDIR="/tmp/pcap-investigation-$$"

if [ $# -gt 0 ]; then
    PCAP="$1"
else
    PCAP="$DEFAULT_PCAP"
fi

if [ ! -f "$PCAP" ]; then
    echo "PCAP not found: $PCAP"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "tshark is not installed"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is not installed"
    exit 1
fi

mkdir -p "$TMPDIR"

# Human readable bytes formatter function
format_bytes() {
    local bytes=$1
    if [ -z "$bytes" ] || [ "$bytes" -eq 0 ]; then
        echo "0 B"
    elif [ "$bytes" -ge 1048576 ]; then
        awk -v b="$bytes" 'BEGIN {printf "%.1f MB", b/1048576}'
    elif [ "$bytes" -ge 1024 ]; then
        awk -v b="$bytes" 'BEGIN {printf "%.0f KB", b/1024}'
    else
        echo "${bytes} B"
    fi
}

echo "[*] PCAP: $PCAP"

PACKETS=$(tshark -r "$PCAP" -T fields -e frame.number 2>/dev/null | tail -1)
DURATION=$(tshark -r "$PCAP" -T fields -e frame.time_relative 2>/dev/null | tail -1)

PACKETS=${PACKETS:-0}
DURATION=${DURATION:-0}

echo "[*] Duration: $DURATION s     Packets: $PACKETS"

# Extract TCP conversations and parse top 10 conversations
echo -n "[*] Extracting TCP conversations... "
tshark -q -z conv,tcp -n -r "$PCAP" > "$TMPDIR/tcp_raw.txt" 2>/dev/null || true

TCP_COUNT=$(awk '$2 == "<->" { count++ } END { print count + 0 }' "$TMPDIR/tcp_raw.txt")

awk '$2 == "<->" { print $1 "\t" $3 "\t" $8 "\t" $9 "\t" $10 "\t" $11 }' "$TMPDIR/tcp_raw.txt" | head -10 > "$TMPDIR/tcp.tsv"

jq -R -s '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    if length == 0 then [] else map({
        endpoint_a: .[0],
        endpoint_b: .[1],
        proto: "tcp",
        packets: (.[2] | tonumber? // 0),
        bytes: (.[3] | tonumber? // 0),
        relative_start: (.[4] | tonumber? // 0),
        duration: (.[5] | tonumber? // 0)
    }) end
' "$TMPDIR/tcp.tsv" > "$TMPDIR/tcp.json"
echo "     ($TCP_COUNT)"

# Extract UDP conversations and parse top 10 conversations
echo -n "[*] Extracting UDP conversations... "
tshark -q -z conv,udp -n -r "$PCAP" > "$TMPDIR/udp_raw.txt" 2>/dev/null || true

UDP_COUNT=$(awk '$2 == "<->" { count++ } END { print count + 0 }' "$TMPDIR/udp_raw.txt")

awk '$2 == "<->" { print $1 "\t" $3 "\t" $8 "\t" $9 "\t" $10 "\t" $11 }' "$TMPDIR/udp_raw.txt" | head -10 > "$TMPDIR/udp.tsv"

jq -R -s '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    if length == 0 then [] else map({
        endpoint_a: .[0],
        endpoint_b: .[1],
        proto: "udp",
        packets: (.[2] | tonumber? // 0),
        bytes: (.[3] | tonumber? // 0),
        relative_start: (.[4] | tonumber? // 0),
        duration: (.[5] | tonumber? // 0)
    }) end
' "$TMPDIR/udp.tsv" > "$TMPDIR/udp.json"
echo "     ($UDP_COUNT)"

# Extract DNS queries via tshark -Y dns.flags.response==0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type
echo -n "[*] Extracting DNS queries... "
tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -E separator=/t -E occurrence=f \
    -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type > "$TMPDIR/dns.tsv" 2>/dev/null || true

jq -R -s '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    if length == 0 then [] else map({
        timestamp: (.[0] // ""),
        src_ip: (.[1] // ""),
        query: (.[2] // ""),
        query_type: (.[3] // "")
    }) end
' "$TMPDIR/dns.tsv" > "$TMPDIR/dns.json"

DNS_COUNT=$(jq 'length' "$TMPDIR/dns.json")
echo "           ($DNS_COUNT)"

# Extract HTTP requests via tshark -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
echo -n "[*] Extracting HTTP requests... "
tshark -r "$PCAP" -Y "http.request" -T fields -E separator=/t -E occurrence=f \
    -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri > "$TMPDIR/http.tsv" 2>/dev/null || true

jq -R -s '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    if length == 0 then [] else map({
        timestamp: (.[0] // ""),
        src_ip: (.[1] // ""),
        dst_ip: (.[2] // ""),
        host: (.[3] // ""),
        method: (.[4] // ""),
        uri: (.[5] // "")
    }) end
' "$TMPDIR/http.tsv" > "$TMPDIR/http.json"

HTTP_COUNT=$(jq 'length' "$TMPDIR/http.json")
echo "         ($HTTP_COUNT)"

# Extract TLS SNI via tshark -Y tls.handshake.type==1 -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
echo -n "[*] Extracting TLS SNI... "
tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -E separator=/t -E occurrence=f \
    -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name > "$TMPDIR/tls.tsv" 2>/dev/null || true

jq -R -s '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    if length == 0 then [] else map({
        timestamp: (.[0] // ""),
        src_ip: (.[1] // ""),
        dst_ip: (.[2] // ""),
        sni: (.[3] // "")
    }) end
' "$TMPDIR/tls.tsv" > "$TMPDIR/tls.json"

TLS_COUNT=$(jq 'length' "$TMPDIR/tls.json")
echo "               ($TLS_COUNT)"

# Extract File transfers via tshark -Y "http.content_type or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename
echo -n "[*] Extracting file transfers... "
tshark -r "$PCAP" -Y "http.content_type or smb2.filename" -T fields -E separator=/t -E occurrence=f \
    -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename > "$TMPDIR/files.tsv" 2>/dev/null || true

jq -R -s '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    if length == 0 then [] else map({
        timestamp: (.[0] // ""),
        src_ip: (.[1] // ""),
        dst_ip: (.[2] // ""),
        http_file_data: (.[3] // ""),
        smb2_filename: (.[4] // "")
    }) end
' "$TMPDIR/files.tsv" > "$TMPDIR/files.json"

FILE_COUNT=$(jq 'length' "$TMPDIR/files.json")
echo "        ($FILE_COUNT)"

# Extract Protocol distribution via tshark -q -z io,phs
echo -n "[*] Protocol distribution... "
tshark -q -z io,phs -n -r "$PCAP" > "$TMPDIR/protocols.txt" 2>/dev/null || true

TCP_PACKETS=$(grep -E '^[[:space:]]*tcp[[:space:]]+frames:' "$TMPDIR/protocols.txt" | head -1 | sed -n 's/.*frames:\([0-9]*\).*/\1/p')
UDP_PACKETS=$(grep -E '^[[:space:]]*udp[[:space:]]+frames:' "$TMPDIR/protocols.txt" | head -1 | sed -n 's/.*frames:\([0-9]*\).*/\1/p')
ICMP_PACKETS=$(grep -E '^[[:space:]]*icmp[[:space:]]+frames:' "$TMPDIR/protocols.txt" | head -1 | sed -n 's/.*frames:\([0-9]*\).*/\1/p')

TCP_PACKETS=${TCP_PACKETS:-0}
UDP_PACKETS=${UDP_PACKETS:-0}
ICMP_PACKETS=${ICMP_PACKETS:-0}

OTHER_PACKETS=$(awk -v total="$PACKETS" -v tcp="$TCP_PACKETS" -v udp="$UDP_PACKETS" -v icmp="$ICMP_PACKETS" 'BEGIN { other = total - tcp - udp - icmp; if (other < 0) other = 0; print other }')

TCP_PERCENT=$(awk -v n="$TCP_PACKETS" -v t="$PACKETS" 'BEGIN { if (t == 0) print 0; else printf "%.0f", (n / t) * 100 }')
UDP_PERCENT=$(awk -v n="$UDP_PACKETS" -v t="$PACKETS" 'BEGIN { if (t == 0) print 0; else printf "%.0f", (n / t) * 100 }')
ICMP_PERCENT=$(awk -v n="$ICMP_PACKETS" -v t="$PACKETS" 'BEGIN { if (t == 0) print 0; else printf "%.0f", (n / t) * 100 }')
OTHER_PERCENT=$(awk -v n="$OTHER_PACKETS" -v t="$PACKETS" 'BEGIN { if (t == 0) print 0; else printf "%.0f", (n / t) * 100 }')

jq -n \
    --argjson tcp_packets "$TCP_PACKETS" \
    --argjson udp_packets "$UDP_PACKETS" \
    --argjson icmp_packets "$ICMP_PACKETS" \
    --argjson other_packets "$OTHER_PACKETS" \
    --argjson tcp_percent "$TCP_PERCENT" \
    --argjson udp_percent "$UDP_PERCENT" \
    --argjson icmp_percent "$ICMP_PERCENT" \
    --argjson other_percent "$OTHER_PERCENT" \
    '{
        tcp: { packets: $tcp_packets, percent: $tcp_percent },
        udp: { packets: $udp_packets, percent: $udp_percent },
        icmp: { packets: $icmp_packets, percent: $icmp_percent },
        other: { packets: $other_packets, percent: $other_percent }
    }' > "$TMPDIR/protocols.json"

echo "            (tcp ${TCP_PERCENT}%, udp ${UDP_PERCENT}%, icmp ${ICMP_PERCENT}%, other ${OTHER_PERCENT}%)"

# Long DNS labels (> 50 chars)
jq '
    if . == null then [] else
    [
        .[] | . as $dns | (($dns.query // "") | split(".")[0]) as $leftmost |
        select(($leftmost | length) > 50) |
        {
            timestamp: $dns.timestamp,
            src_ip: $dns.src_ip,
            query: $dns.query,
            leftmost_label: $leftmost,
            label_length: ($leftmost | length)
        }
    ] end
' "$TMPDIR/dns.json" > "$TMPDIR/long_dns.json"

# Top 5 conversations
jq -s '
    (.[0] + .[1]) | sort_by(-.packets) | .[0:5]
' "$TMPDIR/tcp.json" "$TMPDIR/udp.json" > "$TMPDIR/top5.json"

# Render JSON reports
jq -n \
    --arg pcap "$PCAP" \
    --arg duration "$DURATION" \
    --argjson packets "$PACKETS" \
    --slurpfile tcp "$TMPDIR/tcp.json" \
    --slurpfile udp "$TMPDIR/udp.json" \
    --slurpfile dns "$TMPDIR/dns.json" \
    --slurpfile http "$TMPDIR/http.json" \
    --slurpfile tls "$TMPDIR/tls.json" \
    --slurpfile files "$TMPDIR/files.json" \
    --slurpfile protocols "$TMPDIR/protocols.json" \
    --slurpfile top5 "$TMPDIR/top5.json" \
    --slurpfile longdns "$TMPDIR/long_dns.json" \
    '{
        pcap: $pcap,
        duration_seconds: ($duration | tonumber? // 0),
        packets: $packets,
        conversations: {
            tcp: ($tcp[0] // []),
            udp: ($udp[0] // [])
        },
        dns_queries: ($dns[0] // []),
        http_requests: ($http[0] // []),
        tls_sni: ($tls[0] // []),
        file_transfers: ($files[0] // []),
        protocol_distribution: ($protocols[0] // {}),
        top_conversations: ($top5[0] // []),
        long_dns_labels: ($longdns[0] // [])
    }' > "$OUTPUT"

cp "$OUTPUT" "$ALT_OUTPUT"

echo ""
echo "Top conversations:"
jq -c '.[]' "$TMPDIR/top5.json" | while read -r row; do
    epa=$(echo "$row" | jq -r '.endpoint_a')
    epb=$(echo "$row" | jq -r '.endpoint_b')
    proto=$(echo "$row" | jq -r '.proto')
    pkts=$(echo "$row" | jq -r '.packets')
    bytes=$(echo "$row" | jq -r '.bytes')
    
    formatted_bytes=$(format_bytes "$bytes")
    
    # Format number of packets with comma if large
    formatted_pkts=$(printf "%'d" "$pkts" 2>/dev/null || echo "$pkts")
    
    printf "  %-15s <-> %-15s  %-4s %6s pkts  %6s\n" "$epa" "$epb" "$proto" "$formatted_pkts" "$formatted_bytes"
done

echo ""
echo "Long DNS labels (> 50 chars):"
LONG_COUNT=$(jq 'length' "$TMPDIR/long_dns.json")
if [ "$LONG_COUNT" -eq 0 ]; then
    echo "  none"
else
    jq -c '.[]' "$TMPDIR/long_dns.json" | while read -r row; do
        q=$(echo "$row" | jq -r '.query')
        l=$(echo "$row" | jq -r '.label_length')
        echo "  $q  ($l chars)"
    done
fi

rm -rf "$TMPDIR"
