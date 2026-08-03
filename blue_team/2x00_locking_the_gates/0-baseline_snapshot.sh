#!/bin/bash

# 1. Hostname (Sistemin adı - məsələn: nargiznaghi)
HOSTNAME=$(hostname)

# 2. OS (Əməliyyat Sisteminin adı - məsələn: Ubuntu və ya macOS)
if [ -f /etc/os-release ]; then
    OS=$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
else
    OS="$(uname -s) $(uname -r)"
fi

# 3. Running Services (Həmin an arxa fonda aktiv çalışan xidmətlərin/proqramların sayı)
if command -v systemctl &> /dev/null; then
    RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l | tr -d ' ')
else
    RUNNING_SERVICES=$(ps aux | wc -l | tr -d ' ')
fi

# 4. Open Ports (Şəbəkədə dinləmədə olan/açıq portların sayı)
if command -v ss &> /dev/null; then
    OPEN_PORTS=$(ss -tuln 2>/dev/null | grep -v "State" | grep -v "Recv-Q" | wc -l | tr -d ' ')
else
    OPEN_PORTS=$(netstat -an 2>/dev/null | grep LISTEN | wc -l | tr -d ' ')
fi

# 5. SUID binaries (Xüsusi icazəyə sahib sistem fayllarının sayı)
SUID_COUNT=$(find / -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' ')

# 6. SGID binaries (Qrup icazəli xüsusi faylların sayı)
SGID_COUNT=$(find / -perm -2000 -type f 2>/dev/null | wc -l | tr -d ' ')

# 7. World-writable files (Hər kəsin dəyişdirə bildiyi təhlükəli faylların sayı)
WORLD_WRITABLE=$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null | wc -l | tr -d ' ')

# Nəticələri ekrana çıxarmaq (Output)
echo "Hostname: $HOSTNAME"
echo "OS: $OS"
echo "Running services: $RUNNING_SERVICES"
echo "Open ports: $OPEN_PORTS"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WORLD_WRITABLE"
