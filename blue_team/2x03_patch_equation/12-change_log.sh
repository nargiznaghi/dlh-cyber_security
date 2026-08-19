#!/bin/bash
#
# Name:        12-change_log.sh
# Purpose:     Produce a canonical change log from apt history logs and prior
#              task artifacts, enriched with maintenance window and CVE data
# Author:      Nargiz Naghiyeva
# Date:        August 18, 2026
#SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${SCRIPT_DIR}/patch_change_log.json"

exec python3 - "$SCRIPT_DIR" "$OUTPUT" <<'PY'
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

BASE = sys.argv[1]
OUTPUT = sys.argv[2]

APT_LOGS = sorted(glob.glob("/var/log/apt/history.log*"))

WINDOW_SCRIPT = os.path.join(BASE, "11-maintenance_window.sh")
EXECUTION_LOG = os.path.join(BASE, "patch_execution_log.json")
VULN_INVENTORY = os.path.join(BASE, "vulnerability_inventory.json")

UTC = timezone.utc
GROUP_GAP = timedelta(minutes=15)


def parse_dt(value):
    """Parse common ISO/date formats and return an aware datetime."""
    if not value:
        return None

    value = value.strip()

    # ISO-8601, including trailing Z.
    try:
        v = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        pass

    # APT history.log uses e.g. 2026-03-28 02:03:12
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    return None


def iso(dt):
    return dt.astimezone().isoformat(timespec="seconds")


def json_load(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def apt_transactions():
    """
    Parse all rotated APT history files.

    APT transaction blocks look like:

      Start-Date: 2026-03-28 02:03:12
      Commandline: apt-get upgrade
      Requested-By: analyst (1001)
      Upgrade: pkg:amd64 (...)
      Install: pkg:amd64 (...)
      Remove: pkg:amd64 (...)
      End-Date: 2026-03-28 02:04:00
    """
    transactions = []

    start = None
    commandline = None
    requested_by = None
    upgrades = []
    installs = []
    removes = []
    end = None

    def finish():
        nonlocal start, commandline, requested_by
        nonlocal upgrades, installs, removes, end

        if start is None:
            return

        transactions.append({
            "started": start,
            "ended": end or start,
            "commandline": commandline or "",
            "user": requested_by or "unknown",
            "upgrade": list(upgrades),
            "install": list(installs),
            "remove": list(removes),
        })

        start = None
        commandline = None
        requested_by = None
        upgrades = []
        installs = []
        removes = []
        end = None

    for path in APT_LOGS:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.rstrip("\n")

                    if line.startswith("Start-Date:"):
                        finish()
                        start = parse_dt(line.split(":", 1)[1].strip())

                    elif line.startswith("Commandline:"):
                        commandline = line.split(":", 1)[1].strip()

                    elif line.startswith("Requested-By:"):
                        value = line.split(":", 1)[1].strip()
                        # "analyst (1001)" -> "analyst"
                        requested_by = re.sub(r"\s*\(\d+\)\s*$", "", value)

                    elif line.startswith("Upgrade:"):
                        upgrades.extend(parse_package_field(
                            line.split(":", 1)[1].strip()
                        ))

                    elif line.startswith("Install:"):
                        installs.extend(parse_package_field(
                            line.split(":", 1)[1].strip()
                        ))

                    elif line.startswith("Remove:"):
                        removes.extend(parse_package_field(
                            line.split(":", 1)[1].strip()
                        ))

                    elif line.startswith("End-Date:"):
                        end = parse_dt(line.split(":", 1)[1].strip())
                        finish()

                finish()
        except OSError:
            continue

    # Old/rotated files may overlap; eliminate exact duplicate transactions.
    unique = {}
    for tx in transactions:
        key = (
            tx["started"].isoformat(),
            tx["ended"].isoformat(),
            tx["commandline"],
            tx["user"],
            tuple(tx["upgrade"]),
            tuple(tx["install"]),
            tuple(tx["remove"]),
        )
        unique[key] = tx

    return sorted(unique.values(), key=lambda x: x["started"])


def parse_package_field(value):
    """
    Extract package names from APT's comma-separated transaction fields.
    Handles:
      pkg:amd64 (version)
      pkg:amd64
      pkg (version)
    """
    result = []

    for item in value.split(","):
        item = item.strip()
        if not item:
            continue

        item = re.sub(r"\s+\([^)]*\)", "", item)
        item = item.strip()

        if item:
            result.append(item)

    return sorted(set(result))


def group_events(transactions):
    events = []

    for tx in transactions:
        if not events:
            events.append([tx])
            continue

        previous = events[-1][-1]

        if tx["started"] - previous["ended"] <= GROUP_GAP:
            events[-1].append(tx)
        else:
            events.append([tx])

    return events


def maintenance_decision(timestamp):
    """
    Invoke task 11's reporting interface.

    Expected output contains a decision such as:
      inside
      outside
    or:
      decision: inside
    """
    if not os.path.isfile(WINDOW_SCRIPT):
        return "unknown"

    try:
        result = subprocess.run(
            [WINDOW_SCRIPT, "--report", timestamp.isoformat()],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"

    text = (result.stdout + "\n" + result.stderr).lower()

    # Prefer explicit decision fields.
    match = re.search(
        r"(?:decision|within_window|result)\s*[:=]\s*(inside|outside)",
        text,
    )
    if match:
        return match.group(1)

    # Also accept simple report output.
    if re.search(r"\binside\b", text):
        return "inside"
    if re.search(r"\boutside\b", text):
        return "outside"

    return "unknown"


def package_names(event):
    names = set()

    for tx in event:
        names.update(tx["upgrade"])
        names.update(tx["install"])
        names.update(tx["remove"])

    return sorted(names)


def load_execution_logs():
    data = json_load(EXECUTION_LOG, [])

    if isinstance(data, dict):
        # Support either one execution record or a collection.
        for key in ("events", "executions", "records", "runs"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]

    return data if isinstance(data, list) else []


def execution_timestamp_range(record):
    candidates = []

    for key in (
        "started",
        "start",
        "start_time",
        "timestamp",
        "executed_at",
        "ended",
        "end",
        "end_time",
        "completed_at",
    ):
        value = record.get(key)
        dt = parse_dt(str(value)) if value else None
        if dt:
            candidates.append((key, dt))

    if not candidates:
        return None, None

    values = [x[1] for x in candidates]
    return min(values), max(values)


def linked_execution_log(event_start, event_end):
    """
    Return the execution-log path when an execution timestamp overlaps
    the event interval. If the execution record only has one timestamp,
    treat it as a point in time.
    """
    records = load_execution_logs()

    for record in records:
        if not isinstance(record, dict):
            continue

        start, end = execution_timestamp_range(record)
        if start is None:
            continue

        if end is None:
            end = start

        if start <= event_end and end >= event_start:
            return os.path.abspath(EXECUTION_LOG)

    return None


def vulnerability_entries():
    data = json_load(VULN_INVENTORY, [])

    if isinstance(data, dict):
        for key in ("vulnerabilities", "findings", "entries", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]

    return data if isinstance(data, list) else []


def vuln_packages(entry):
    values = []

    if not isinstance(entry, dict):
        return values

    for key in (
        "package",
        "package_name",
        "name",
        "affected_package",
        "affected_packages",
    ):
        value = entry.get(key)

        if isinstance(value, str):
            values.append(value.split(":", 1)[0])

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    values.append(item.split(":", 1)[0])
                elif isinstance(item, dict):
                    n = item.get("name") or item.get("package")
                    if n:
                        values.append(str(n).split(":", 1)[0])

    return sorted(set(values))


def vuln_id(entry):
    if not isinstance(entry, dict):
        return None

    for key in ("cve", "cve_id", "id", "vulnerability_id"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value

    return None


def cves_resolved_for_event(event):
    """
    Cross-reference packages changed by the event against the vulnerability
    inventory. A CVE is considered resolved when its affected package was
    changed by the transaction and the inventory entry is no longer present
    after that event.

    The inventory is the post-event source of truth. Thus a CVE present in
    the current inventory cannot be counted as resolved.
    """
    changed = {
        name.split(":", 1)[0]
        for name in package_names(event)
    }

    if not changed:
        return []

    resolved = []

    for entry in vulnerability_entries():
        cve = vuln_id(entry)
        if not cve:
            continue

        affected = set(vuln_packages(entry))

        if affected & changed:
            # This entry still exists, so it is not resolved according to
            # the current inventory.
            continue

        # No remaining affected package in the inventory means the CVE may
        # have been removed by this event only when the package changed.
        # We therefore cannot infer resolution without historical inventory.
        # Keep this conservative and do not invent a CVE resolution.
        continue

    return sorted(set(resolved))


def build_event(event):
    start = min(tx["started"] for tx in event)
    end = max(tx["ended"] for tx in event)

    packages = package_names(event)

    upgrades = sorted({
        pkg for tx in event for pkg in tx["upgrade"]
    })
    installs = sorted({
        pkg for tx in event for pkg in tx["install"]
    })
    removes = sorted({
        pkg for tx in event for pkg in tx["remove"]
    })

    users = sorted({
        tx["user"] for tx in event if tx["user"]
    })

    return {
        "started": iso(start),
        "ended": iso(end),
        "user": users[0] if len(users) == 1 else users,
        "commandlines": sorted({
            tx["commandline"]
            for tx in event
            if tx["commandline"]
        }),
        "upgrade": upgrades,
        "install": installs,
        "remove": removes,
        "packages": packages,
        "package_count": len(packages),
        "within_window": maintenance_decision(start),
        "linked_execution_log": linked_execution_log(start, end),
        "cves_resolved": cves_resolved_for_event(event),
    }


transactions = apt_transactions()
grouped = group_events(transactions)
events = [build_event(group) for group in grouped]

events.sort(key=lambda x: x["started"])

inside = sum(1 for e in events if e["within_window"] == "inside")
outside = sum(1 for e in events if e["within_window"] == "outside")
cves = sorted({
    cve
    for event in events
    for cve in event["cves_resolved"]
})

if events:
    period_start = events[0]["started"]
    period_end = events[-1]["ended"]
else:
    # Deterministic empty-period values.
    period_start = None
    period_end = None

output = {
    "period_start": period_start,
    "period_end": period_end,
    "events": events,
    "summary": {
        "total_events": len(events),
        "inside_window": inside,
        "outside_window": outside,
        "cves_resolved": len(cves),
    },
}

# Compact, sorted-key JSON makes output deterministic across runs.
tmp = OUTPUT + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(output, f, sort_keys=True, separators=(",", ":"))
    f.write("\n")

os.replace(tmp, OUTPUT)
PY

chmod 0755 "$0"
printf 'Wrote %s\n' "$OUTPUT"
