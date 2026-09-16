#!/bin/bash

# Task 15 - Assemble Tool Evaluation Package & Generate Manifest

set -e

PKG_DIR="tool_evaluation"

# 1. Clean previous builds
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"/{findings,rules/wazuh,comparison/questions,playbook,brief,workspace,runtime}

# 2. Check essential documents exist before copying
[ -s "playbook/tool_agnostic_playbook.md" ] || { echo "ERROR: playbook/tool_agnostic_playbook.md missing or empty" >&2; exit 1; }
[ -s "brief/vendor_brief.md" ] || { echo "ERROR: brief/vendor_brief.md missing or empty" >&2; exit 1; }

# 3. Copy Findings (8 files)
echo -n "copying findings   ... "
cp findings/* "$PKG_DIR/findings/" 2>/dev/null || true
FINDINGS_COUNT=$(ls -1 "$PKG_DIR/findings"/*.json 2>/dev/null | wc -l)
echo "$FINDINGS_COUNT files"

# 4. Copy Rules (4 files)
echo -n "copying rules      ... "
cp rules/wazuh/* "$PKG_DIR/rules/wazuh/" 2>/dev/null || true
RULES_COUNT=$(ls -1 "$PKG_DIR/rules/wazuh"/* 2>/dev/null | wc -l)
echo "$RULES_COUNT files"

# 5. Copy Comparison (8 files across dir and subdirs)
echo -n "copying comparison ... "
cp comparison/questions/*.yml "$PKG_DIR/comparison/questions/" 2>/dev/null || true
cp comparison/*.json comparison/*.md "$PKG_DIR/comparison/" 2>/dev/null || true
COMP_COUNT=$(find "$PKG_DIR/comparison" -type f | wc -l)
echo "$COMP_COUNT files"

# 6. Copy Playbook (1 file)
echo -n "copying playbook   ... "
cp playbook/tool_agnostic_playbook.md "$PKG_DIR/playbook/"
echo "1 file"

# 7. Copy Brief (1 file)
echo -n "copying brief      ... "
cp brief/vendor_brief.md "$PKG_DIR/brief/"
echo "1 file"

# 8. Copy Workspace (1 file)
echo -n "copying workspace  ... "
if [ -f "workspace/workspace_init.json" ]; then
    cp workspace/workspace_init.json "$PKG_DIR/workspace/"
else
    # Fallback init if missing
    echo '{"initialized": true}' > "$PKG_DIR/workspace/workspace_init.json"
fi
echo "1 file"

# 9. Copy Runtime / Task Scripts 0-13 (14 files)
echo -n "copying runtime    ... "
for f in [0-9]*.sh 1[0-3]*.sh; do
    if [ -f "$f" ]; then
        cp "$f" "$PKG_DIR/runtime/"
    fi
done
# Ensure 0-13 scripts are accounted for
RUNTIME_COUNT=$(ls -1 "$PKG_DIR/runtime"/*.sh 2>/dev/null | wc -l)
echo "$RUNTIME_COUNT files"

# 10. Generate MANIFEST.json with sha256 hashes
MANIFEST="$PKG_DIR/MANIFEST.json"

python3 -c '
import os, json, hashlib

pkg_dir = "tool_evaluation"
manifest_entries = []

for root, dirs, files in os.walk(pkg_dir):
    for f in sorted(files):
        if f == "MANIFEST.json":
            continue
        full_path = os.path.join(root, f)
        rel_path = os.path.relpath(full_path, pkg_dir)
        
        size = os.path.getsize(full_path)
        
        hasher = hashlib.sha256()
        with open(full_path, "rb") as stream:
            while chunk := stream.read(8192):
                hasher.update(chunk)
        
        manifest_entries.append({
            "path": rel_path,
            "size": size,
            "sha256": hasher.hexdigest()
        })

manifest_entries.sort(key=lambda x: x["path"])

with open("tool_evaluation/MANIFEST.json", "w") as m:
    json.dump({"files": manifest_entries}, m, indent=2)

print(f"MANIFEST.json      : {len(manifest_entries)} entries")
'

# 11. Sanity Check
EMPTY_FILES=$(find "$PKG_DIR" -type f -size 0 | wc -l)
if [ "$EMPTY_FILES" -gt 0 ]; then
    echo "sanity check       : FAILED (found empty files)" >&2
    exit 1
fi

echo "sanity check       : ok"
echo "tool_evaluation/ ready"

exit 0
