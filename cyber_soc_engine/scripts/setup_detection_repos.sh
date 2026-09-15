#!/bin/bash
# Setup or update Security Detection Repositories

set -e

DETECTION_DIR="$HOME/security-detections"
UPDATE_MODE=false

if [[ "$1" == "--update" ]]; then
    UPDATE_MODE=true
fi

mkdir -p "$DETECTION_DIR"
cd "$DETECTION_DIR"

echo "Detection Repository Setup"
echo "Location: $DETECTION_DIR"
echo ""

# Function to clone or update repo
clone_or_update() {
    local repo_name=$1
    local repo_url=$2
    local display_name=$3
    
    if [ -d "$repo_name" ]; then
        if [ "$UPDATE_MODE" = true ]; then
            echo "📦 Updating $display_name..."
            cd "$repo_name"
            git pull --quiet
            cd ..
            echo "✅ Updated"
        else
            echo "✅ $display_name already exists"
        fi
    else
        echo "📥 Cloning $display_name..."
        git clone --quiet --depth 1 "$repo_url" "$repo_name" 2>&1 | grep -v "Cloning into" || true
        echo "✅ Cloned"
    fi
}

# Clone/update repositories
clone_or_update "sigma" "https://github.com/SigmaHQ/sigma.git" "Sigma Rules (~3,200)"
clone_or_update "security_content" "https://github.com/splunk/security_content.git" "Splunk ESCU (~2,000)"
clone_or_update "detection-rules" "https://github.com/elastic/detection-rules.git" "Elastic Rules (~1,500)"
clone_or_update "Hunting-Queries-Detection-Rules" "https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git" "KQL Queries (~420)"

echo ""
echo "=========================================="
echo "✅ Detection Repositories Ready"
echo "=========================================="
echo "Location: $DETECTION_DIR"
echo ""
echo "Paths configured:"
echo "  Sigma:   $DETECTION_DIR/sigma/rules"
echo "  Splunk:  $DETECTION_DIR/security_content/detections"
echo "  Elastic: $DETECTION_DIR/detection-rules/rules"
echo "  KQL:     $DETECTION_DIR/Hunting-Queries-Detection-Rules"
echo ""

