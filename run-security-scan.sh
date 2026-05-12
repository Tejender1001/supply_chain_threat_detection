#!/bin/bash
# ==============================================
# Supply Chain Threat Detection - CI/CD Pipeline
# Simulates automated security gate on code push
# ==============================================

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
PROJECT_DIR="/home/developer/developer-project"
TRIVY_RAW="$PROJECT_DIR/trivy.log"
TRIVY_WAZUH="/home/developer/wazuh-logs/trivy-wazuh.log"
PIPELINE_LOG="$PROJECT_DIR/pipeline.log"

echo "[$TIMESTAMP] ========================================" >> "$PIPELINE_LOG"
echo "[$TIMESTAMP] CI/CD Security Gate - Scan Started" >> "$PIPELINE_LOG"
echo "[$TIMESTAMP] Project: $PROJECT_DIR" >> "$PIPELINE_LOG"

# Step 1: Run Trivy SBOM Scan
echo "[$TIMESTAMP] Step 1: Running Trivy SBOM vulnerability scan..." >> "$PIPELINE_LOG"
trivy fs "$PROJECT_DIR" --format json > "$TRIVY_RAW" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[$TIMESTAMP] Step 1: Scan completed successfully" >> "$PIPELINE_LOG"
else
    echo "[$TIMESTAMP] Step 1: ERROR - Scan failed" >> "$PIPELINE_LOG"
    exit 1
fi

# Step 2: Flatten JSON for Wazuh ingestion
echo "[$TIMESTAMP] Step 2: Processing results for SOC ingestion..." >> "$PIPELINE_LOG"

mkdir -p /home/developer/wazuh-logs

python3 -c "
import json, sys

def extract_objects(text):
    decoder = json.JSONDecoder()
    pos = 0
    text = text.strip()
    while pos < len(text):
        try:
            obj, idx = decoder.raw_decode(text, pos)
            yield obj
            pos = idx
            while pos < len(text) and text[pos] in ' \t\n\r':
                pos += 1
        except json.JSONDecodeError:
            break

with open('$TRIVY_RAW', 'r') as f:
    content = f.read()

counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
for data in extract_objects(content):
    for result in data.get('Results', []):
        target = result.get('Target', '')
        pkg_type = result.get('Type', '')
        for vuln in result.get('Vulnerabilities') or []:
            vuln['Target'] = target
            vuln['Type'] = pkg_type
            vuln['ScanTimestamp'] = '$TIMESTAMP'
            vuln['PipelineRun'] = 'ci-cd-simulation'
            print(json.dumps(vuln))
            sev = vuln.get('Severity', 'UNKNOWN')
            if sev in counts:
                counts[sev] += 1

total = sum(counts.values())
sys.stderr.write(f'CRITICAL={counts[\"CRITICAL\"]} HIGH={counts[\"HIGH\"]} MEDIUM={counts[\"MEDIUM\"]} LOW={counts[\"LOW\"]} TOTAL={total}\n')
" >> "$TRIVY_WAZUH" 2>> "$PIPELINE_LOG"

# Step 3: Count vulnerabilities and decide gate outcome
CRITICAL=$(python3 -c "print(open('$TRIVY_RAW').read().count('\"Severity\": \"CRITICAL\"'))")
HIGH=$(python3 -c "print(open('$TRIVY_RAW').read().count('\"Severity\": \"HIGH\"'))")

echo "[$TIMESTAMP] Step 3: Vulnerability Summary:" >> "$PIPELINE_LOG"
echo "[$TIMESTAMP]   CRITICAL: $CRITICAL" >> "$PIPELINE_LOG"
echo "[$TIMESTAMP]   HIGH:     $HIGH" >> "$PIPELINE_LOG"

# Step 4: Security Gate Decision
if [ "$CRITICAL" -gt 0 ]; then
    echo "[$TIMESTAMP] SECURITY GATE: *** BLOCKED *** Critical vulnerabilities found!" >> "$PIPELINE_LOG"
    echo "[$TIMESTAMP] ACTION: Deployment blocked. Alerts sent to SOC dashboard." >> "$PIPELINE_LOG"
    EXIT_CODE=1
elif [ "$HIGH" -gt 5 ]; then
    echo "[$TIMESTAMP] SECURITY GATE: *** WARNING *** High severity vulnerabilities exceed threshold!" >> "$PIPELINE_LOG"
    echo "[$TIMESTAMP] ACTION: Deployment flagged for review." >> "$PIPELINE_LOG"
    EXIT_CODE=1
else
    echo "[$TIMESTAMP] SECURITY GATE: *** PASSED *** No critical issues found." >> "$PIPELINE_LOG"
    EXIT_CODE=0
fi

echo "[$TIMESTAMP] Step 4: Results forwarded to Wazuh SOC dashboard" >> "$PIPELINE_LOG"
echo "[$TIMESTAMP] ========================================" >> "$PIPELINE_LOG"

exit $EXIT_CODE
