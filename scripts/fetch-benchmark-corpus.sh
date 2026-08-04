#!/usr/bin/env bash
# Fetch a public AIOps log corpus for benchmarking PhiGate.
#
# Usage: scripts/fetch-benchmark-corpus.sh [dest_dir]
#   default dest: eval/corpus
#
# The datasets come from LogHub (https://github.com/logpai/loghub), the standard
# public collection of real system logs used in log-parsing research. Each
# "_2k" file is a 2,000-line sample.
#
# Using a third-party corpus is deliberate. A vendor benchmarking its compressor
# on logs the vendor wrote proves nothing, and it is the first thing a sceptical
# reader checks. These files were collected by researchers with no interest in
# PhiGate's numbers, so anyone can rerun the benchmark and get what we published.
#
# Cite: Jieming Zhu et al., "Loghub: A Large Collection of System Log Datasets
# for AI-driven Log Analytics", ISSRE 2023.
set -euo pipefail

DEST="${1:-eval/corpus}"
BASE="https://raw.githubusercontent.com/logpai/loghub/master"

# A deliberate spread of shapes: distributed-system logs, supercomputer RAS
# logs, an application server, and an auth daemon. Compression behaves very
# differently across them, and reporting only the friendliest one would be
# exactly the kind of number this project exists to distrust.
DATASETS=(HDFS Spark BGL Thunderbird OpenSSH Apache Zookeeper Linux)

mkdir -p "$DEST"
echo "Fetching LogHub samples into $DEST/"

for d in "${DATASETS[@]}"; do
  out="$DEST/${d}_2k.log"
  if [ -s "$out" ]; then
    echo "  $d — already present"
    continue
  fi
  if curl -fsSL "$BASE/$d/${d}_2k.log" -o "$out"; then
    printf '  %-12s %s lines\n' "$d" "$(wc -l < "$out")"
  else
    echo "  $d — unavailable, skipped"
    rm -f "$out"
  fi
done

cat <<EOF

Done. Now run:

  make build
  ./bin/phigate-eval bench -dir $DEST     # token reduction per pipeline stage
  ./bin/phigate-eval leak  -dir $DEST     # what gets detected, by class and rule

Both are pure local computation — no API keys, no network, no cost.

The third mode measures answer quality and does need model access, because the
only honest way to show compression has not degraded answers is to ask a model
both ways and score the results:

  ./bin/phigate-eval eval -cases eval/cases.json \\
    -gateway http://localhost:8080/v1 -gateway-key <your-phigate-key> \\
    -baseline https://api.openai.com/v1 -baseline-key \$OPENAI_API_KEY
EOF
