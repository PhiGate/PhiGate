---

### Container image

```bash
docker run -p 8080:8080 \
  -e PHIGATE_API_KEYS="your-client-key:team-sre" \
  -e PHIGATE_CLOUD_API_KEY="sk-..." \
  ghcr.io/phigate/phigate:latest
```

Published for `linux/amd64` and `linux/arm64`, with build provenance and an SBOM
attached. The release job refuses to publish an image that starts without
`PHIGATE_API_KEYS`, so a tagged image can never ship as an open relay.

### Verifying the claims yourself

Nothing here has to be taken on trust:

```bash
make guarantees                            # every security guarantee, as named checks
scripts/fetch-benchmark-corpus.sh          # public third-party log corpora (LogHub)
./bin/phigate-eval bench -dir eval/corpus  # token reduction, reproducible
./bin/phigate-eval leak  -dir eval/corpus  # detection coverage on your own logs
```

See [THREAT-MODEL.md](../blob/main/THREAT-MODEL.md) for what PhiGate does **not**
protect against — read that before putting it in front of anything that executes
commands automatically.
