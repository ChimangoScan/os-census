FROM golang:1.23.8-alpine AS builder

ARG GOVULNCHECK_VERSION=v1.1.4

RUN go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}

# ── runtime image (Alpine: apk avoids the apt GPG/IPv6 issues on the scan hosts)
FROM alpine:3.21

RUN apk add --no-cache file python3 bash

COPY --from=builder /go/bin/govulncheck /usr/local/bin/govulncheck
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
