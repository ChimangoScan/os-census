FROM debian:bookworm-slim

# Arachni 1.6.1.3 — last release of the project (EOL 2020, binary still functional)
ARG ARACHNI_VERSION=1.6.1.3
ARG ARACHNI_UI_VERSION=0.6.1.1
ARG ARACHNI_TARBALL="arachni-${ARACHNI_VERSION}-${ARACHNI_UI_VERSION}-linux-x86_64.tar.gz"
ARG ARACHNI_URL="https://github.com/Arachni/arachni/releases/download/v${ARACHNI_VERSION}/${ARACHNI_TARBALL}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates passwd util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 2000 scanner          # Arachni refuses to run as root

RUN curl -fsSL "${ARACHNI_URL}" -o /tmp/arachni.tar.gz \
    && tar -xzf /tmp/arachni.tar.gz -C /opt \
    && mv /opt/arachni-${ARACHNI_VERSION}-${ARACHNI_UI_VERSION} /opt/arachni \
    && rm /tmp/arachni.tar.gz \
    && chown -R scanner:scanner /opt/arachni   # arachni writes to its own tree

ENV PATH="/opt/arachni/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
