FROM eclipse-temurin:17-jre-alpine

# Pinned versions
ARG SPOTBUGS_VERSION=4.8.6
ARG FSB_VERSION=1.14.0

# Alpine base: apk avoids the apt GPG/IPv6 failures seen on the scan hosts.
RUN apk add --no-cache curl unzip bash python3

# Download and extract the find-sec-bugs CLI zip (bundles SpotBugs + FSB plugin)
RUN curl -fsSL \
    "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FSB_VERSION}/findsecbugs-cli-${FSB_VERSION}.zip" \
    -o /tmp/fsb.zip \
    && unzip -q /tmp/fsb.zip -d /opt/findsecbugs \
    && rm /tmp/fsb.zip \
    && chmod +x /opt/findsecbugs/findsecbugs.sh

ENV PATH="/opt/findsecbugs:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
