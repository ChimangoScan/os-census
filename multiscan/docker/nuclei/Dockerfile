# nuclei with the template repo baked in — the upstream image ships no
# templates and the runtime cache/prepare proved unreliable on the scan hosts.
FROM alpine:3.21 AS templates
RUN apk add --no-cache git \
 && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /nuclei-templates \
 && rm -rf /nuclei-templates/.git

FROM projectdiscovery/nuclei:latest
COPY --from=templates /nuclei-templates /root/nuclei-templates
