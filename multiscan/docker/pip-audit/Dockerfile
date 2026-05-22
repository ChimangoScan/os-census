FROM python:3.12.9-slim

ARG PIP_AUDIT_VERSION=2.9.0

RUN pip install --no-cache-dir pip-audit==${PIP_AUDIT_VERSION}

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
