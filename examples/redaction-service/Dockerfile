# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Reference customer redaction service (contracts/redaction/v1). An example
# sidecar, not a Fabric release artifact. Mount a shared volume at /run/fabric
# so the application container reaches the socket.
# Multi-arch index digest; Dependabot (docker, /examples/redaction-service) moves it.
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54

RUN useradd --system --uid 10001 --no-create-home redaction \
    && mkdir -p /run/fabric /etc/fabric-redaction \
    && chown redaction /run/fabric

COPY redaction_service.py /opt/fabric-redaction/redaction_service.py
COPY rules.example.json /etc/fabric-redaction/rules.json

USER 10001
ENTRYPOINT ["python", "/opt/fabric-redaction/redaction_service.py"]
CMD ["--listen", "unix:///run/fabric/redaction.sock", "--rules", "/etc/fabric-redaction/rules.json"]
