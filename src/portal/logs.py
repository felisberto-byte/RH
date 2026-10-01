"""Configuração de logs: JSON estruturado (Cloud Logging lê ``severity`` e
``message``) em produção; texto legível em desenvolvimento."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(),
        }
        if record.exc_info:
            payload["stack_trace"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: int = logging.INFO) -> None:
    fmt = os.environ.get("PORTAL_LOG_FORMAT") or (
        "json" if os.environ.get("PORTAL_ENV", "prod") == "prod" else "text"
    )
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
