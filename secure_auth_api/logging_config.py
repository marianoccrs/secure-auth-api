"""Configuração de logging estruturado para tentativas de acesso.

Cada tentativa de login vira uma linha de log JSON com username, resultado
e timestamp — nunca a senha (nem em texto puro, nem hash). Isso dá
rastreabilidade pra investigar incidentes (ex: um IP/username martelando
tentativas) sem guardar nada sensível no log.
"""

import json
import logging
import sys

ACCESS_LOGGER_NAME = "secure_auth_api.access"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if hasattr(record, "username"):
            payload["username"] = record.username
        if hasattr(record, "outcome"):
            payload["outcome"] = record.outcome
        return json.dumps(payload)


def get_access_logger() -> logging.Logger:
    logger = logging.getLogger(ACCESS_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def log_access_attempt(username: str, outcome: str, detail: str = "") -> None:
    logger = get_access_logger()
    logger.info(detail or outcome, extra={"username": username, "outcome": outcome})
