"""Ponto de entrada ASGI: ``uvicorn portal.web.asgi:app``."""

from portal.logs import setup_logging
from portal.web.app import create_app

setup_logging()
app = create_app()
