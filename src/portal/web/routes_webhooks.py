from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from portal.documents.docuseal_flow import handle_event
from portal.integrations.docuseal import DocusealError, verify_signature
from portal.web.deps import AppContext, app_ctx

router = APIRouter(prefix="/webhooks")
log = logging.getLogger(__name__)
MAX_BODY = 1024 * 1024


def _process(ctx: AppContext, payload: dict) -> str:
    """Todo o trabalho de banco/armazenamento/assinatura roda numa thread, com
    sessão própria (nada bloqueante no laço de eventos)."""
    assert ctx.docuseal is not None
    with ctx.database.sessionmaker() as db:
        try:
            return handle_event(
                db, ctx.storage, ctx.docuseal, payload, sealer=ctx.sealer, settings=ctx.settings
            )
        except Exception:
            db.rollback()
            raise


@router.post("/docuseal")
async def docuseal_webhook(request: Request):
    ctx = app_ctx(request)
    if ctx.docuseal is None:
        raise HTTPException(status_code=404, detail="integração DocuSeal desativada")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise HTTPException(status_code=413, detail="corpo grande demais")
    secret = ctx.settings.docuseal_webhook_secret.get_secret_value()
    if not verify_signature(secret, bytes(body), request.headers.get("x-docuseal-signature")):
        raise HTTPException(status_code=401, detail="assinatura do webhook inválida")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="JSON inválido") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON inválido")
    try:
        result = await run_in_threadpool(_process, ctx, payload)
    except DocusealError as exc:
        log.warning("webhook DocuSeal falhou: %s", exc)
        # 5xx faz o DocuSeal reenviar (backoff exponencial, até 12 tentativas).
        raise HTTPException(status_code=502, detail="falha ao processar") from exc
    return {"resultado": result}
