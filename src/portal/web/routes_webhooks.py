from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from portal.documents.docuseal_flow import handle_event
from portal.integrations.docuseal import DocusealError, verify_signature
from portal.web.deps import app_ctx, get_db

router = APIRouter(prefix="/webhooks")
log = logging.getLogger(__name__)


@router.post("/docuseal")
async def docuseal_webhook(request: Request, db: Session = Depends(get_db)):
    ctx = app_ctx(request)
    client = ctx.docuseal
    if client is None:
        raise HTTPException(status_code=404)
    body = await request.body()
    if len(body) > 1024 * 1024:
        raise HTTPException(status_code=413)
    secret = ctx.settings.docuseal_webhook_secret.get_secret_value()
    if not verify_signature(secret, body, request.headers.get("x-docuseal-signature")):
        raise HTTPException(status_code=401, detail="assinatura do webhook inválida")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400) from exc
    try:
        result = await run_in_threadpool(
            lambda: handle_event(
                db, ctx.storage, client, payload, sealer=ctx.sealer, settings=ctx.settings
            )
        )
    except DocusealError as exc:
        db.rollback()
        log.warning("webhook DocuSeal falhou: %s", exc)
        # 5xx faz o DocuSeal reenviar (backoff exponencial, até 12 tentativas).
        raise HTTPException(status_code=502, detail="falha ao processar") from exc
    return {"resultado": result}
