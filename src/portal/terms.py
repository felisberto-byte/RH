"""Termo de Adesão ao Uso de Meios Eletrônicos (versionado).

Fundamento: MP 2.200-2/2001, art. 10, § 2º — meios de comprovação de autoria
e integridade não ICP-Brasil valem quando "admitido pelas partes como válido
ou aceito pela pessoa a quem for oposto o documento". O aceite do termo é
registrado com a mesma evidência dos documentos e cada manifestação
posterior referencia a versão vigente.

Para colaboradores já admitidos, recomenda-se coletar o termo também em
papel ou gov.br e registrá-lo com ``channel="papel"``/``"govbr"``.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import sha256_hex
from portal.models import AdhesionAcceptance, AdhesionTerm, Employee

DEFAULT_TERM_V1 = """TERMO DE ADESÃO AO USO DE MEIOS ELETRÔNICOS — versão 1

1. Concordo em receber, consultar e manifestar ciência ou concordância sobre documentos \
da relação de emprego (recibos de pagamento, contratos, termos aditivos, avisos e outros) \
por meio do Portal do Colaborador da empresa.

2. Reconheço como meio válido de comprovação de autoria e integridade, nos termos do \
art. 10, § 2º, da Medida Provisória nº 2.200-2/2001, a minha manifestação eletrônica \
realizada no Portal mediante: (a) autenticação com meu usuário e senha corporativos \
(Active Directory), pessoais e intransferíveis; (b) confirmação no ato da manifestação \
(nova digitação da senha e, quando habilitado, código do meu aplicativo autenticador); \
(c) registro de data e hora, endereço IP, navegador e do código (hash SHA-256) do documento.

3. Os documentos são assinados digitalmente pela empresa com certificado ICP-Brasil, e \
cada manifestação gera um comprovante que posso baixar a qualquer tempo.

4. Comprometo-me a não compartilhar minha senha nem meu aplicativo autenticador e a \
comunicar imediatamente ao RH/TI qualquer suspeita de uso indevido.

5. A ciência de um recibo de pagamento não implica concordância com seus valores; \
posso registrar divergência pelo próprio Portal ou junto ao RH. O pagamento do salário \
não depende da manifestação no Portal.

6. Posso solicitar ao RH, a qualquer momento, cópia dos meus documentos e o \
atendimento em meio físico.

7. Meus dados pessoais são tratados para cumprimento de obrigações legais e execução \
do contrato de trabalho (Lei nº 13.709/2018, art. 7º, II, V e VI), conforme o Aviso de \
Privacidade da empresa.
"""


class TermService:
    def __init__(self, db: Session):
        self.db = db

    def active(self) -> AdhesionTerm | None:
        return self.db.scalar(
            select(AdhesionTerm).where(AdhesionTerm.active.is_(True)).order_by(AdhesionTerm.id.desc())
        )

    def publish(self, version: str, text: str, *, published_by: str) -> AdhesionTerm:
        version, text = version.strip(), text.strip()
        if not version or len(text) < 50:
            raise ValueError("Informe a versão e o texto completo do termo.")
        if self.db.scalar(select(AdhesionTerm).where(AdhesionTerm.version == version)):
            raise ValueError("Já existe um termo com esta versão.")
        for t in self.db.scalars(select(AdhesionTerm).where(AdhesionTerm.active.is_(True))):
            t.active = False
        term = AdhesionTerm(
            version=version, text=text, sha256=sha256_hex(text), published_by=published_by
        )
        self.db.add(term)
        self.db.flush()
        audit.record(
            self.db,
            action="TERMO_PUBLICADO",
            actor_type="rh",
            actor_ref=published_by,
            data={"versao": version, "sha256": term.sha256},
        )
        return term

    def acceptance_of(self, employee_id: int, term: AdhesionTerm) -> AdhesionAcceptance | None:
        return self.db.scalar(
            select(AdhesionAcceptance).where(
                AdhesionAcceptance.employee_id == employee_id,
                AdhesionAcceptance.term_id == term.id,
            )
        )

    def pending_for(self, employee_id: int) -> AdhesionTerm | None:
        term = self.active()
        if term is None or self.acceptance_of(employee_id, term) is not None:
            return None
        return term

    def register(
        self,
        employee: Employee,
        term: AdhesionTerm,
        *,
        channel: str,
        actor_type: str,
        registered_by: str,
        object_guid: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        note: str | None = None,
        evidence_json: str | None = None,
        receipt: tuple[str, str] | None = None,
    ) -> AdhesionAcceptance:
        """Registra a adesão. ``channel="portal"`` só pode vir do próprio
        colaborador autenticado (``actor_type="colaborador"``); o RH registra
        apenas adesões coletadas fora (papel/gov.br)."""
        if channel not in ("portal", "papel", "govbr"):
            raise ValueError("canal inválido")
        if channel == "portal" and actor_type != "colaborador":
            raise ValueError("adesão pelo portal só pode ser feita pelo próprio colaborador")
        if channel != "portal" and actor_type != "rh":
            raise ValueError("adesão externa deve ser registrada pelo RH")
        if self.acceptance_of(employee.id, term) is not None:
            raise ValueError("Termo já aceito.")
        acc = AdhesionAcceptance(
            employee_id=employee.id,
            term_id=term.id,
            channel=channel,
            ad_object_guid=object_guid,
            ip=ip,
            user_agent=(user_agent or "")[:512] or None,
            registered_by=registered_by,
            note=note,
            evidence_json=evidence_json,
            evidence_sha256=audit.sha256_hex(evidence_json) if evidence_json else None,
            receipt_key=receipt[0] if receipt else None,
            receipt_sha256=receipt[1] if receipt else None,
        )
        self.db.add(acc)
        self.db.flush()
        audit.record(
            self.db,
            action="TERMO_ACEITO",
            actor_type=actor_type,
            actor_ref=registered_by,
            ip=ip,
            user_agent=user_agent,
            data={
                "matricula": employee.matricula,
                "versao": term.version,
                "sha256_termo": term.sha256,
                "canal": channel,
                "objectGUID": object_guid,
                "observacao": note,
                "evidencia_sha256": acc.evidence_sha256,
            },
        )
        return acc
