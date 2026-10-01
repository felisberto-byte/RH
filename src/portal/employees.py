"""Cadastro de colaboradores (importação CSV) e revogação de sessões."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from portal.models import Employee, UserSession

MAX_CSV_BYTES = 10 * 1024 * 1024
_FALSE = ("0", "nao", "não", "false", "n", "inativo")
_TRUE = ("1", "sim", "true", "s", "ativo")


class EmployeeImportError(ValueError):
    pass


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    deactivated: list[int] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.created + self.updated


def decode_csv(raw: bytes) -> str:
    if len(raw) > MAX_CSV_BYTES:
        raise EmployeeImportError("Arquivo maior que 10 MB.")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _clean(value: str) -> str:
    # NBSP e espaços Unicode vindos de planilhas viram espaço comum.
    return " ".join((value or "").replace(" ", " ").split())


def parse_employees_csv(text: str) -> list[dict]:
    """CSV com cabeçalho ``matricula;nome;cpf;email;ativo`` (separador ; ou ,).

    ``ativo`` vazio/ausente significa "não alterar" para quem já existe (nunca
    reativa por omissão um colaborador desligado) e "ativo" para quem é novo.
    """
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,") if sample else csv.excel
    except csv.Error:
        dialect = csv.excel
    rows: list[dict] = []
    seen_mat: dict[str, int] = {}
    seen_cpf: dict[str, int] = {}
    for i, row in enumerate(csv.DictReader(io.StringIO(text), dialect=dialect), start=2):
        row = {(k or "").strip().lower(): _clean(v or "") for k, v in row.items() if k}
        if not row.get("matricula") or not row.get("nome"):
            raise EmployeeImportError(f"Linha {i}: matrícula e nome são obrigatórios.")
        mat = row["matricula"]
        if mat in seen_mat:
            raise EmployeeImportError(f"Linha {i}: matrícula repetida (linha {seen_mat[mat]}).")
        seen_mat[mat] = i
        cpf = re.sub(r"\D", "", row.get("cpf", "")) or None
        if cpf and len(cpf) != 11:
            raise EmployeeImportError(f"Linha {i}: CPF inválido.")
        if cpf:
            if cpf in seen_cpf:
                raise EmployeeImportError(f"Linha {i}: CPF repetido (linha {seen_cpf[cpf]}).")
            seen_cpf[cpf] = i
        ativo_raw = row.get("ativo", "").lower()
        if ativo_raw and ativo_raw not in _FALSE + _TRUE:
            raise EmployeeImportError(f"Linha {i}: valor de 'ativo' inválido ({ativo_raw}).")
        rows.append(
            {
                "line": i,
                "matricula": mat,
                "nome": row["nome"][:200],
                "cpf": cpf,
                "email": row.get("email") or None,
                "ativo": None if not ativo_raw else ativo_raw in _TRUE,
            }
        )
    return rows


def upsert_employees(db: Session, rows: list[dict]) -> ImportResult:
    result = ImportResult()
    for r in rows:
        if r["cpf"]:
            other = db.scalar(
                select(Employee).where(Employee.cpf == r["cpf"], Employee.matricula != r["matricula"])
            )
            if other is not None:
                raise EmployeeImportError(
                    f"Linha {r['line']}: CPF já cadastrado para a matrícula {other.matricula}. "
                    "Para readmissão com nova matrícula, limpe o CPF do vínculo antigo antes."
                )
        emp = db.scalar(select(Employee).where(Employee.matricula == r["matricula"]))
        if emp is None:
            emp = Employee(matricula=r["matricula"], ativo=True if r["ativo"] is None else r["ativo"])
            db.add(emp)
            result.created += 1
        else:
            result.updated += 1
            if r["ativo"] is not None:
                if emp.ativo and not r["ativo"]:
                    result.deactivated.append(emp.id)
                emp.ativo = r["ativo"]
        emp.nome, emp.cpf, emp.email = r["nome"], r["cpf"], r["email"]
        db.flush()
    for emp_id in result.deactivated:
        revoke_sessions(db, emp_id)
    return result


def revoke_sessions(db: Session, employee_id: int) -> int:
    res = db.execute(
        update(UserSession)
        .where(UserSession.employee_id == employee_id, UserSession.revoked.is_(False))
        .values(revoked=True)
        .execution_options(synchronize_session=False)
    )
    return res.rowcount or 0  # type: ignore[attr-defined]
