"""Auditor de política de senha (Windows) — espelho DEFENSIVO do ataque a credencial.

Em vez de atacar hashes, verifica se a POLÍTICA do host dificulta o ataque:
comprimento mínimo, complexidade, histórico, bloqueio de conta e armazenamento
reversível. Lê a política via `secedit` (chaves independentes de idioma) e as
contas locais via `Get-LocalUser`. Só leitura.

Baseline alinhada a CIS / boas práticas atuais:
  - comprimento mínimo >= 14
  - complexidade ativada
  - histórico >= 24
  - bloqueio de conta ATIVO (limite de tentativas)
  - sem armazenamento de senha em texto reversível
Observação (NIST SP 800-63B / CIS atual): expiração periódica forçada NÃO é
mais recomendada, então "senha nunca expira" na política é tratado como INFO.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

from ..plugin import Contexto, Finding, Plugin, Severity

# (severidade, titulo, descricao, recomendacao)
Item = tuple[Severity, str, str, str]


def avaliar_politica(pol: dict[str, int]) -> list[Item]:
    """Avalia a política (dict de chaves do secedit). Função pura/testável."""
    itens: list[Item] = []

    ml = pol.get("MinimumPasswordLength")
    if ml is not None and ml < 14:
        sev = Severity.HIGH if ml < 8 else Severity.MEDIUM
        itens.append((sev, "Comprimento mínimo de senha fraco",
                      f"Mínimo atual: {ml} caracteres.",
                      "Defina pelo menos 14 caracteres (CIS)."))

    pc = pol.get("PasswordComplexity")
    if pc == 0:
        itens.append((Severity.MEDIUM, "Complexidade de senha desativada",
                      "Senhas podem ser simples (sem exigir variedade de caracteres).",
                      "Ative a complexidade de senha."))

    hist = pol.get("PasswordHistorySize")
    if hist is not None and hist < 24:
        itens.append((Severity.LOW, "Histórico de senha curto",
                      f"Lembra apenas {hist} senhas anteriores.",
                      "Aumente para 24 (evita reuso de senha antiga)."))

    lock = pol.get("LockoutBadCount")
    if lock in (0, None):
        itens.append((Severity.HIGH, "Bloqueio de conta desativado",
                      "Não há limite de tentativas de senha — facilita força bruta.",
                      "Defina um limite (ex.: 10) com duração de bloqueio >= 15 min."))

    if pol.get("ClearTextPassword") == 1:
        itens.append((Severity.CRITICAL, "Senhas armazenadas em texto reversível",
                      "A política permite guardar senha de forma recuperável.",
                      "Desative 'armazenar senha usando criptografia reversível'."))

    return itens


def avaliar_contas(contas: list[dict]) -> list[Item]:
    """Avalia contas locais. Função pura/testável."""
    itens: list[Item] = []
    for c in contas:
        nome = c.get("Name", "?")
        habilitada = bool(c.get("Enabled"))
        exige_senha = c.get("PasswordRequired")

        if habilitada and exige_senha is False:
            itens.append((Severity.CRITICAL, f"Conta habilitada sem exigir senha: {nome}",
                          "A conta pode logar sem senha (login em branco).",
                          "Exija senha ou desabilite a conta."))

        if habilitada and nome.lower() in ("guest", "convidado"):
            itens.append((Severity.MEDIUM, "Conta de convidado habilitada",
                          "A conta Guest/Convidado está ativa.",
                          "Desabilite a conta de convidado."))
    return itens


class PoliticaSenhaAudit(Plugin):
    nome = "politica-senha-audit"
    descricao = "Audita política de senha e contas locais (força, complexidade, bloqueio)."
    sistemas = ("Windows",)

    def run(self, ctx: Contexto) -> list[Finding]:
        achados: list[Finding] = []

        pol = self._coletar_politica()
        if not pol:
            achados.append(self.finding(
                titulo="Não foi possível ler a política de senha",
                severidade=Severity.INFO,
                descricao="secedit não retornou dados (normalmente requer executar como Administrador).",
                recomendacao="Rode o auditor em um prompt elevado para esta checagem.",
            ))
        else:
            for sev, titulo, desc, rec in avaliar_politica(pol):
                achados.append(self.finding(titulo=titulo, severidade=sev, descricao=desc,
                                            recomendacao=rec, recurso="Política local de senha",
                                            evidencia={k: pol.get(k) for k in
                                                       ("MinimumPasswordLength", "PasswordComplexity",
                                                        "PasswordHistorySize", "LockoutBadCount",
                                                        "ClearTextPassword")},
                                            referencia="CIS / NIST SP 800-63B"))

        for sev, titulo, desc, rec in avaliar_contas(self._coletar_contas()):
            achados.append(self.finding(titulo=titulo, severidade=sev, descricao=desc,
                                        recomendacao=rec, recurso="Contas locais",
                                        referencia="CIS Controls 5"))
        return achados

    # ---- coletores (só leitura) ----
    def _coletar_politica(self) -> dict[str, int]:
        destino = os.path.join(tempfile.gettempdir(), "cidadela_secpol.inf")
        try:
            subprocess.run(["secedit", "/export", "/cfg", destino, "/areas", "SECURITYPOLICY", "/quiet"],
                           capture_output=True, text=True, errors="replace", timeout=40, check=False)
        except (OSError, subprocess.SubprocessError):
            return {}
        if not os.path.isfile(destino):
            return {}
        pol: dict[str, int] = {}
        try:
            # o arquivo do secedit é UTF-16
            with open(destino, encoding="utf-16", errors="replace") as fh:
                dentro = False
                for linha in fh:
                    s = linha.strip()
                    if s.startswith("["):
                        dentro = s.lower() == "[system access]"
                        continue
                    if dentro and "=" in s:
                        chave, _, valor = s.partition("=")
                        chave, valor = chave.strip(), valor.strip()
                        try:
                            pol[chave] = int(valor)
                        except ValueError:
                            pass
        finally:
            try:
                os.remove(destino)
            except OSError:
                pass
        return pol

    def _coletar_contas(self) -> list[dict]:
        ps = ("Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | ConvertTo-Json -Compress")
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                               capture_output=True, text=True, errors="replace", timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return []
        saida = (r.stdout or "").strip()
        if not saida:
            return []
        try:
            dados = json.loads(saida)
        except json.JSONDecodeError:
            return []
        return dados if isinstance(dados, list) else [dados]
