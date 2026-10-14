"""Auditor de persistência (Windows) — espelho DEFENSIVO de técnicas de persistência.

Enumera, SOMENTE LEITURA, os pontos clássicos onde algo se registra para
iniciar sozinho e sinaliza os suspeitos:
  - Chaves Run/RunOnce (HKLM e HKCU)
  - Pastas de inicialização (Startup)
  - Tarefas agendadas (schtasks)

Mapeia para MITRE ATT&CK T1547 (Boot/Logon Autostart), T1053 (Scheduled Task).
NÃO cria, altera nem remove nada.

Qualidade de detecção: o discriminador principal é a ASSINATURA DIGITAL. Um
binário assinado por fabricante confiável em AppData é um app comum (Discord,
OneDrive...), não ameaça — por isso é suprimido. O que fica no relatório é o
que realmente merece olhar: não-assinado em pasta gravável, comando codificado,
LOLBin, ou executável em Temp/Downloads/Público.
"""

from __future__ import annotations

import os
import re
import subprocess
from functools import lru_cache
from typing import Iterator

from ..plugin import Contexto, Finding, Plugin, Severity

_LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "wmic.exe",
}

# Tier forte: pastas onde executável iniciando sozinho é quase sempre suspeito.
_TEMP_LIKE = re.compile(
    r"(\\temp\\|\\tmp\\|\\windows\\temp\\|\\downloads\\|\\users\\public\\|\\recycle)",
    re.IGNORECASE,
)
# Tier fraco: AppData é comum em apps por-usuário — só pesa se não for assinado.
_APPDATA = re.compile(r"\\appdata\\", re.IGNORECASE)

_ENCODED = re.compile(
    r"(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/]{16,}|frombase64string|[/-]w\s+hidden)",
    re.IGNORECASE,
)

Motivo = tuple[Severity, str]


def _primeiro_exe(comando: str) -> str:
    comando = comando.strip()
    if comando.startswith('"'):
        fim = comando.find('"', 1)
        caminho = comando[1:fim] if fim > 0 else comando[1:]
    else:
        caminho = comando.split()[0] if comando.split() else ""
    return os.path.basename(caminho).lower()


def caminho_exe(comando: str) -> str:
    """Caminho completo do executável (resolve aspas e variáveis de ambiente)."""
    comando = comando.strip()
    if comando.startswith('"'):
        fim = comando.find('"', 1)
        bruto = comando[1:fim] if fim > 0 else comando[1:]
    else:
        bruto = comando.split()[0] if comando.split() else ""
    return os.path.expandvars(bruto)


def tier_caminho(comando: str) -> str:
    """'temp' (forte), 'appdata' (fraco) ou 'outro'."""
    if _TEMP_LIKE.search(comando):
        return "temp"
    if _APPDATA.search(comando):
        return "appdata"
    return "outro"


def avaliar_comando(nome: str, comando: str) -> list[Motivo]:
    """Heurística pura (sem SO): devolve motivos ponderados por severidade."""
    motivos: list[Motivo] = []
    if not comando.strip():
        return motivos

    tier = tier_caminho(comando)
    if tier == "temp":
        motivos.append((Severity.HIGH, "executável em pasta temporária/downloads/pública"))
    elif tier == "appdata":
        motivos.append((Severity.LOW, "executável em AppData (comum em apps por-usuário)"))

    exe = _primeiro_exe(comando)
    if exe in _LOLBINS:
        motivos.append((Severity.MEDIUM, f"usa binário do sistema abusável ({exe})"))
    if _ENCODED.search(comando):
        motivos.append((Severity.HIGH, "comando codificado/oculto (-enc, base64, janela oculta)"))
    if " " in comando and not comando.strip().startswith('"') and ".exe " in comando.lower():
        if " " in comando.lower().split(".exe ", 1)[0]:
            motivos.append((Severity.MEDIUM, "caminho sem aspas com espaço (risco de sequestro de caminho)"))
    return motivos


def severidade_de(motivos: list[Motivo]) -> Severity:
    return max((s for s, _ in motivos), default=Severity.INFO)


@lru_cache(maxsize=256)
def resolver_lnk(caminho_lnk: str) -> str:
    """Resolve um atalho .lnk para 'alvo + argumentos' via WScript.Shell."""
    if not os.path.isfile(caminho_lnk):
        return ""
    ps = (
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('"
        + caminho_lnk + "');"
        "Write-Output ($s.TargetPath + ' ' + $s.Arguments)"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, errors="replace", timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (r.stdout or "").strip()


@lru_cache(maxsize=512)
def assinatura(caminho: str) -> str:
    """'valida' | 'nao_assinado' | 'desconhecido'. Usa Get-AuthenticodeSignature."""
    if not caminho or not os.path.isfile(caminho):
        return "desconhecido"
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{caminho}').Status"],
            capture_output=True, text=True, errors="replace", timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "desconhecido"
    status = (r.stdout or "").strip()
    if status == "Valid":
        return "valida"
    if status in ("NotSigned", "HashMismatch"):
        return "nao_assinado"
    return "desconhecido"


class PersistenciaAudit(Plugin):
    nome = "persistencia-audit"
    descricao = "Audita pontos de persistência do Windows (autoruns, tarefas); assinatura digital como filtro."
    sistemas = ("Windows",)

    def run(self, ctx: Contexto) -> list[Finding]:
        achados: list[Finding] = []
        for origem, nome, comando in self._coletar():
            motivos = avaliar_comando(nome, comando)
            if not motivos:
                continue

            tier = tier_caminho(comando)
            status = "nao_verificado"
            if tier in ("temp", "appdata"):
                status = assinatura(caminho_exe(comando))
                if status == "valida":
                    # Assinado por fabricante confiável: tira o peso do "está em pasta X".
                    motivos = [(s, m) for s, m in motivos
                               if "AppData" not in m and "temporária" not in m]
                    if not motivos:
                        continue  # era só um app legítimo — não polui o relatório
                elif status == "nao_assinado":
                    extra = Severity.HIGH if tier == "temp" else Severity.MEDIUM
                    motivos.append((extra, "binário NÃO assinado digitalmente"))

            achados.append(self.finding(
                titulo=f"Autostart suspeito: {nome}",
                severidade=severidade_de(motivos),
                descricao="; ".join(m for _, m in motivos),
                recurso=f"{origem} → {nome}",
                recomendacao="Confirme se é esperado. Se não reconhecer, investigue o "
                             "executável antes de remover.",
                evidencia={"origem": origem, "nome": nome, "comando": comando, "assinatura": status},
                referencia="MITRE ATT&CK T1547/T1053",
            ))
        return achados

    # ---- coletores (só leitura) ----
    def _coletar(self) -> Iterator[tuple[str, str, str]]:
        yield from self._run_keys()
        yield from self._startup_folders()
        yield from self._scheduled_tasks()

    def _run_keys(self) -> Iterator[tuple[str, str, str]]:
        import winreg

        caminhos = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
        ]
        for raiz, sub, rotulo in caminhos:
            try:
                with winreg.OpenKey(raiz, sub) as chave:
                    i = 0
                    while True:
                        try:
                            nome, valor, _ = winreg.EnumValue(chave, i)
                        except OSError:
                            break
                        yield rotulo, nome, str(valor)
                        i += 1
            except FileNotFoundError:
                continue

    def _startup_folders(self) -> Iterator[tuple[str, str, str]]:
        # A pasta Startup fica sempre em AppData/ProgramData, então o que importa
        # é o ALVO do atalho, não onde o .lnk está. Resolvemos os .lnk.
        ignorar = {"desktop.ini"}
        pastas = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for pasta in pastas:
            if not os.path.isdir(pasta):
                continue
            for item in os.listdir(pasta):
                if item.lower() in ignorar:
                    continue
                full = os.path.join(pasta, item)
                alvo = resolver_lnk(full) if item.lower().endswith(".lnk") else full
                yield "Startup", item, (alvo or full)

    def _scheduled_tasks(self) -> Iterator[tuple[str, str, str]]:
        try:
            saida = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, errors="replace", timeout=60, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return
        if not saida:
            return
        linhas = saida.splitlines()
        if not linhas:
            return
        cabecalho = [c.strip('"') for c in linhas[0].split('","')]
        try:
            i_nome = cabecalho.index("TaskName")
            i_cmd = cabecalho.index("Task To Run")
        except ValueError:
            return
        for linha in linhas[1:]:
            campos = [c.strip('"') for c in linha.split('","')]
            if len(campos) <= max(i_nome, i_cmd):
                continue
            nome, cmd = campos[i_nome], campos[i_cmd]
            if cmd and cmd not in ("Task To Run", "N/A", "COM handler"):
                yield "Tarefa agendada", nome, cmd
