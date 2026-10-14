"""Caça a segredo exposto em arquivo — chave, token e senha largados no código.

Antes de um projeto ir pro ar, o vazamento mais comum não é falha sofisticada:
é a chave que ficou num `.env` commitado, a senha no `config`, o `id_rsa` dentro
do repositório. O atacante nem precisa invadir — ele lê. Este módulo procura
isso no código, em repouso, como complemento do `postura-web` (que olha o que
vaza por HTTP): um olha a porta, o outro olha a gaveta.

Dois cuidados que definem se presta:

1. **O segredo nunca aparece inteiro no relatório.** Cada achado mostra só o
   começo e o tamanho (ex.: `ghp_abcd…[40]`). Scanner que imprime a chave
   crua só move o vazamento de lugar.

2. **Assinatura forte x contexto fraco.** Prefixo conhecido (AKIA, ghp_, BEGIN
   PRIVATE KEY) é quase certeza. Já "qualquer coisa com muita entropia" ou
   `senha = ...` é fraco: hash, asset minificado e placeholder (`your_key_here`,
   `changeme`, `${VAR}`) enchem o relatório de mentira. Placeholder é filtrado;
   atribuição genérica só conta se o valor não parecer exemplo.

Se o arquivo está rastreado pelo git, a gravidade sobe: aí o segredo não está só
na máquina, está no histórico que se compartilha e se publica.

Tudo só leitura.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..plugin import Contexto, Finding, Plugin, Severity

MAX_BYTES = 2_000_000          # arquivo maior que isto é provavelmente dado, não código
MAX_LINHA = 4000               # linha gigante = minificado; não vale caçar segredo nela
MAX_ACHADOS = 200

PASTAS_IGNORADAS = frozenset({
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    "vendor", ".idea", ".vscode", "site-packages", ".mypy_cache", ".pytest_cache",
    "coverage", ".next", "target",
})
EXT_IGNORADAS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".pyc", ".class", ".o",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav", ".mov", ".bin",
    ".map", ".lock", ".min.js", ".min.css",
})
# arquivos que são segredo pelo próprio nome
NOMES_CHAVE = (
    (re.compile(r"(?:^|[/\\._])id_(?:rsa|dsa|ecdsa|ed25519)$", re.I), Severity.CRITICAL,
     "chave SSH privada"),
    (re.compile(r"\.(pem|key|pfx|p12|keystore|jks)$", re.I), Severity.HIGH,
     "arquivo de chave/certificado privado"),
    (re.compile(r"(^|[/\\])\.env(\.|$)", re.I), Severity.HIGH,
     "arquivo de variáveis de ambiente (costuma guardar segredo)"),
    (re.compile(r"\.(ovpn|rdp)$", re.I), Severity.MEDIUM,
     "perfil de acesso (VPN/RDP), pode conter credencial"),
)

# (nome, regex, severidade, descrição). Prefixos conhecidos = assinatura forte.
REGRAS: tuple[tuple[str, re.Pattern[str], Severity, str], ...] = (
    ("chave-privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     Severity.CRITICAL, "cabeçalho de chave privada embutida"),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     Severity.HIGH, "chave de acesso AWS"),
    ("stripe-live", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
     Severity.CRITICAL, "chave secreta de produção da Stripe"),
    ("github-token", re.compile(r"\b(?:gh[posru]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
     Severity.HIGH, "token do GitHub"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     Severity.HIGH, "chave de API do Google"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     Severity.HIGH, "token do Slack"),
    ("telegram-bot", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{30,}\b"),
     Severity.HIGH, "token de bot do Telegram"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     Severity.MEDIUM, "JSON Web Token (pode conter sessão/credencial)"),
    ("url-com-credencial", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@", re.I),
     Severity.HIGH, "URL com usuário e senha embutidos"),
)

# nome_do_lado_esquerdo = valor  (aspas ou valor cru, como em arquivo .env)
_LINHA_ATRIB = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_\-]*)\s*[:=]\s*"""
    r"""(?:"([^"]{8,})"|'([^']{8,})'|([^\s'";,]{8,}))""")

# a variável/chave indica segredo? (procurada como componente do nome)
_IDENT_SENSIVEL = re.compile(
    r"(?i)(pass(?:word|wd)?|senha|secret|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|priv(?:ate)?[_-]?key|auth[_-]?token|token|credential|"
    r"credencial|pwd)")

# valor que é referência de código (ler de ambiente/config), não um literal
_REFERENCIA = re.compile(r"[\[\]()]|environ|getenv|process\.env|os\.environ")

_PLACEHOLDER = re.compile(
    r"(?i)(example|exemplo|changeme|troque|your[_-]?|seu[_-]?|placeholder|dummy|"
    r"sample|test(e)?|xxxx+|\.\.\.|<[^>]+>|\$\{|\{\{|%[a-z_]+%|here|redacted|"
    r"insira|coloque|troca[r]?)")


@dataclass(frozen=True)
class Achado:
    regra: str
    severidade: Severity
    descricao: str
    trecho: str                 # já mascarado
    linha: int = 0


@dataclass(frozen=True)
class Item:
    severidade: Severity
    titulo: str
    descricao: str
    recomendacao: str
    recurso: str = ""
    referencia: str = "OWASP A05 / CWE-798 (credencial embutida)"
    evidencia: dict[str, Any] = field(default_factory=dict)


def mascarar(segredo: str) -> str:
    """Mostra o bastante pra reconhecer, de menos pra vazar: 'ghp_abcd…[40]'."""
    s = segredo.strip()
    if len(s) <= 8:
        return "•" * len(s) + f"[{len(s)}]"
    return f"{s[:4]}…{s[-2:]}[{len(s)}]"


def e_placeholder(valor: str) -> bool:
    """Valor de exemplo/modelo não é segredo de verdade."""
    v = valor.strip()
    if _PLACEHOLDER.search(v):
        return True
    if len(set(v)) <= 3:                       # 'xxxxxxxx', 'aaaaaaaa'
        return True
    return False


def parece_segredo(valor: str) -> bool:
    """O valor atribuído tem cara de segredo real, não de placeholder nem de código?

    Rejeita exemplo (`your_key`), referência de código (`os.environ[...]`) e
    texto comum sem entropia ('João Silva'). Aceita o que tem mistura de
    caractere ou comprimento de chave.
    """
    v = valor.strip()
    if len(v) < 8 or e_placeholder(v) or _REFERENCIA.search(v):
        return False
    if len(v) >= 20:
        return True
    tem_letra = any(c.isalpha() for c in v)
    tem_digito = any(c.isdigit() for c in v)
    tem_simbolo = any(not c.isalnum() for c in v)
    return tem_letra and (tem_digito or tem_simbolo)


def escanear_texto(texto: str, *, nome: str = "") -> list[Achado]:
    """Varre um texto e devolve os segredos achados, já mascarados. Função pura."""
    achados: list[Achado] = []
    vistos: set[tuple[str, int, str]] = set()

    for num, linha in enumerate(texto.splitlines(), 1):
        if len(linha) > MAX_LINHA:
            continue

        for regra, padrao, sev, desc in REGRAS:
            for m in padrao.finditer(linha):
                trecho = mascarar(m.group(0))
                chave = (regra, num, trecho)
                if chave in vistos:
                    continue
                vistos.add(chave)
                achados.append(Achado(regra, sev, desc, trecho, num))

        for m in _LINHA_ATRIB.finditer(linha):
            ident = m.group(1)
            if not _IDENT_SENSIVEL.search(ident):
                continue
            valor = m.group(2) or m.group(3) or m.group(4) or ""
            if not parece_segredo(valor):
                continue
            trecho = mascarar(valor)
            # se uma regra forte já pegou esse mesmo valor na linha, não duplica
            if trecho in {a.trecho for a in achados if a.linha == num}:
                continue
            chave = ("atribuicao", num, trecho)
            if chave in vistos:
                continue
            vistos.add(chave)
            achados.append(Achado("atribuicao-sensivel", Severity.MEDIUM,
                                  f"valor atribuído a '{ident.lower()}'", trecho, num))
    return achados


def classificar_nome(caminho: str) -> tuple[Severity, str] | None:
    base = caminho.replace("\\", "/")
    for padrao, sev, desc in NOMES_CHAVE:
        if padrao.search(base):
            return sev, desc
    return None


def deve_ignorar(caminho: str) -> bool:
    partes = set(re.split(r"[/\\]", caminho.lower()))
    if partes & {p.lower() for p in PASTAS_IGNORADAS}:
        return True
    nome = os.path.basename(caminho).lower()
    return any(nome.endswith(ext) for ext in EXT_IGNORADAS)


class SegredoExposto(Plugin):
    nome = "segredo-exposto"
    descricao = "Varre o projeto atrás de chave, token e senha em arquivo (segredo mascarado no relatório)."
    sistemas = ()

    def run(self, ctx: Contexto) -> list[Finding]:
        raiz = str(ctx.opcoes.get("caminho") or os.getcwd())
        if not os.path.isdir(raiz):
            return [self.finding(titulo="Caminho inválido", severidade=Severity.INFO,
                                 descricao=f"{raiz} não é uma pasta.",
                                 recomendacao="Passe --opcao caminho=<pasta do projeto>.")]

        rastreados = self._arquivos_do_git(raiz)
        itens: list[Item] = []
        total_arquivos = 0

        for arquivo in self._listar(raiz):
            total_arquivos += 1
            rel = os.path.relpath(arquivo, raiz)
            no_git = rastreados is not None and rel.replace("\\", "/") in rastreados

            classe = classificar_nome(rel)
            if classe:
                sev, desc = classe
                itens.append(self._item_arquivo_chave(rel, sev, desc, no_git))

            for a in self._escanear_arquivo(arquivo):
                itens.append(self._item_segredo(rel, a, no_git))
                if len(itens) >= MAX_ACHADOS:
                    break
            if len(itens) >= MAX_ACHADOS:
                break

        if not itens:
            return [self.finding(
                titulo="Nenhum segredo exposto encontrado",
                severidade=Severity.INFO,
                descricao=f"Varridos {total_arquivos} arquivos em {raiz}; nada que pareça "
                          "chave, token ou senha embutida.",
                recomendacao="Mantenha segredo em variável de ambiente ou cofre, nunca no código.")]

        return [self.finding(titulo=i.titulo, severidade=i.severidade, descricao=i.descricao,
                             recomendacao=i.recomendacao, recurso=i.recurso,
                             referencia=i.referencia, evidencia=i.evidencia) for i in itens]

    @staticmethod
    def _item_segredo(rel: str, a: Achado, no_git: bool) -> Item:
        sev = a.severidade
        extra = ""
        if no_git and sev < Severity.CRITICAL:
            sev = Severity(min(int(sev) + 1, int(Severity.CRITICAL)))
            extra = " O arquivo está no git — o segredo foi para o histórico, que se compartilha."
        return Item(sev, f"Possível segredo em {rel}:{a.linha}",
                    f"{a.descricao} ({a.trecho}).{extra}",
                    "Remova o segredo do código, troque-o por variável de ambiente/cofre e "
                    "ROTACIONE a chave — a que vazou deve ser tratada como queimada."
                    + (" Como está no git, limpe também o histórico (git filter-repo)." if no_git else ""),
                    recurso=rel, evidencia={"linha": a.linha, "regra": a.regra,
                                            "trecho": a.trecho, "no_git": no_git})

    @staticmethod
    def _item_arquivo_chave(rel: str, sev: Severity, desc: str, no_git: bool) -> Item:
        if no_git and sev < Severity.CRITICAL:
            sev = Severity(min(int(sev) + 1, int(Severity.CRITICAL)))
        return Item(sev, f"Arquivo sensível no projeto: {rel}",
                    f"{rel} é {desc}." + (" E está rastreado pelo git." if no_git else ""),
                    "Tire do projeto, coloque no .gitignore e, se já foi commitado, "
                    "rotacione a chave e limpe o histórico.",
                    recurso=rel, referencia="CWE-312 (dado sensível em claro)",
                    evidencia={"no_git": no_git})

    # ---- coletores (só leitura) ----
    def _listar(self, raiz: str):
        for atual, dirs, arquivos in os.walk(raiz):
            dirs[:] = [d for d in dirs if d.lower() not in
                       {p.lower() for p in PASTAS_IGNORADAS}]
            for nome in arquivos:
                caminho = os.path.join(atual, nome)
                if deve_ignorar(caminho):
                    continue
                try:
                    if os.path.getsize(caminho) > MAX_BYTES:
                        continue
                except OSError:
                    continue
                yield caminho

    @staticmethod
    def _escanear_arquivo(caminho: str) -> list[Achado]:
        try:
            with open(caminho, encoding="utf-8", errors="ignore") as fh:
                return escanear_texto(fh.read(), nome=os.path.basename(caminho))
        except (OSError, ValueError):
            return []

    @staticmethod
    def _arquivos_do_git(raiz: str) -> set[str] | None:
        """Conjunto de caminhos rastreados pelo git, ou None se não for repositório."""
        try:
            r = subprocess.run(["git", "-C", raiz, "ls-files"],
                               capture_output=True, text=True, errors="replace",
                               timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        return {linha.strip() for linha in r.stdout.splitlines() if linha.strip()}
