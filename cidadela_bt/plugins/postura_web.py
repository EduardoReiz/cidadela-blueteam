"""Auditoria de postura de um site — como um atacante o vê de fora, sem bater nele.

Este módulo é a única parte do framework que olha para FORA: em vez de auditar a
máquina local, inspeciona um alvo HTTP(S). Tudo não destrutivo — só GET/HEAD e
conexão TCP, o mesmo que um navegador faz. Nada de fuzzing, nada de payload,
nada que derrube ou altere o alvo.

O que é verificado:
  - redirecionamento HTTP → HTTPS (quem fala em claro pode ser escutado)
  - TLS: versão negociada e validade do certificado
  - cabeçalhos de segurança (HSTS, CSP, X-Frame-Options, etc.)
  - vazamento de versão em Server / X-Powered-By (entrega o alvo de CVE pronto)
  - caminhos sensíveis expostos (.env, .git, backups, dumps) — GET que só olha
    o código de status, nunca o conteúdo
  - listagem de diretório ligada
  - portas de rede abertas no host (connect scan enxuto de uma lista conhecida)
  - presença de Cloudflare e o alerta do IP de origem exposto

A separação de sempre: cada `avaliar_*` é função pura (recebe o que já foi
coletado e devolve achados), então a régua inteira é testável sem rede. Os
coletores fazem o I/O e ficam de fora do teste unitário.

Uso:
    python -m cidadela_bt rodar --apenas postura-web --opcao url=https://exemplo.com
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ..plugin import Contexto, Finding, Plugin, Severity


@dataclass(frozen=True)
class Item:
    severidade: Severity
    titulo: str
    descricao: str
    recomendacao: str
    recurso: str = ""
    referencia: str = "OWASP Secure Headers / CIS"
    evidencia: dict[str, Any] = field(default_factory=dict)


# cabeçalho -> (severidade se faltar, o que ele protege, como ligar)
CABECALHOS = {
    "strict-transport-security": (
        Severity.MEDIUM, "Sem HSTS: o navegador pode ser induzido a falar em HTTP claro.",
        "Envie Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    "content-security-policy": (
        Severity.MEDIUM, "Sem CSP: script injetado na página executa sem freio (XSS).",
        "Defina uma Content-Security-Policy, começando restritiva."),
    "x-content-type-options": (
        Severity.LOW, "Sem X-Content-Type-Options: o navegador adivinha tipo de arquivo.",
        "Envie X-Content-Type-Options: nosniff."),
    "x-frame-options": (
        Severity.LOW, "Sem X-Frame-Options nem CSP frame-ancestors: a página pode ser "
        "embutida para clickjacking.",
        "Envie X-Frame-Options: DENY (ou frame-ancestors na CSP)."),
    "referrer-policy": (
        Severity.LOW, "Sem Referrer-Policy: a URL atual vaza para sites de terceiros.",
        "Envie Referrer-Policy: strict-origin-when-cross-origin."),
}

# portas que, abertas para a internet, merecem atenção (porquê)
PORTAS_RISCO: dict[int, tuple[Severity, str]] = {
    21: (Severity.MEDIUM, "FTP: credencial em claro e histórico de falhas"),
    22: (Severity.LOW, "SSH: ok se restrito; exposto à internet vira alvo de força bruta"),
    23: (Severity.HIGH, "Telnet: tudo em claro, não deveria existir"),
    445: (Severity.HIGH, "SMB exposto à internet: vetor de ransomware"),
    3306: (Severity.HIGH, "MySQL exposto: banco não devia ser alcançável de fora"),
    3389: (Severity.HIGH, "RDP exposto: alvo campeão de força bruta e ransomware"),
    5432: (Severity.HIGH, "PostgreSQL exposto: banco não devia ser alcançável de fora"),
    6379: (Severity.HIGH, "Redis exposto: sem senha, obedece quem chegar"),
    9200: (Severity.HIGH, "Elasticsearch exposto: vazamento de dados clássico"),
    27017: (Severity.HIGH, "MongoDB exposto: vazamento de dados clássico"),
    8080: (Severity.LOW, "HTTP alternativo: confira se é painel que não devia estar público"),
}
PORTAS_PADRAO = (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379,
                 8080, 8443, 9200, 27017)

# caminhos que não deviam responder 200 — vazam código, segredo ou backup
CAMINHOS_SENSIVEIS = (
    "/.env", "/.git/HEAD", "/.git/config", "/config.php", "/wp-config.php.bak",
    "/.htaccess", "/backup.zip", "/backup.sql", "/dump.sql", "/db.sqlite",
    "/.DS_Store", "/phpinfo.php", "/server-status", "/.aws/credentials",
    "/id_rsa", "/.ssh/id_rsa", "/composer.lock", "/package-lock.json",
)


def avaliar_redirecionamento(http_para_https: bool | None) -> list[Item]:
    if http_para_https is None:
        return []
    if http_para_https:
        return []
    return [Item(Severity.MEDIUM, "HTTP não redireciona para HTTPS",
                 "A porta 80 serve conteúdo sem forçar a ida para HTTPS; dá para escutar "
                 "ou adulterar a sessão no meio do caminho.",
                 "Redirecione todo HTTP para HTTPS (301) e ative HSTS.",
                 recurso="http://", referencia="OWASP TLS")]


def avaliar_tls(info: dict) -> list[Item]:
    """`info`: {'versao': 'TLSv1.2', 'dias_para_expirar': int} — ou vazio se falhou."""
    if not info:
        return [Item(Severity.INFO, "Não foi possível inspecionar o TLS",
                     "O handshake TLS não completou (host fora do ar, porta 443 fechada "
                     "ou nome não resolveu).",
                     "Confirme que o site responde em HTTPS.", recurso="TLS")]
    itens: list[Item] = []
    versao = str(info.get("versao") or "")
    if versao in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        itens.append(Item(Severity.HIGH, f"TLS obsoleto aceito ({versao})",
                          f"O servidor negociou {versao}, protocolo quebrado.",
                          "Aceite só TLS 1.2 e 1.3; desligue o resto.",
                          recurso="TLS", referencia="OWASP TLS",
                          evidencia={"versao": versao}))
    dias = info.get("dias_para_expirar")
    if isinstance(dias, int):
        if dias < 0:
            itens.append(Item(Severity.HIGH, "Certificado TLS vencido",
                              f"O certificado venceu há {-dias} dias; o navegador barra o acesso.",
                              "Renove o certificado (com Cloudflare, confira o modo de SSL).",
                              recurso="Certificado TLS", evidencia={"dias": dias}))
        elif dias <= 14:
            itens.append(Item(Severity.MEDIUM, "Certificado TLS perto de vencer",
                              f"O certificado vence em {dias} dias.",
                              "Garanta a renovação automática.",
                              recurso="Certificado TLS", evidencia={"dias": dias}))
    return itens


def avaliar_cabecalhos(headers: dict[str, str]) -> list[Item]:
    """`headers` com as chaves já em minúsculo."""
    itens: list[Item] = []
    tem_csp = "content-security-policy" in headers
    for chave, (sev, por_que, como) in CABECALHOS.items():
        if chave in headers:
            continue
        # X-Frame-Options é dispensável se a CSP já traz frame-ancestors
        if chave == "x-frame-options" and tem_csp and \
                "frame-ancestors" in headers.get("content-security-policy", "").lower():
            continue
        itens.append(Item(sev, f"Cabeçalho de segurança ausente: {chave}",
                          por_que, como, recurso=chave,
                          referencia="OWASP Secure Headers"))
    return itens


def avaliar_divulgacao(headers: dict[str, str]) -> list[Item]:
    """Server/X-Powered-By com número de versão entrega o alvo de CVE de bandeja."""
    itens: list[Item] = []
    for chave in ("server", "x-powered-by", "x-aspnet-version"):
        valor = headers.get(chave, "")
        if valor and any(c.isdigit() for c in valor):
            # 'cloudflare' sem versão não é vazamento; '/1.2.3' é
            if chave == "server" and valor.strip().lower() == "cloudflare":
                continue
            itens.append(Item(Severity.LOW, f"Versão de software divulgada em {chave}",
                              f"O cabeçalho {chave} entrega '{valor}', que diz ao atacante "
                              "exatamente qual CVE tentar.",
                              f"Remova ou mascare o número de versão no cabeçalho {chave}.",
                              recurso=chave, referencia="OWASP", evidencia={chave: valor}))
    return itens


def avaliar_caminhos(resultados: dict[str, int]) -> list[Item]:
    """`resultados`: caminho -> código de status. 200/206 = exposto."""
    expostos = [c for c, status in resultados.items() if status in (200, 206)]
    if not expostos:
        return []
    criticos = {"/.env", "/.git/config", "/.git/HEAD", "/id_rsa", "/.ssh/id_rsa",
                "/.aws/credentials", "/backup.sql", "/dump.sql", "/db.sqlite"}
    achados: list[Item] = []
    for caminho in expostos:
        eh_critico = caminho in criticos
        achados.append(Item(
            Severity.CRITICAL if eh_critico else Severity.HIGH,
            f"Caminho sensível exposto: {caminho}",
            f"{caminho} respondeu 200. "
            + ("Isso tende a conter segredo, chave ou código-fonte."
               if eh_critico else "Isso não deveria ser servido ao público."),
            "Bloqueie esse caminho no servidor/Cloudflare e, se vazou segredo, "
            "ROTACIONE a chave — tratar como comprometida.",
            recurso=caminho, referencia="OWASP A05 / CWE-538",
            evidencia={"status": resultados[caminho]}))
    return achados


def avaliar_listagem(tem_listagem: bool) -> list[Item]:
    if not tem_listagem:
        return []
    return [Item(Severity.MEDIUM, "Listagem de diretório ativa",
                 "O servidor mostra o conteúdo de pastas (Index of /...), revelando "
                 "arquivos que o atacante nem sabia que existiam.",
                 "Desligue o autoindex/directory listing.",
                 recurso="Listagem de diretório", referencia="OWASP A05")]


def avaliar_portas(abertas: list[int]) -> list[Item]:
    itens: list[Item] = []
    for porta in sorted(set(abertas)):
        if porta in PORTAS_RISCO:
            sev, por_que = PORTAS_RISCO[porta]
            itens.append(Item(sev, f"Porta {porta} aberta para a internet",
                              f"{por_que}.",
                              "Feche a porta no firewall ou restrinja a IPs confiáveis; "
                              "o que for serviço interno não deve ser alcançável de fora.",
                              recurso=f"porta {porta}", referencia="CIS Controls 4",
                              evidencia={"porta": porta}))
    return itens


def avaliar_cloudflare(atras_de_cloudflare: bool, origem_exposta: bool | None) -> list[Item]:
    itens: list[Item] = []
    if not atras_de_cloudflare:
        itens.append(Item(Severity.INFO, "Cloudflare não detectado nas respostas",
                          "As respostas não trazem marca do Cloudflare. Se era pra estar "
                          "atrás dele, o tráfego pode estar indo direto no origin.",
                          "Confirme no painel se o registro está com o proxy (nuvem laranja) ligado.",
                          recurso="Cloudflare"))
        return itens

    if origem_exposta is True:
        itens.append(Item(Severity.HIGH, "IP de origem alcançável fora do Cloudflare",
                          "O servidor de origem responde direto, por fora do Cloudflare. "
                          "Todo o WAF, rate limit e anti-DDoS do Cloudflare viram enfeite: "
                          "basta o atacante achar o IP e bater nele. É o fosso do castelo "
                          "com a porta dos fundos destrancada.",
                          "No firewall do origin, aceite tráfego HTTP/HTTPS só das faixas de "
                          "IP do Cloudflare; recuse o resto.",
                          recurso="IP de origem", referencia="Cloudflare origin lockdown"))
    elif origem_exposta is None:
        itens.append(Item(Severity.INFO, "Exposição do IP de origem não verificada",
                          "Não dá para medir isto só de fora. Vale confirmar pelo servidor "
                          "se ele só aceita conexão vinda das faixas do Cloudflare.",
                          "Na fase de endurecimento do origin, travar o firewall nas faixas "
                          "do Cloudflare é o item nº 1.",
                          recurso="IP de origem", referencia="Cloudflare origin lockdown"))
    return itens


# ------------------------------------------------------------ coletores (I/O)
class PosturaWeb(Plugin):
    nome = "postura-web"
    descricao = "Audita a postura de um site (TLS, cabeçalhos, caminhos expostos, portas) sem atacá-lo."
    sistemas = ()  # multiplataforma: só precisa de rede

    def run(self, ctx: Contexto) -> list[Finding]:
        url = str(ctx.opcoes.get("url") or "").strip()
        if not url:
            return [self.finding(
                titulo="Nenhuma URL informada",
                severidade=Severity.INFO,
                descricao="Este módulo precisa de um alvo.",
                recomendacao="Rode com --opcao url=https://seu-site.com")]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        alvo = urlparse(url)
        host = alvo.hostname or ""

        itens: list[Item] = []
        headers, status_raiz = self._coletar_headers(url)
        itens += avaliar_redirecionamento(self._checar_redirecionamento(host))
        itens += avaliar_tls(self._coletar_tls(host, alvo.port or 443))
        if headers:
            itens += avaliar_cabecalhos(headers)
            itens += avaliar_divulgacao(headers)
            itens += avaliar_cloudflare(self._e_cloudflare(headers), None)
        else:
            itens.append(Item(Severity.INFO, "Site não respondeu ao HTTP",
                              f"Nenhuma resposta HTTP de {url} (status: {status_raiz}).",
                              "Confirme que o site está no ar e acessível desta máquina.",
                              recurso=url))
        itens += avaliar_caminhos(self._coletar_caminhos(url))
        itens += avaliar_listagem(self._checar_listagem(url))
        itens += avaliar_portas(self._scan_portas(host))

        return [self.finding(titulo=i.titulo, severidade=i.severidade, descricao=i.descricao,
                             recomendacao=i.recomendacao, recurso=i.recurso,
                             referencia=i.referencia, evidencia=i.evidencia) for i in itens]

    @staticmethod
    def _coletar_headers(url: str) -> tuple[dict[str, str], Any]:
        import urllib.error
        import urllib.request
        pedido = urllib.request.Request(url, method="GET",
                                        headers={"User-Agent": "cidadela-blueteam/1.0 (auditoria autorizada)"})
        try:
            with urllib.request.urlopen(pedido, timeout=15) as r:
                return {k.lower(): v for k, v in r.headers.items()}, r.status
        except urllib.error.HTTPError as e:
            # 4xx/5xx ainda traz cabeçalho útil
            return {k.lower(): v for k, v in (e.headers or {}).items()}, e.code
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return {}, None

    @staticmethod
    def _coletar_tls(host: str, porta: int) -> dict[str, Any]:
        if not host:
            return {}
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, porta), timeout=15) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    versao = tls.version()
                    cert = tls.getpeercert()
        except (OSError, ssl.SSLError, ValueError):
            return {}
        dados: dict[str, Any] = {"versao": versao}
        venc = (cert or {}).get("notAfter")
        if venc:
            try:
                quando = datetime.strptime(venc, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                dados["dias_para_expirar"] = (quando - datetime.now(timezone.utc)).days
            except ValueError:
                pass
        return dados

    @staticmethod
    def _checar_redirecionamento(host: str) -> bool | None:
        import urllib.error
        import urllib.request
        if not host:
            return None

        class SemSeguir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):  # não segue; só quero ver o Location
                return None

        try:
            abridor = urllib.request.build_opener(SemSeguir)
            with abridor.open(f"http://{host}/", timeout=15) as r:
                destino = r.headers.get("Location", "")
                return destino.startswith("https://")
        except urllib.error.HTTPError as e:
            return (e.headers or {}).get("Location", "").startswith("https://")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None

    @staticmethod
    def _coletar_caminhos(url: str) -> dict[str, int]:
        import urllib.error
        import urllib.request
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        resultados: dict[str, int] = {}
        for caminho in CAMINHOS_SENSIVEIS:
            pedido = urllib.request.Request(base + caminho, method="GET",
                                            headers={"User-Agent": "cidadela-blueteam/1.0"})
            try:
                with urllib.request.urlopen(pedido, timeout=10) as r:
                    resultados[caminho] = r.status
            except urllib.error.HTTPError as e:
                resultados[caminho] = e.code
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                resultados[caminho] = 0
        return resultados

    @staticmethod
    def _checar_listagem(url: str) -> bool:
        import urllib.error
        import urllib.request
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for caminho in ("/", "/uploads/", "/images/", "/static/", "/files/"):
            pedido = urllib.request.Request(base + caminho, method="GET",
                                            headers={"User-Agent": "cidadela-blueteam/1.0"})
            try:
                with urllib.request.urlopen(pedido, timeout=10) as r:
                    corpo = r.read(4096).decode("utf-8", errors="replace").lower()
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
                continue
            if "index of /" in corpo or "<title>directory listing" in corpo:
                return True
        return False

    @staticmethod
    def _scan_portas(host: str, portas: tuple[int, ...] = PORTAS_PADRAO) -> list[int]:
        """Connect scan enxuto: abre e fecha; não envia payload nenhum."""
        if not host:
            return []
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return []
        abertas: list[int] = []
        for porta in portas:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((ip, porta)) == 0:
                    abertas.append(porta)
        return abertas

    @staticmethod
    def _e_cloudflare(headers: dict[str, str]) -> bool:
        return (headers.get("server", "").lower() == "cloudflare"
                or "cf-ray" in headers or "cf-cache-status" in headers)
