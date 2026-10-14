"""Priorização de correção (patch) e de CVE — o que consertar primeiro.

Máquina nenhuma está 100% corrigida; o que separa defesa boa de defesa inútil é
a ORDEM. Este módulo monta essa fila.

Por que não é um "scanner de CVE" e sim um priorizador
------------------------------------------------------
Casar "tenho o Foo 2.3 instalado" com "existe CVE no Foo" por nome de produto
produz lixo com cara de certeza: CVE de outro fabricante, de outra versão, de
outro sistema. Um laudo errado que soa confiante é pior que nenhum laudo.

Então a espinha do módulo é fato local verificável:
  - idade do último patch do SO e reinício pendente (patch aplicado e não
    efetivado conta como não aplicado)
  - build do SO dentro ou fora de suporte
  - serviço de atualização desligado
  - software abandonado/sem suporte (fato histórico estável)
  - EXPOSIÇÃO: o que escuta em porta de rede, e se escuta para fora ou só para
    o próprio host — software exposto furado é urgente; o mesmo software sem
    socket aberto pode esperar a janela de manutenção

E a consulta de CVE entra como enriquecimento OPCIONAL (`--opcao online=1`),
com casamento de FAIXA DE VERSÃO pelo CPE que o próprio NVD devolve — não por
palavra-chave. Mesmo assim o achado sai rotulado como indício a confirmar,
porque nome de produto no CPE e nome no "Programas Instalados" divergem o tempo
todo.

Tudo só leitura: registro de software instalado, consultas de estado e, quando
pedido, uma chamada HTTP de leitura ao NVD.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Iterable

from ..plugin import Contexto, Finding, Plugin, Severity

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[assignment]

# A tabela de ciclo de vida é CONHECIMENTO, não medição: envelhece. A data fica
# registrada e vai no achado, para ninguém confiar nela cegamente depois.
TABELA_ATUALIZADA = "2026-10-07"

CHAVES_UNINSTALL = (
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
)

# build do Windows -> (nome comercial, fim de suporte Home/Pro em ISO)
BUILDS_WINDOWS: dict[int, tuple[str, str]] = {
    19041: ("Windows 10 2004", "2021-12-14"),
    19042: ("Windows 10 20H2", "2022-05-10"),
    19043: ("Windows 10 21H1", "2022-12-13"),
    19044: ("Windows 10 21H2", "2023-06-13"),
    19045: ("Windows 10 22H2", "2025-10-14"),
    22000: ("Windows 11 21H2", "2023-10-10"),
    22621: ("Windows 11 22H2", "2024-10-08"),
    22631: ("Windows 11 23H2", "2025-11-11"),
    26100: ("Windows 11 24H2", "2026-10-13"),
    26200: ("Windows 11 25H2", "2027-10-12"),
}

# (padrão no nome, versão até a qual está abandonado ou None p/ qualquer uma,
#  rótulo, severidade, motivo)
ABANDONADOS: tuple[tuple[str, str | None, str, Severity, str], ...] = (
    (r"\bpython\s*2(\.\d+)?\b", None, "Python 2", Severity.HIGH,
     "o Python 2 não recebe correção desde 2020"),
    (r"\bnode\.?js\b", "17.999", "Node.js antigo", Severity.MEDIUM,
     "versões de Node abaixo da 18 saíram de suporte"),
    (r"\bjava\b.*\b8\b|\bjre\s*8\b|\bjdk\s*8\b", None, "Java 8", Severity.MEDIUM,
     "o Java 8 público parou de receber atualização gratuita de segurança"),
    (r"flash\s*player", None, "Adobe Flash Player", Severity.HIGH,
     "o Flash morreu em 2020 e virou alvo fácil"),
    (r"\binternet\s*explorer\b", None, "Internet Explorer", Severity.HIGH,
     "o IE foi aposentado e não recebe mais correção"),
    (r"\bwinrar\b", "5.999", "WinRAR antigo", Severity.HIGH,
     "WinRAR abaixo da 6.23 tem falha de execução remota muito explorada (CVE-2023-38831)"),
    (r"\b7-?zip\b", "21.999", "7-Zip antigo", Severity.MEDIUM,
     "7-Zip abaixo da 22 tem falhas conhecidas de tratamento de arquivo"),
    (r"\bopenssl\b", "1.999", "OpenSSL 1.x", Severity.MEDIUM,
     "a série 1.x do OpenSSL saiu de suporte"),
    (r"\bredis\b", "3.999", "Redis for Windows", Severity.HIGH,
     "o porte do Redis para Windows (MSOpenTech) parou na 3.0.x em 2016 e nunca mais "
     "recebeu correção; pior, o Redis sem senha obedece a qualquer um que alcance a "
     "porta, e o 6379 costuma ficar aberto para a rede toda"),
    (r"\bvisual c\+\+ 200[0-9]", None, "Runtime Visual C++ antigo", Severity.LOW,
     "runtime de época sem suporte; costuma vir de software velho instalado"),
)

# Software que é alvo frequente: peso na fila de correção.
# Cada padrão traz a própria fronteira de palavra, de propósito: sem o \b final,
# "redis" casa dentro de "Visual C++ Redistributable" e o runtime é classificado
# como banco de dados. Já "postgres\w*" precisa do sufixo livre para pegar
# "PostgreSQL" — é por isso que a fronteira não pode ser aplicada por igual a
# todos os padrões de fora.
ALVOS_FREQUENTES: tuple[tuple[str, int, str], ...] = (
    (r"\b(?:chrome|firefox|edge|opera|brave)\b", 30,
     "navegador: superfície de ataque diária"),
    (r"\b(?:acrobat|foxit|pdf\w*)\b", 25,
     "leitor de PDF: vetor clássico de documento malicioso"),
    (r"\b(?:java|jre|jdk|temurin|openjdk)\b", 25, "runtime Java: alvo histórico"),
    (r"\b(?:teamviewer|anydesk|vnc|radmin)\b", 30,
     "acesso remoto: dá o host inteiro se cair"),
    (r"\b(?:openvpn|wireguard|forticlient|cisco\s+\w*vpn)\b", 25,
     "VPN: fica na borda da rede"),
    (r"\b(?:python|node\.?js|ruby|perl)\b", 15, "runtime de script"),
    (r"\b(?:winrar|7-?zip|winzip)\b", 20,
     "compactador: processa arquivo de origem duvidosa"),
    (r"\b(?:vlc|media player|codec\w*)\b", 15,
     "player de mídia: processa arquivo não confiável"),
    (r"\b(?:docker|virtualbox|vmware|hyper-v)\b", 20,
     "virtualização: roda carga isolada e tem driver"),
    (r"\b(?:office|word|excel|outlook|thunderbird)\b", 25,
     "suíte de escritório/e-mail: porta de entrada de phishing"),
    (r"\b(?:mysql|postgres\w*|mariadb|mongodb|redis)\b", 20,
     "banco de dados: guarda o que interessa"),
    (r"\b(?:apache|nginx|tomcat|iis|xampp|wamp)\b", 25,
     "servidor web: feito para receber requisição de fora"),
    (r"\b(?:git|visual studio|vs ?code|jetbrains|intellij)\b", 10,
     "ferramenta de desenvolvimento"),
)

PUBLICADORES_SO = re.compile(r"microsoft|windows", re.IGNORECASE)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Palavra que, no nome do produto dentro do CPE, indica OUTRO produto: driver,
# biblioteca e pacote de distribuição têm numeração própria e CVE própria.
QUALIFICADORES = frozenset("""
jdbc odbc driver drivers connector connectors client clients library libraries
plugin plugins extension extensions module modules sdk cli agent exporter
operator proxy gateway bundle common tools toolkit wrapper binding bindings
adapter adapters dkms sidecar helm chart ansible puppet cookbook
""".split())


@dataclass(frozen=True)
class Item:
    severidade: Severity
    titulo: str
    descricao: str
    recomendacao: str
    recurso: str = ""
    referencia: str = "CIS Controls 7 (gestão contínua de vulnerabilidade)"
    evidencia: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Programa:
    nome: str
    versao: str = ""
    publicador: str = ""
    instalado_em: str = ""
    origem: str = ""


@dataclass(frozen=True)
class Escuta:
    porta: int
    endereco: str
    processo: str
    pid: int = 0

    @property
    def exposta(self) -> bool:
        """0.0.0.0 e :: aceitam conexão de fora; 127.0.0.1 e ::1 só do próprio host."""
        return not self.endereco.startswith(("127.", "::1", "169.254"))


# ---------------------------------------------------------------- versões
_SEPARADOR = re.compile(r"[.\-_+]")


def normalizar_versao(v: str) -> tuple[int, ...]:
    """Transforma '2.3.10-beta' em (2, 3, 10). Pedaço não numérico é ignorado."""
    if not v:
        return ()
    partes: list[int] = []
    for pedaco in _SEPARADOR.split(str(v).strip()):
        digitos = re.match(r"\d+", pedaco)
        if not digitos:
            break
        partes.append(int(digitos.group()))
    return tuple(partes)


def comparar_versoes(a: str, b: str) -> int:
    """-1 se a < b, 0 se iguais, 1 se a > b. Compara campo por campo."""
    va, vb = normalizar_versao(a), normalizar_versao(b)
    tamanho = max(len(va), len(vb))
    va += (0,) * (tamanho - len(va))
    vb += (0,) * (tamanho - len(vb))
    return (va > vb) - (va < vb)


def versao_na_faixa(versao: str, inicio_incl: str = "", inicio_excl: str = "",
                    fim_incl: str = "", fim_excl: str = "") -> bool:
    """A versão cai na faixa que o CPE do NVD descreve?

    Sem nenhum limite a faixa é aberta, e aí NÃO serve para priorizar nada:
    "todas as versões" costuma ser CPE mal preenchido. Quem chama decide.
    """
    if not normalizar_versao(versao):
        return False
    if inicio_incl and comparar_versoes(versao, inicio_incl) < 0:
        return False
    if inicio_excl and comparar_versoes(versao, inicio_excl) <= 0:
        return False
    if fim_incl and comparar_versoes(versao, fim_incl) > 0:
        return False
    if fim_excl and comparar_versoes(versao, fim_excl) >= 0:
        return False
    return True


# ---------------------------------------------------------------- SO e patch
def avaliar_suporte_so(build: int | None, hoje: date) -> list[Item]:
    if not build:
        return []
    info = BUILDS_WINDOWS.get(build)
    if info is None:
        return [Item(Severity.INFO, "Build do Windows não está na tabela de suporte",
                     f"O build {build} não consta na tabela de ciclo de vida "
                     f"(atualizada em {TABELA_ATUALIZADA}).",
                     "Confira o ciclo de vida desse build no site da Microsoft e "
                     "atualize a tabela BUILDS_WINDOWS.",
                     recurso=f"Windows build {build}",
                     evidencia={"build": build, "tabela_de": TABELA_ATUALIZADA})]

    nome, fim_iso = info
    fim = date.fromisoformat(fim_iso)
    dias = (fim - hoje).days
    base = {"build": build, "versao": nome, "fim_de_suporte": fim_iso,
            "dias_restantes": dias, "tabela_de": TABELA_ATUALIZADA}

    if dias < 0:
        return [Item(Severity.CRITICAL, f"{nome} fora de suporte",
                     f"O suporte terminou em {fim_iso}, há {-dias} dias. Falha nova "
                     "descoberta a partir dessa data não ganha correção nesta máquina.",
                     "Atualize para uma versão do Windows ainda em suporte.",
                     recurso=nome, evidencia=base)]
    if dias <= 90:
        return [Item(Severity.MEDIUM, f"{nome} perto do fim de suporte",
                     f"O suporte termina em {fim_iso}, em {dias} dias.",
                     "Planeje a atualização de versão antes dessa data.",
                     recurso=nome, evidencia=base)]
    return [Item(Severity.INFO, f"{nome} em suporte",
                 f"Suporte até {fim_iso} ({dias} dias). Tabela de {TABELA_ATUALIZADA}.",
                 "Nada a fazer agora.", recurso=nome, evidencia=base)]


def avaliar_patches(ultimo_patch: str, hoje: date, reinicio_pendente: bool,
                    atualizacao_ativa: bool | None, uptime_dias: int | None) -> list[Item]:
    """Estado do ciclo de correção. Datas em ISO; função pura."""
    itens: list[Item] = []

    if not ultimo_patch:
        itens.append(Item(Severity.INFO, "Não foi possível ver a data do último patch",
                          "Nem o histórico de atualização nem a lista de hotfix responderam.",
                          "Confira o histórico em Configurações → Windows Update."))
    else:
        dias = (hoje - date.fromisoformat(ultimo_patch[:10])).days
        ev = {"ultimo_patch": ultimo_patch[:10], "dias": dias}
        if dias > 90:
            itens.append(Item(Severity.HIGH, "Sistema sem patch há muito tempo",
                              f"O último patch entrou em {ultimo_patch[:10]}, há {dias} dias. "
                              "Ciclo de correção parado é a falha mais explorada que existe, "
                              "porque o atacante usa falha conhecida, não falha nova.",
                              "Rode o Windows Update e reinicie.",
                              recurso="Windows Update", evidencia=ev))
        elif dias > 45:
            itens.append(Item(Severity.MEDIUM, "Patch do sistema atrasado",
                              f"Último patch em {ultimo_patch[:10]}, há {dias} dias.",
                              "Rode o Windows Update.", recurso="Windows Update", evidencia=ev))
        elif dias > 35:
            itens.append(Item(Severity.LOW, "Patch do mês ainda não aplicado",
                              f"Último patch em {ultimo_patch[:10]}, há {dias} dias "
                              "(a Microsoft publica correção toda segunda terça-feira).",
                              "Rode o Windows Update.", recurso="Windows Update", evidencia=ev))

    if reinicio_pendente:
        itens.append(Item(Severity.MEDIUM, "Reinício pendente: patch aplicado mas não efetivado",
                          "Há atualização instalada esperando reinício. Até reiniciar, o "
                          "código antigo é o que está rodando — na prática, o patch não existe.",
                          "Reinicie a máquina.", recurso="Reinício pendente"))

    if atualizacao_ativa is False:
        itens.append(Item(Severity.HIGH, "Serviço de atualização do Windows desativado",
                          "O wuauserv está desativado, então a máquina não recebe correção "
                          "nenhuma — nem as críticas.",
                          "Reative o serviço Windows Update (início Manual ou Automático).",
                          recurso="Serviço wuauserv"))

    if uptime_dias is not None and uptime_dias > 30:
        itens.append(Item(Severity.LOW, "Máquina ligada sem reiniciar há muito tempo",
                          f"{uptime_dias} dias sem reiniciar; patch que exige reinício fica "
                          "na fila esse tempo todo.",
                          "Reinicie periodicamente, de preferência depois de cada patch.",
                          recurso="Tempo ligado", evidencia={"dias": uptime_dias}))
    return itens


# ---------------------------------------------------------------- software
def avaliar_abandonado(inventario: Iterable[Programa]) -> list[Item]:
    """Software sem suporte do fabricante. Fato histórico, não precisa de rede."""
    itens: list[Item] = []
    for prog in inventario:
        alvo = f"{prog.nome} {prog.versao}".lower()
        for padrao, versao_max, rotulo, sev, motivo in ABANDONADOS:
            if not re.search(padrao, alvo, re.IGNORECASE):
                continue
            if versao_max and prog.versao and comparar_versoes(prog.versao, versao_max) > 0:
                continue                       # versão nova o bastante: tudo bem
            itens.append(Item(sev, f"Software sem suporte: {rotulo}",
                              f"{prog.nome} {prog.versao} — {motivo}.",
                              "Atualize para uma versão com suporte, ou desinstale se não usa.",
                              recurso=prog.nome,
                              evidencia={"versao": prog.versao, "publicador": prog.publicador,
                                         "tabela_de": TABELA_ATUALIZADA}))
            break
    return itens


@dataclass(frozen=True)
class Prioridade:
    programa: Programa
    escore: int
    motivos: list[str]
    portas: list[int] = field(default_factory=list)
    exposto: bool = False


def pontuar_prioridade(prog: Programa, escutas: Iterable[Escuta]) -> Prioridade:
    """Quanto esse software merece ser corrigido antes dos outros.

    Dois eixos, os dois verificáveis aqui: o que o software É (alvo frequente) e
    o quanto ele está ALCANÇÁVEL (escuta em porta, e de onde).
    """
    escore = 0
    motivos: list[str] = []
    alvo = prog.nome.lower()

    for padrao, peso, rotulo in ALVOS_FREQUENTES:
        if re.search(padrao, alvo, re.IGNORECASE):
            escore += peso
            motivos.append(rotulo)
            break

    minhas = [e for e in escutas if forca_do_casamento(prog.nome, e.processo)]
    portas = sorted({e.porta for e in minhas})
    exposto = any(e.exposta for e in minhas)
    if exposto:
        escore += 40
        motivos.append(f"escuta para fora nas portas {portas}: alcançável pela rede")
    elif portas:
        escore += 10
        motivos.append(f"escuta só local nas portas {portas}")

    return Prioridade(prog, escore, motivos, portas, exposto)


# Palavra que aparece em metade dos nomes de software não identifica nada. Sem
# esta lista, o services.exe (gerenciador de serviços do Windows) casa com todo
# programa que tenha "Service" no nome — foi o que aconteceu em teste de campo:
# uma porta do services.exe foi atribuída a cinco programas de uma vez.
GENERICAS = frozenset("""
service services agent agents update updater upgrade support center centre client
host system systems windows microsoft application applications manager helper
tool tools software driver drivers stable online smart search console server
servers desktop launcher runtime framework edition setup install installer
package assistant experience settings store security display audio video network
mobile device control panel suite studio connect component common core data
engine group media plus plugin pack platform process program project redistributable
service_pack shared version visual
""".split())


def condensar(nome: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", re.sub(r"\.exe$", "", nome.lower()))


def _prefixo_comum(a: str, b: str) -> int:
    n = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        n += 1
    return n


def forca_do_casamento(nome_programa: str, nome_processo: str) -> int:
    """Quão específico é o casamento entre o nome do programa e o do processo.

    0 = não casa. Número maior = casamento mais específico, e é isso que permite
    dar a porta ao programa certo quando vários disputam: 'Samsung Analytics
    Service' ganha de 'Samsung Update Service' para o processo
    SamsungAnalyticsService, porque o prefixo em comum é muito mais longo.
    """
    processo = condensar(nome_processo)
    if len(processo) < 4:
        return 0

    prefixo = _prefixo_comum(condensar(nome_programa), processo)
    forca = prefixo if prefixo >= 5 else 0

    for palavra in re.split(r"[^a-z0-9]+", nome_programa.lower()):
        if len(palavra) < 4 or palavra in GENERICAS:
            continue
        if palavra == processo or processo.startswith(palavra) or palavra.startswith(processo):
            forca = max(forca, len(palavra))
    return forca


def _mesmo_software(nome_programa: str, nome_processo: str) -> bool:
    return forca_do_casamento(nome_programa, nome_processo) > 0


def atribuir_escutas(inventario: Iterable[Programa],
                     escutas: Iterable[Escuta]) -> dict[str, list[Escuta]]:
    """Dá cada porta em escuta a UM programa: o de casamento mais específico.

    Antes cada programa procurava as portas que pareciam suas, e uma porta
    acabava contada para vários. Aqui a porta é que escolhe o dono.
    """
    inventario = list(inventario)
    mapa: dict[str, list[Escuta]] = {}
    for escuta in escutas:
        melhor: Programa | None = None
        melhor_forca = 0
        for prog in inventario:
            forca = forca_do_casamento(prog.nome, escuta.processo)
            if forca > melhor_forca:
                melhor, melhor_forca = prog, forca
        if melhor is not None:
            mapa.setdefault(melhor.nome, []).append(escuta)
    return mapa


def priorizar(inventario: Iterable[Programa], escutas: Iterable[Escuta],
              minimo: int = 20) -> list[Prioridade]:
    inventario = list(inventario)
    mapa = atribuir_escutas(inventario, escutas)
    fila = [pontuar_prioridade(p, mapa.get(p.nome, [])) for p in inventario]
    fila = [p for p in fila if p.escore >= minimo]
    fila.sort(key=lambda p: (-p.escore, p.programa.nome.lower()))
    return fila


# ---------------------------------------------------------------- NVD (opcional)
@dataclass(frozen=True)
class CveCasado:
    id: str
    cvss: float
    gravidade: str
    resumo: str
    faixa: str


def cves_que_casam(resposta: dict, versao: str, produto: str) -> list[CveCasado]:
    """Filtra a resposta do NVD pelas CVEs cuja FAIXA DE VERSÃO inclui a nossa.

    Função pura: recebe o JSON já baixado. É aqui que o módulo deixa de ser
    busca por palavra-chave e passa a comparar versão de verdade. CVE sem faixa
    declarada é descartada — "todas as versões" não prioriza nada.
    """
    casados: list[CveCasado] = []
    produto_norm = produto.lower()
    for vulnerabilidade in resposta.get("vulnerabilities") or []:
        cve = vulnerabilidade.get("cve") or {}
        identificador = cve.get("id") or "?"
        faixa_usada = ""
        casou = False

        for config in cve.get("configurations") or []:
            for no in config.get("nodes") or []:
                for cpe in no.get("cpeMatch") or []:
                    if not cpe.get("vulnerable"):
                        continue
                    criterio = str(cpe.get("criteria") or "").lower()
                    if not _produto_no_cpe(produto_norm, criterio):
                        continue
                    limites = {
                        "inicio_incl": cpe.get("versionStartIncluding") or "",
                        "inicio_excl": cpe.get("versionStartExcluding") or "",
                        "fim_incl": cpe.get("versionEndIncluding") or "",
                        "fim_excl": cpe.get("versionEndExcluding") or "",
                    }
                    if not any(limites.values()):
                        continue
                    if versao_na_faixa(versao, **limites):
                        casou = True
                        faixa_usada = ", ".join(f"{k}={v}" for k, v in limites.items() if v)
                        break
                if casou:
                    break
            if casou:
                break

        if not casou:
            continue
        cvss, gravidade = _cvss_de(cve)
        casados.append(CveCasado(identificador, cvss, gravidade,
                                 _descricao_de(cve)[:300], faixa_usada))
    casados.sort(key=lambda c: -c.cvss)
    return casados


def _produto_no_cpe(produto: str, criterio: str) -> bool:
    """'google chrome' casa com 'cpe:2.3:a:google:chrome:*:*:*...'.

    O CPE não é texto livre: ele tem campos, e o 4º e o 5º são fabricante e
    produto. Ler os campos certos é bem melhor que procurar palavra no meio da
    string inteira — que foi a primeira tentativa e não casava nada.

    O nome do produto é o que identifica; o fabricante sozinho só vale quando é
    tudo que temos, senão 'microsoft edge' casaria com qualquer CPE da
    Microsoft, Office incluído.
    """
    partes = criterio.split(":")
    if len(partes) < 5:
        return False
    tokens_fabricante = set(re.split(r"[^a-z0-9]+", partes[3]))
    tokens_produto = set(re.split(r"[^a-z0-9]+", partes[4]))
    palavras = [p for p in re.split(r"[^a-z0-9]+", produto) if len(p) >= 4]
    if not palavras:
        return False

    # Um qualificador no nome do produto muda o produto. 'postgresql' e
    # 'postgresql_jdbc_driver' são coisas diferentes, com numeração diferente:
    # em teste de campo o PostgreSQL 17.11 casou com CVE do driver JDBC 42.x
    # e com o pacote Debian postgresql-common 210. Nome parecido, produto outro.
    if any(t in QUALIFICADORES and t not in palavras for t in tokens_produto):
        return False

    if any(p in tokens_produto for p in palavras):
        return True
    return len(palavras) == 1 and palavras[0] in tokens_fabricante


def _cvss_de(cve: dict) -> tuple[float, str]:
    metricas = cve.get("metrics") or {}
    for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metricas.get(chave) or []:
            dados = m.get("cvssData") or {}
            nota = dados.get("baseScore")
            if isinstance(nota, (int, float)):
                return float(nota), str(dados.get("baseSeverity")
                                        or m.get("baseSeverity") or "")
    return 0.0, ""


def _descricao_de(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return str(d.get("value") or "")
    return ""


def severidade_de_cvss(nota: float) -> Severity:
    if nota >= 9.0:
        return Severity.CRITICAL
    if nota >= 7.0:
        return Severity.HIGH
    if nota >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def consultar_nvd(produto: str, chave_api: str = "", timeout: int = 25) -> dict | None:
    """Uma consulta de leitura ao NVD. Devolve None se não der para falar."""
    url = f"{NVD_URL}?{urllib.parse.urlencode({'keywordSearch': produto, 'resultsPerPage': 200})}"
    pedido = urllib.request.Request(url, headers={"User-Agent": "cidadela-blueteam/1.0"})
    if chave_api:
        pedido.add_header("apiKey", chave_api)
    try:
        with urllib.request.urlopen(pedido, timeout=timeout) as resposta:
            return json.loads(resposta.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


class PatchPriority(Plugin):
    nome = "patch-priority"
    descricao = "Monta a fila de correção: patch do SO, suporte, software abandonado e exposição de rede."
    sistemas = ("Windows",)

    def run(self, ctx: Contexto) -> list[Finding]:
        hoje = datetime.now(timezone.utc).date()
        estado = self._coletar_estado()
        inventario = self._inventario()
        escutas = self._escutas()

        itens: list[Item] = []
        itens += avaliar_suporte_so(estado.get("build"), hoje)
        itens += avaliar_patches(estado.get("ultimo_patch") or "", hoje,
                                 bool(estado.get("reinicio_pendente")),
                                 estado.get("atualizacao_ativa"),
                                 estado.get("uptime_dias"))
        itens += avaliar_abandonado(inventario)

        fila = priorizar(inventario, escutas)
        itens += self._item_da_fila(fila, inventario, escutas)
        if ctx.opcoes.get("online"):
            itens += self._enriquecer_com_nvd(fila, ctx)

        return [self.finding(titulo=i.titulo, severidade=i.severidade, descricao=i.descricao,
                             recomendacao=i.recomendacao, recurso=i.recurso,
                             referencia=i.referencia, evidencia=i.evidencia) for i in itens]

    # ---- fila ----
    @staticmethod
    def _item_da_fila(fila: list[Prioridade], inventario: list[Programa],
                      escutas: list[Escuta]) -> list[Item]:
        if not inventario:
            return [Item(Severity.INFO, "Não foi possível ler o software instalado",
                         "As chaves de desinstalação do registro não responderam.",
                         "Verifique a permissão de leitura do registro.")]
        if not fila:
            return [Item(Severity.INFO, "Nenhum software de alta prioridade de correção",
                         f"{len(inventario)} programas inventariados; nenhum é alvo frequente "
                         "nem escuta em porta de rede.",
                         "Mantenha o Windows Update em dia.")]

        expostos = [p for p in fila if p.exposto]
        linhas = [f"{i + 1}. {p.programa.nome} {p.programa.versao} "
                  f"(escore {p.escore}) — {'; '.join(p.motivos)}"
                  for i, p in enumerate(fila[:15])]
        sev = Severity.MEDIUM if expostos else Severity.LOW
        return [Item(sev, f"Fila de correção: {len(fila)} programas priorizados",
                     "Ordem sugerida para aplicar atualização, por tipo de software e por "
                     "alcance pela rede:\n    " + "\n    ".join(linhas),
                     "Atualize de cima para baixo. O que escuta para fora vem primeiro: "
                     "é o que um atacante alcança sem precisar de você.",
                     recurso="Software instalado",
                     evidencia={"total_inventariado": len(inventario),
                                "priorizados": len(fila),
                                "expostos_na_rede": [p.programa.nome for p in expostos],
                                "portas_em_escuta": sorted({e.porta for e in escutas}),
                                "fila": [{"nome": p.programa.nome, "versao": p.programa.versao,
                                          "escore": p.escore, "portas": p.portas,
                                          "exposto": p.exposto} for p in fila[:30]]})]

    # ---- NVD ----
    def _enriquecer_com_nvd(self, fila: list[Prioridade], ctx: Contexto) -> list[Item]:
        quantos = _inteiro(ctx.opcoes.get("max_consultas"), 5)
        chave = str(ctx.opcoes.get("nvd_api_key") or "")
        espera = 1 if chave else 7     # sem chave de API o NVD limita a 5 por 30s
        itens: list[Item] = []
        consultados: list[str] = []
        sem_resposta: list[str] = []

        candidatos = [p for p in fila if p.programa.versao][:quantos]
        for i, prio in enumerate(candidatos):
            produto = _termo_de_busca(prio.programa.nome)
            if i:
                time.sleep(espera)
            resposta = consultar_nvd(produto, chave)
            if resposta is None:
                sem_resposta.append(produto)
                continue
            consultados.append(produto)
            casados = cves_que_casam(resposta, prio.programa.versao, produto)
            if not casados:
                continue
            pior = casados[0]
            itens.append(Item(
                severidade_de_cvss(pior.cvss),
                f"Indício de CVE em {prio.programa.nome} {prio.programa.versao}",
                f"{len(casados)} CVE(s) do NVD têm faixa de versão que inclui a instalada. "
                f"A mais grave é {pior.id} (CVSS {pior.cvss}): {pior.resumo}",
                "CONFIRME antes de agir: nome de produto no CPE e nome no registro divergem, "
                "e faixa de versão no NVD vem com erro. Confira a CVE e, se procede, "
                "atualize o software.",
                recurso=f"{prio.programa.nome} {prio.programa.versao}",
                referencia=f"NVD {pior.id}",
                evidencia={"indicio_a_confirmar": True,
                           "termo_de_busca": produto,
                           "versao_instalada": prio.programa.versao,
                           "faixa_que_casou": pior.faixa,
                           "cves": [{"id": c.id, "cvss": c.cvss, "gravidade": c.gravidade,
                                     "faixa": c.faixa} for c in casados[:10]]}))

        if sem_resposta:
            itens.append(Item(Severity.INFO, "Consulta ao NVD falhou em parte",
                              f"Sem resposta para: {', '.join(sem_resposta)}. Pode ser rede, "
                              "limite de requisição (5 por 30s sem chave de API) ou o serviço fora.",
                              "Tente de novo mais tarde, ou use --opcao nvd_api_key=<sua chave>.",
                              evidencia={"consultados": consultados, "sem_resposta": sem_resposta}))
        elif not itens:
            itens.append(Item(Severity.INFO, "NVD consultado, nenhuma faixa de versão casou",
                              f"Consultados {len(consultados)} produtos: {', '.join(consultados)}. "
                              "Nenhuma CVE com faixa declarada inclui a versão instalada. "
                              "Isso não é atestado de saúde: CPE incompleto é comum.",
                              "Nada a fazer com base nisso.",
                              evidencia={"consultados": consultados}))
        return itens

    # ---- coletores (só leitura) ----
    @staticmethod
    def _inventario() -> list[Programa]:
        if winreg is None:
            return []
        achados: dict[tuple[str, str], Programa] = {}
        raizes = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        for caminho, raiz_nome in CHAVES_UNINSTALL:
            try:
                raiz = winreg.OpenKey(raizes[raiz_nome], caminho, 0,
                                      winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            except OSError:
                continue
            with raiz:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(raiz, i)
                    except OSError:
                        break
                    i += 1
                    prog = _ler_programa(raiz, sub, f"{raiz_nome}\\{caminho}")
                    if prog:
                        achados.setdefault((prog.nome.lower(), prog.versao), prog)
        return sorted(achados.values(), key=lambda p: p.nome.lower())

    @staticmethod
    def _escutas() -> list[Escuta]:
        dados = _powershell_json(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json -Compress")
        if dados is None:
            return []
        lista = dados if isinstance(dados, list) else [dados]
        processos = _powershell_json(
            "Get-Process | Select-Object Id, ProcessName | ConvertTo-Json -Compress") or []
        if isinstance(processos, dict):
            processos = [processos]
        por_pid = {p.get("Id"): p.get("ProcessName") or "" for p in processos
                   if isinstance(p, dict)}

        escutas: list[Escuta] = []
        for c in lista:
            if not isinstance(c, dict):
                continue
            pid = c.get("OwningProcess") or 0
            escutas.append(Escuta(porta=int(c.get("LocalPort") or 0),
                                  endereco=str(c.get("LocalAddress") or ""),
                                  processo=str(por_pid.get(pid, "")), pid=int(pid)))
        return escutas

    @staticmethod
    def _coletar_estado() -> dict[str, Any]:
        dados = _powershell_json(_PS_ESTADO)
        return dados if isinstance(dados, dict) else {}


_PS_ESTADO = r"""
$ErrorActionPreference = 'Stop'
$r = @{}
try {
  $so = Get-CimInstance Win32_OperatingSystem
  $r.build = [int]$so.BuildNumber
  $r.nome_so = [string]$so.Caption
  $r.uptime_dias = [int]((Get-Date) - $so.LastBootUpTime).TotalDays
} catch { }
# histórico do Windows Update é mais fiel que a lista de hotfix, que só mostra parte
try {
  $sessao = New-Object -ComObject Microsoft.Update.Session
  $total = $sessao.CreateUpdateSearcher().GetTotalHistoryCount()
  if ($total -gt 0) {
    $ultimo = $sessao.CreateUpdateSearcher().QueryHistory(0, [Math]::Min(50, $total)) |
      Where-Object { $_.ResultCode -eq 2 } | Sort-Object Date -Descending | Select-Object -First 1
    if ($ultimo) { $r.ultimo_patch = $ultimo.Date.ToString('s') }
  }
} catch { }
if (-not $r.ultimo_patch) {
  try {
    $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending |
      Select-Object -First 1
    if ($hf) { $r.ultimo_patch = $hf.InstalledOn.ToString('s') }
  } catch { }
}
try { $r.atualizacao_ativa = ((Get-Service wuauserv).StartType -ne 'Disabled') } catch { }
$pendente = $false
foreach ($c in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress')) {
  if (Test-Path $c) { $pendente = $true }
}
try {
  $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name PendingFileRenameOperations).PendingFileRenameOperations
  if ($pfro) { $pendente = $true }
} catch { }
$r.reinicio_pendente = $pendente
$r | ConvertTo-Json -Depth 3 -Compress
"""


def _ler_programa(raiz: Any, sub: str, origem: str) -> Programa | None:
    try:
        with winreg.OpenKey(raiz, sub) as chave:
            def ler(nome: str) -> str:
                try:
                    valor, _ = winreg.QueryValueEx(chave, nome)
                except OSError:
                    return ""
                return str(valor).strip()

            nome = ler("DisplayName")
            if not nome:
                return None
            # atualização do próprio Windows polui o inventário e não é software
            if ler("SystemComponent") == "1" or ler("ParentKeyName"):
                return None
            return Programa(nome=nome, versao=ler("DisplayVersion"),
                            publicador=ler("Publisher"),
                            instalado_em=ler("InstallDate"), origem=origem)
    except OSError:
        return None


# Palavra de embalagem: diz como o software foi empacotado, não qual software é.
# "Redis on Windows" tem que virar "redis", senão a busca leva 'on' e 'windows'
# atrás de um CPE que nunca vai ter essas palavras.
PALAVRAS_VAZIAS = frozenset("""
on for the and of de do da com em plus stable beta alpha rc edition bit win
windows win32 win64 setup installer install portable free community pro premium
""".split())


def _termo_de_busca(nome: str) -> str:
    """Reduz 'Redis on Windows 3.0.504' a 'redis' para a busca do NVD."""
    # número só é versão se tiver ponto, ou se vier solto depois de um espaço.
    # Tirar dígito de qualquer jeito transformava "7-Zip" em "zip".
    limpo = re.sub(r"\(.*?\)|\b\d+(?:\.\d+)+\b|(?<=\s)\d+\b|\bversion\b|\bversão\b|"
                   r"\bx64\b|\bx86\b|\b64-bit\b|\b32-bit\b", " ", nome, flags=re.IGNORECASE)
    # o hífen fica dentro do token: "7-zip" é um nome, não dois pedaços
    brutas = (p.strip("-.") for p in re.split(r"[^\w+#.-]+", limpo.lower()))
    palavras = [p for p in brutas if len(p) > 1 and p not in PALAVRAS_VAZIAS]
    return " ".join(palavras[:3]).strip()


def _inteiro(valor: Any, padrao: int) -> int:
    try:
        n = int(valor)
    except (TypeError, ValueError):
        return padrao
    return n if n > 0 else padrao


def _powershell_json(script: str) -> Any:
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, errors="replace",
                           timeout=180, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    saida = (r.stdout or "").strip()
    if not saida:
        return None
    try:
        return json.loads(saida)
    except json.JSONDecodeError:
        return None
