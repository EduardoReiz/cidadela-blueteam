"""Detector de ofuscação em comandos e scripts — espelho DEFENSIVO da ofuscação.

Ofuscar é esconder a intenção do comando sem mudar o que ele faz. O lado
defensivo não precisa desofuscar tudo: precisa perceber que *houve* esforço de
esconder, porque comando legítimo não se disfarça.

Como funciona: um motor de regras no espírito do YARA, só que em regex puro e
com as regras como DADO (a tupla `REGRAS`), para estender sem mexer no código.
Cada regra tem peso; a soma vira escore e o escore vira severidade.

Dois cuidados que seguram o falso positivo, que é o veneno deste tipo de módulo:

1. **Sinal forte x sinal fraco.** Heurística numérica (comprimento, entropia,
   sopa de símbolos, caixa misturada) é FRACA e só pontua se alguma regra forte
   também apontar. Linha de comando de Chrome, Electron e Java é longa e cheia
   de símbolo por natureza — sem essa trava, o módulo gritaria com o navegador.
2. **Base64 que decodifica para texto UTF-16LE é sinal forte; base64 solto é
   fraco.** UTF-16LE é a assinatura do `-EncodedCommand` do PowerShell e quase
   não acontece por acidente; já blob base64 em linha de comando é comum em
   software legítimo.

Quando um blob decodifica, o conteúdo é PONTUADO DE NOVO (recursivamente, até
2 níveis). Payload escondido que, aberto, também parece malicioso é o caso mais
próximo de certeza que este módulo consegue.

Fontes de telemetria (todas só leitura):
  - processos em execução (`Win32_Process`) — funciona sem configurar nada
  - log `Microsoft-Windows-PowerShell/Operational` evento 4104 (script block)
  - log `Security` evento 4688 (criação de processo com linha de comando)
  - arquivo avulso, via `--opcao arquivo=<caminho>`

Os dois logs dependem de auditoria ligada no host (é o que o `hardening-audit`
cobra). Quando a telemetria não existe, o módulo DIZ que está cego em vez de
devolver "nada encontrado" — detecção calada é pior que detecção ausente.

Nada aqui executa, desofusca para rodar ou grava arquivo: só lê, decodifica em
memória e relata.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..plugin import Contexto, Finding, Plugin, Severity

T1027 = "MITRE T1027"              # Obfuscated Files or Information
T1059 = "MITRE T1059.001"          # Command and Scripting Interpreter: PowerShell
T1218 = "MITRE T1218"              # System Binary Proxy Execution (LOLBin)
T1562 = "MITRE T1562.001"          # Impair Defenses

# limiares de escore -> severidade
LIMIARES: tuple[tuple[int, Severity], ...] = (
    (60, Severity.CRITICAL),
    (40, Severity.HIGH),
    (25, Severity.MEDIUM),
    (15, Severity.LOW),
)

MAX_PROFUNDIDADE = 2        # até onde reavaliar payload decodificado
MIN_BLOB_BASE64 = 40        # abaixo disso não vale tentar decodificar
MAX_TEXTO_EVIDENCIA = 1500  # corte do comando guardado na evidência


@dataclass(frozen=True)
class Regra:
    nome: str
    padrao: str
    peso: int
    descricao: str
    forte: bool = True
    referencia: str = T1027

    def compilar(self) -> re.Pattern[str]:
        return re.compile(self.padrao, re.IGNORECASE)


REGRAS: tuple[Regra, ...] = (
    # --- execução escondida / codificada ---
    Regra("comando-codificado", r"-e(nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}", 40,
          "PowerShell recebendo comando codificado em base64 (-EncodedCommand)",
          referencia=T1059),
    Regra("decodificar-base64", r"FromBase64String|::FromBase64", 25,
          "decodificação de base64 dentro do próprio comando"),
    Regra("invoke-expression", r"Invoke-Expression|\biex\b|\|\s*iex", 25,
          "execução de string montada em tempo real (IEX)", referencia=T1059),
    Regra("download-e-executa", r"DownloadString|DownloadFile|Net\.WebClient|"
          r"Invoke-WebRequest|iwr\s|curl\s+http", 25,
          "baixa conteúdo da rede para executar na hora", referencia=T1059),
    # Contexto, não ofuscação: instalador legítimo também roda escondido e
    # ignora política. Entram como FRACO para somar ao lado de um sinal de
    # verdade, sem nunca virar achado por conta própria.
    Regra("janela-escondida", r"-w(indowstyle)?\s+h(id|idden)?\b", 15,
          "pede para rodar sem janela visível", forte=False),
    Regra("politica-ignorada", r"-ex(ecutionpolicy)?\s+(bypass|unrestricted)|-ep\s+bypass", 15,
          "ignora a política de execução de script", forte=False),
    Regra("sem-perfil", r"-nop(rofile)?\b", 5,
          "roda sem carregar perfil", forte=False),
    # --- montagem de string para escapar de assinatura ---
    Regra("crase-no-identificador", r"[A-Za-z]`[A-Za-z]", 25,
          "crase quebrando o nome do comando (I`E`X) para furar assinatura"),
    Regra("acento-circunflexo-cmd", r"[A-Za-z]\^[A-Za-z]", 25,
          "^ quebrando o nome do comando no cmd.exe"),
    Regra("char-aritmetico", r"\[char\]\s*[\d\(\$]", 20,
          "texto montado a partir de códigos de caractere"),
    Regra("operador-formato", r"\{\d\}.{0,80}-f\s*['\"(]", 20,
          "string remontada pelo operador de formato -f"),
    Regra("juntar-pedacos", r"-join\s*[\(\$'\"]", 15,
          "string remontada por -join"),
    Regra("texto-invertido", r"\[array\]::reverse|ToCharArray\(\)", 20,
          "texto invertido para esconder a palavra original"),
    Regra("substring-de-variavel", r"%[A-Za-z_]+:~\s*-?\d+|\$env:[A-Za-z]+\[\d", 35,
          "comando montado com fatias de variável de ambiente (%COMSPEC:~4,1%)"),
    # --- carga em memória ---
    Regra("carregar-assembly", r"Reflection\.Assembly|\[Reflection\]|Assembly\]::Load", 25,
          "carrega código .NET direto na memória, sem passar por arquivo"),
    Regra("fluxo-comprimido", r"MemoryStream|DeflateStream|GzipStream", 15,
          "payload comprimido descompactado em memória"),
    Regra("adicionar-tipo", r"Add-Type\s+.{0,40}(TypeDefinition|MemberDefinition)", 20,
          "compila código em tempo de execução"),
    Regra("api-de-injecao", r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|"
          r"GetDelegateForFunctionPointer", 45,
          "chama API usada para injetar código em outro processo",
          referencia="MITRE T1055"),
    # --- desligar defesa ---
    Regra("burlar-amsi", r"amsiInitFailed|AmsiScanBuffer|AmsiUtils", 50,
          "mexe no AMSI — tentativa de cegar a varredura de script",
          referencia=T1562),
    Regra("desligar-defender", r"Set-MpPreference\s+.{0,60}Disable|"
          r"Add-MpPreference\s+-ExclusionPath", 35,
          "desliga proteção ou cria exclusão no Defender", referencia=T1562),
    Regra("apagar-historico", r"Clear-EventLog|wevtutil\s+cl\b|Remove-Item\s+.{0,40}ConsoleHost_history", 35,
          "apaga log ou histórico de comando", referencia="MITRE T1070"),
    # --- binário do sistema servindo de proxy (LOLBin) ---
    Regra("lolbin-script-inline", r"mshta\s+(javascript|vbscript):|rundll32\s+javascript:|"
          r"regsvr32\s+.{0,20}/i:http", 40,
          "binário do Windows executando script embutido na linha de comando",
          referencia=T1218),
    Regra("certutil-decodifica", r"certutil(\.exe)?\s+.{0,40}(-decode|-urlcache|-f\s+-split)", 30,
          "certutil usado para baixar ou decodificar payload", referencia=T1218),
    Regra("bitsadmin-transfere", r"bitsadmin\s+.{0,30}/transfer", 20,
          "bitsadmin baixando arquivo", referencia=T1218),
    # --- sinais fracos: só contam se algo forte apontar ---
    Regra("base64-longo", r"[A-Za-z0-9+/]{100,}={0,2}", 20,
          "bloco base64 longo embutido", forte=False),
    Regra("muita-chamada-encadeada", r"(\)\s*\.\s*\w+\s*\(){3,}", 10,
          "cadeia longa de chamadas encadeadas", forte=False),
)

_COMPILADAS: tuple[tuple[Regra, re.Pattern[str]], ...] = tuple(
    (r, r.compilar()) for r in REGRAS)

_BLOCO_BASE64 = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_BLOB_BASE64)
_PALAVRA = re.compile(r"[A-Za-z]{4,}")


@dataclass(frozen=True)
class Sinal:
    regra: str
    peso: int
    descricao: str
    ocorrencias: int = 1
    amostra: str = ""
    forte: bool = True


@dataclass
class Avaliacao:
    escore: int = 0
    sinais: list[Sinal] = field(default_factory=list)
    decodificado: str | None = None
    fortes: int = 0

    @property
    def severidade(self) -> Severity | None:
        for minimo, sev in LIMIARES:
            if self.escore >= minimo:
                return sev
        return None

    def resumo(self) -> str:
        return "; ".join(s.descricao for s in self.sinais)


def entropia(s: str) -> float:
    """Entropia de Shannon (bits por caractere)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def proporcao_simbolos(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for ch in s if not ch.isalnum() and not ch.isspace()) / len(s)


def caixa_misturada(s: str) -> float:
    """Fração de palavras com maiúscula no meio sem ser CamelCase decente.

    `dOwNlOaDsTrInG` é ofuscação; `DownloadString` e `IEX` não são.
    """
    palavras = _PALAVRA.findall(s)
    if not palavras:
        return 0.0
    baguncadas = 0
    for p in palavras:
        miolo = p[1:]
        if not any(c.isupper() for c in miolo) or not any(c.islower() for c in miolo):
            continue                                  # tudo igual: Camel ou SIGLA
        trocas = sum(1 for a, b in zip(miolo, miolo[1:]) if a.isupper() != b.isupper())
        if trocas >= max(2, len(miolo) // 3):
            baguncadas += 1
    return baguncadas / len(palavras)


def decodificar_base64(texto: str) -> str | None:
    """Tenta abrir o maior blob base64 do texto. Decodifica, nunca executa.

    Aceita só o que sai com CARA DE COMANDO: texto legível, quase todo ASCII,
    em UTF-16LE (o formato do `-EncodedCommand`) ou UTF-8. A exigência de ASCII
    não é purismo — sem ela, qualquer blob base64 de software legítimo abre como
    ideograma aleatório, passa no teste de "imprimível" e vira achado inventado.
    Payload binário também é descartado: quem cuida de binário é outra análise.
    """
    blocos = sorted(_BLOCO_BASE64.findall(texto), key=len, reverse=True)
    for bloco in blocos[:3]:
        recorte = bloco[:len(bloco) - (len(bloco) % 4)]
        if len(recorte) < MIN_BLOB_BASE64:
            continue
        try:
            cru = base64.b64decode(recorte, validate=True)
        except (binascii.Error, ValueError):
            continue
        for codec in ("utf-16-le", "utf-8"):
            try:
                aberto = cru.decode(codec)
            except UnicodeDecodeError:
                continue
            if parece_comando(aberto):
                return aberto
    return None


def parece_comando(texto: str) -> bool:
    """O texto decodificado tem cara de comando/script, e não de lixo?"""
    if not texto or not texto.strip():
        return False
    legiveis = sum(1 for ch in texto if ch.isprintable() or ch in "\r\n\t")
    if legiveis / len(texto) < 0.9:
        return False
    ascii_puro = sum(1 for ch in texto if ord(ch) < 128)
    if ascii_puro / len(texto) < 0.9:
        return False
    return sum(1 for ch in texto if ch.isascii() and ch.isalpha()) >= 3


def pontuar(texto: str, profundidade: int = 0) -> Avaliacao:
    """Pontua o esforço de ofuscação de um texto. Função pura/testável."""
    av = Avaliacao()
    if not texto or not texto.strip():
        return av

    for regra, padrao in _COMPILADAS:
        achados = padrao.findall(texto)
        if not achados:
            continue
        primeiro = achados[0]
        if isinstance(primeiro, tuple):
            primeiro = next((p for p in primeiro if p), "")
        av.sinais.append(Sinal(regra.nome, regra.peso, regra.descricao,
                               ocorrencias=len(achados), amostra=str(primeiro)[:80],
                               forte=regra.forte))

    # payload que abre e, aberto, continua suspeito: o sinal mais forte que existe
    aberto = decodificar_base64(texto)
    if aberto and profundidade < MAX_PROFUNDIDADE:
        av.decodificado = aberto[:MAX_TEXTO_EVIDENCIA]
        av.sinais.append(Sinal("payload-decodificavel", 35,
                               "o bloco base64 abre como texto de comando — "
                               "ou seja, é comando escondido, não dado"))
        interno = pontuar(aberto, profundidade + 1)
        if interno.escore >= 25:
            av.sinais.append(Sinal("payload-tambem-suspeito", 30,
                                   f"o conteúdo escondido também pontua alto ({interno.escore}): "
                                   + interno.resumo()[:160]))

    # heurísticas numéricas entram como sinal fraco
    if len(texto) > 600:
        av.sinais.append(Sinal("comando-muito-longo", 10,
                               f"linha de comando com {len(texto)} caracteres",
                               forte=False))
    # 5.2 bits/char é terreno de payload codificado; texto de comando comum vive
    # na faixa de 4,2 a 4,8, e em texto curto a medida não diz nada
    if len(texto) >= 100 and entropia(texto) > 5.2:
        av.sinais.append(Sinal("alta-aleatoriedade", 15,
                               f"alta aleatoriedade no texto ({entropia(texto):.1f} bits/char)",
                               forte=False))
    if proporcao_simbolos(texto) > 0.30:
        av.sinais.append(Sinal("sopa-de-simbolos", 10,
                               f"{proporcao_simbolos(texto):.0%} do texto é símbolo",
                               forte=False))
    if caixa_misturada(texto) > 0.25:
        av.sinais.append(Sinal("caixa-misturada", 15,
                               "maiúsculas e minúsculas trocadas no meio das palavras",
                               forte=False))

    av.fortes = sum(1 for s in av.sinais if s.forte)
    if not av.fortes:
        # primeira trava: sem nenhum sinal forte, o fraco não pontua
        av.escore = 0
        av.sinais = []
        return av

    # segunda trava: o fraco acrescenta no máximo metade do que o forte já
    # somou. Em teste de campo um lançador legítimo (política ignorada, sem
    # perfil, caminho comprido) juntou 35 pontos de contexto em cima de um único
    # sinal forte e saiu como CRÍTICO. Contexto agrava o que já é suspeito; ele
    # não decide sozinho a gravidade.
    peso_forte = sum(s.peso for s in av.sinais if s.forte)
    peso_fraco = sum(s.peso for s in av.sinais if not s.forte)
    av.escore = peso_forte + min(peso_fraco, peso_forte // 2)
    return av


@dataclass(frozen=True)
class Amostra:
    """Um texto a analisar, junto com de onde ele veio."""

    origem: str
    recurso: str
    texto: str
    extra: dict[str, Any] = field(default_factory=dict)


def normalizar(texto: str) -> str:
    """Chave de agrupamento: mesmo comando em 20 processos vira um achado só."""
    return " ".join(texto.split())


_PS_PROCESSOS = (
    "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine } | "
    "Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath | "
    "ConvertTo-Json -Depth 3 -Compress"
)

# Devolve $null quando a FONTE está cega (log inacessível, desligado, ou sem um
# único evento daquele tipo em toda a história do log) e lista vazia quando o
# log funciona e só não houve evento na janela pedida. Essa diferença é o que
# separa "não achei nada" de "não consigo ver nada" — e é por RecordCount/
# IsEnabled, não por texto de erro, que varia com o idioma do Windows.
_PS_EVENTOS = r"""
$ErrorActionPreference = 'Stop'
$horas = %(horas)d
$max = %(max)d
$inicio = (Get-Date).AddHours(-$horas)

function Coletar($log, $id) {
  try { $info = Get-WinEvent -ListLog $log } catch { return $null }
  if (-not $info.IsEnabled) { return $null }
  try { $existe = @(Get-WinEvent -FilterHashtable @{ LogName=$log; Id=$id } -MaxEvents 1) }
  catch { return $null }
  if ($existe.Count -eq 0) { return $null }
  try { return ,@(Get-WinEvent -FilterHashtable @{ LogName=$log; Id=$id; StartTime=$inicio } -MaxEvents $max) }
  catch { return ,@() }
}

$r = @{}
$blocos = Coletar 'Microsoft-Windows-PowerShell/Operational' 4104
if ($null -eq $blocos) { $r.script_blocks = $null } else {
  $r.script_blocks = ,@($blocos | ForEach-Object {
    @{ hora = $_.TimeCreated.ToString('s'); texto = [string]$_.Properties[2].Value } })
}
$procs = Coletar 'Security' 4688
if ($null -eq $procs) { $r.processos_log = $null } else {
  $r.processos_log = ,@($procs | ForEach-Object {
    $p = $_.Properties
    @{ hora = $_.TimeCreated.ToString('s'); imagem = [string]$p[5].Value; texto = [string]$p[8].Value } })
}
$r | ConvertTo-Json -Depth 4 -Compress
"""


class OfuscacaoDetect(Plugin):
    nome = "ofuscacao-detect"
    descricao = "Detecta comando e script ofuscados em processos, logs de telemetria ou arquivo."
    sistemas = ()  # o motor é multiplataforma; a coleta ao vivo é Windows

    def run(self, ctx: Contexto) -> list[Finding]:
        achados: list[Finding] = []
        amostras: list[Amostra] = []
        telemetria: dict[str, int | None] = {}

        amostras += self._de_arquivo(ctx)
        if ctx.so == "Windows":
            amostras += self._de_processos()
            eventos, telemetria = self._de_eventos(ctx)
            amostras += eventos

        amostras, ignoradas = self._filtrar(amostras, ctx)
        if ignoradas:
            achados.append(self.finding(
                titulo="Amostras ignoradas por configuração",
                severidade=Severity.INFO,
                descricao=f"{sum(ignoradas.values())} comando(s) foram tirados da análise "
                          "pelos padrões em opcoes['ignorar'].",
                recomendacao="Confira a lista de vez em quando: ajuste que começa como "
                             "calibragem termina como ponto cego.",
                evidencia={"padroes": ignoradas},
            ))

        achados += self._avaliar(amostras)
        achados += self._avisar_telemetria_cega(telemetria, ctx)

        if not achados:
            achados.append(self.finding(
                titulo="Nenhum indício de ofuscação",
                severidade=Severity.INFO,
                descricao=f"Analisadas {len(amostras)} amostras de comando/script; "
                          "nada acima dos limiares.",
            ))
        return achados

    # ---- avaliação ----
    def _avaliar(self, amostras: Iterable[Amostra]) -> list[Finding]:
        grupos: dict[str, list[Amostra]] = defaultdict(list)
        for a in amostras:
            if a.texto and a.texto.strip():
                grupos[normalizar(a.texto)].append(a)

        pontuados: list[tuple[str, Avaliacao, list[Amostra]]] = []
        for texto, iguais in grupos.items():
            av = pontuar(texto)
            if av.severidade is not None:
                pontuados.append((texto, av, iguais))

        # maior escore primeiro; depois descarta o que é só um pedaço de outro
        # já relatado (o arquivo é analisado inteiro E linha por linha, então o
        # mesmo payload chegaria duas vezes)
        pontuados.sort(key=lambda t: t[1].escore, reverse=True)
        mantidos: list[tuple[str, Avaliacao, list[Amostra]]] = []
        for texto, av, iguais in pontuados:
            if any(texto in maior for maior, _, _ in mantidos):
                continue
            mantidos.append((texto, av, iguais))

        achados: list[Finding] = []
        for texto, av, iguais in mantidos:
            primeira = iguais[0]
            evidencia: dict[str, Any] = {
                "escore": av.escore,
                "sinais": [{"regra": s.regra, "peso": s.peso, "ocorrencias": s.ocorrencias,
                            "amostra": s.amostra} for s in av.sinais],
                "texto": texto[:MAX_TEXTO_EVIDENCIA],
                "ocorrencias": len(iguais),
                "origens": sorted({a.recurso for a in iguais})[:10],
            }
            if av.decodificado:
                evidencia["conteudo_decodificado"] = av.decodificado
            evidencia.update(primeira.extra)

            achados.append(self.finding(
                titulo=f"Comando ofuscado em {primeira.origem} (escore {av.escore})",
                severidade=av.severidade or Severity.LOW,
                descricao=av.resumo(),
                recurso=primeira.recurso,
                recomendacao="Confirme quem disparou esse comando. Se não houver dono "
                             "legítimo, isole o host antes de encerrar o processo — matar "
                             "primeiro apaga a pista. O conteúdo decodificado, quando "
                             "existe, está na evidência.",
                evidencia=evidencia,
                referencia=T1027,
            ))
        return achados

    def _avisar_telemetria_cega(self, telemetria: dict[str, int | None],
                                ctx: Contexto) -> list[Finding]:
        """Sem log, este módulo só vê o que está rodando AGORA. Isso tem que ser dito."""
        if ctx.so != "Windows" or not telemetria:
            return []
        avisos: list[Finding] = []
        fontes = (
            ("script_blocks", "Script block logging do PowerShell (evento 4104)",
             "Ative o Script Block Logging — sem ele, script ofuscado que já rodou "
             "não deixa rastro nenhum.", T1059),
            ("processos_log", "Criação de processo com linha de comando (evento 4688)",
             "Ative a auditoria de criação de processo com linha de comando (precisa de "
             "prompt elevado para ler o log Security).", T1059),
        )
        for chave, nome, acao, ref in fontes:
            if telemetria.get(chave) is None:
                avisos.append(self.finding(
                    titulo=f"Sem telemetria: {nome}",
                    severidade=Severity.INFO,
                    descricao="Essa fonte não respondeu (auditoria desligada ou sem "
                              "privilégio para ler o log). A detecção fica limitada ao "
                              "que está em execução neste instante — histórico, não há.",
                    recomendacao=acao + " Veja também o hardening-audit.",
                    recurso=nome, referencia=ref,
                ))
        return avisos

    @staticmethod
    def _filtrar(amostras: Iterable[Amostra],
                 ctx: Contexto) -> tuple[list[Amostra], dict[str, int]]:
        """Tira da análise o que casar com `opcoes['ignorar']` (lista por vírgula).

        Calibrar é parte do trabalho: toda ferramenta legítima da casa que use o
        mesmo formato de um ataque vai aparecer aqui. O que não pode é a
        supressão ser calada — por isso o que foi ignorado é contado e relatado.
        """
        bruto = str(ctx.opcoes.get("ignorar") or "").strip()
        padroes = [p.strip().lower() for p in bruto.split(",") if p.strip()]
        if not padroes:
            return list(amostras), {}

        mantidas: list[Amostra] = []
        contagem: dict[str, int] = {}
        for a in amostras:
            alvo = a.texto.lower()
            casou = next((p for p in padroes if p in alvo), None)
            if casou:
                contagem[casou] = contagem.get(casou, 0) + 1
            else:
                mantidas.append(a)
        return mantidas, contagem

    # ---- coletores (só leitura) ----
    @staticmethod
    def _de_arquivo(ctx: Contexto) -> list[Amostra]:
        caminho = ctx.opcoes.get("arquivo")
        if not caminho or not os.path.isfile(caminho):
            return []
        with open(caminho, encoding="utf-8", errors="replace") as fh:
            conteudo = fh.read()
        nome = os.path.basename(caminho)
        # script inteiro de uma vez e também linha por linha: payload às vezes
        # mora em uma linha só, e aí a média do arquivo esconderia o sinal
        amostras = [Amostra("arquivo", nome, conteudo, {"caminho": caminho})]
        for i, linha in enumerate(conteudo.splitlines(), 1):
            if len(linha.strip()) >= 40:
                amostras.append(Amostra("arquivo", f"{nome}:{i}", linha,
                                        {"caminho": caminho}))
        return amostras

    @staticmethod
    def _de_processos() -> list[Amostra]:
        dados = _powershell_json(_PS_PROCESSOS)
        if dados is None:
            return []
        lista = dados if isinstance(dados, list) else [dados]
        amostras: list[Amostra] = []
        for p in lista:
            cmd = p.get("CommandLine")
            if not cmd:
                continue
            nome = p.get("Name") or "?"
            amostras.append(Amostra(
                "processo em execução", f"PID {p.get('ProcessId')} ({nome})", cmd,
                {"executavel": p.get("ExecutablePath"), "pid_pai": p.get("ParentProcessId")}))
        return amostras

    @staticmethod
    def _de_eventos(ctx: Contexto) -> tuple[list[Amostra], dict[str, int | None]]:
        """Devolve as amostras e quantas linhas cada fonte deu (None = não respondeu)."""
        horas = _inteiro(ctx.opcoes.get("horas"), 24)
        maximo = _inteiro(ctx.opcoes.get("eventos"), 300)
        dados = _powershell_json(_PS_EVENTOS % {"horas": horas, "max": maximo})
        if not isinstance(dados, dict):
            return [], {"script_blocks": None, "processos_log": None}

        amostras: list[Amostra] = []
        contagem: dict[str, int | None] = {}

        blocos = _como_lista(dados.get("script_blocks"))
        contagem["script_blocks"] = None if blocos is None else len(blocos)
        for ev in blocos or []:
            amostras.append(Amostra("log do PowerShell (4104)",
                                    f"evento 4104 em {ev.get('hora')}",
                                    ev.get("texto") or "", {"hora": ev.get("hora")}))

        procs = _como_lista(dados.get("processos_log"))
        contagem["processos_log"] = None if procs is None else len(procs)
        for ev in procs or []:
            amostras.append(Amostra("log de criação de processo (4688)",
                                    f"evento 4688 em {ev.get('hora')}",
                                    ev.get("texto") or "",
                                    {"hora": ev.get("hora"), "imagem": ev.get("imagem")}))
        return amostras, contagem


def _como_lista(valor: Any) -> list[dict] | None:
    """O ConvertTo-Json desembrulha lista de um item em objeto; isso reembrulha."""
    if valor is None:
        return None
    if isinstance(valor, dict):
        return [valor]
    return [v for v in valor if isinstance(v, dict)]


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

