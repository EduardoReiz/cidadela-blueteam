"""Detecção de tunelamento DNS — espelho DEFENSIVO do túnel/C2.

Em vez de criar o túnel, procura o PADRÃO dele no DNS: exfiltração/C2 por DNS
tende a gerar muitos subdomínios distintos sob um mesmo domínio, rótulos longos
e com alta aleatoriedade (dados codificados em base32/hex no nome).

Fontes de dados (só leitura):
  - cache do resolvedor local (`Get-DnsClientCache`) — disponível ao vivo, mas
    limitado (TTL); bom pra um retrato rápido.
  - arquivo de nomes consultados (um por linha), via opção `arquivo=<path>` —
    aponte para logs reais (DNS do servidor, Zeek, pihole) para fidelidade alta.

HONESTIDADE: os limiares abaixo são um ponto de partida sensato. Em produção,
calibre-os contra o SEU tráfego para equilibrar detecção x falso-positivo.
Mapeia para MITRE ATT&CK T1071.004 / T1048 (C2 e exfiltração por DNS).
"""

from __future__ import annotations

import json
import math
import os
import subprocess
from collections import defaultdict

from ..plugin import Contexto, Finding, Plugin, Severity

# --- limiares (tunáveis) ---
MIN_AMOSTRAS = 8          # domínios com menos nomes que isso são ignorados (ruído)
LIMITE_ROTULO = 40        # rótulo acima disto sugere dados codificados
LIMITE_ENTROPIA = 3.6     # bits/caractere perto do aleatório (máx teórico ~5.2)
LIMITE_CARDINALIDADE = 40  # subdomínios distintos sob um mesmo domínio

# sufixos compostos comuns, para extrair o domínio registrável corretamente
_SUFIXOS = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "dev.br",
    "co.uk", "org.uk", "gov.uk", "com.au", "co.jp", "com.mx",
}

Item = tuple[Severity, str]


def entropia(s: str) -> float:
    """Entropia de Shannon (bits por caractere) de uma string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def dominio_registravel(nome: str) -> str:
    partes = nome.strip(".").lower().split(".")
    if len(partes) <= 2:
        return ".".join(partes)
    ult2 = ".".join(partes[-2:])
    if ult2 in _SUFIXOS and len(partes) >= 3:
        return ".".join(partes[-3:])
    return ult2


def avaliar_dominio(parent: str, nomes: list[str]) -> tuple[Severity, list[str], dict]:
    """Avalia os nomes agrupados sob um domínio. Pura/testável."""
    subs: set[str] = set()
    max_label = 0
    entropias: list[float] = []

    for n in nomes:
        n = n.strip(".").lower()
        sub = n[: -len(parent)].rstrip(".") if n.endswith(parent) and n != parent else ""
        if sub:
            subs.add(sub)
            for lab in sub.split("."):
                if lab:
                    max_label = max(max_label, len(lab))
                    entropias.append(entropia(lab))

    card = len(subs)
    ent_med = sum(entropias) / len(entropias) if entropias else 0.0
    stats = {"subdominios_distintos": card, "maior_rotulo": max_label,
             "entropia_media": round(ent_med, 2), "amostras": len(nomes)}

    motivos: list[str] = []
    pesos: list[Severity] = []
    if max_label > LIMITE_ROTULO:
        motivos.append(f"rótulo muito longo ({max_label} chars) — típico de dados codificados")
        pesos.append(Severity.MEDIUM)
    if ent_med > LIMITE_ENTROPIA:
        motivos.append(f"alta aleatoriedade nos rótulos (entropia {ent_med:.1f}/char) — possível payload")
        pesos.append(Severity.MEDIUM)
    if card > LIMITE_CARDINALIDADE:
        motivos.append(f"{card} subdomínios distintos sob {parent} — volume típico de túnel")
        pesos.append(Severity.HIGH)

    sev = max(pesos, default=Severity.INFO)
    if len(motivos) >= 2:  # múltiplos indícios juntos => eleva
        sev = Severity.HIGH
    return sev, motivos, stats


class DnsTunnelDetect(Plugin):
    nome = "dns-tunnel-detect"
    descricao = "Detecta indícios de tunelamento/exfiltração por DNS (cache local ou log)."
    sistemas = ()  # a heurística é multiplataforma; a coleta ao vivo é Windows

    def run(self, ctx: Contexto) -> list[Finding]:
        nomes = list(self._coletar(ctx))
        if not nomes:
            return [self.finding(
                titulo="Sem dados de DNS para analisar",
                severidade=Severity.INFO,
                descricao="Cache local vazio e nenhum arquivo informado "
                          "(use opcoes['arquivo']=<caminho de log de nomes>).",
            )]

        grupos: dict[str, list[str]] = defaultdict(list)
        for n in nomes:
            grupos[dominio_registravel(n)].append(n)

        achados: list[Finding] = []
        for parent, lista in grupos.items():
            if len(lista) < MIN_AMOSTRAS:
                continue
            sev, motivos, stats = avaliar_dominio(parent, lista)
            if not motivos:
                continue
            achados.append(self.finding(
                titulo=f"Possível tunelamento DNS: {parent}",
                severidade=sev,
                descricao="; ".join(motivos),
                recurso=parent,
                recomendacao="Investigue o processo que consulta esse domínio e o "
                             "destino. Se não for serviço legítimo (CDN/telemetria), "
                             "bloqueie o domínio e isole o host.",
                evidencia=stats,
                referencia="MITRE ATT&CK T1071.004 / T1048",
            ))
        return achados or [self.finding(
            titulo="Nenhum indício de tunelamento DNS",
            severidade=Severity.INFO,
            descricao=f"Analisados {len(nomes)} nomes em {len(grupos)} domínios; nada acima dos limiares.",
        )]

    def _coletar(self, ctx: Contexto):
        arq = ctx.opcoes.get("arquivo")
        if arq and os.path.isfile(arq):
            with open(arq, encoding="utf-8", errors="replace") as fh:
                for linha in fh:
                    nome = linha.strip()
                    if nome and not nome.startswith("#"):
                        yield nome
        yield from self._cache_dns()

    @staticmethod
    def _cache_dns():
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-DnsClientCache | Select-Object -ExpandProperty Entry"],
                capture_output=True, text=True, errors="replace", timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return
        for linha in (r.stdout or "").splitlines():
            nome = linha.strip()
            if nome:
                yield nome
