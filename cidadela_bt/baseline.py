"""Baseline e diff: guarda uma foto dos achados e compara com a atual.

Monitorar não é repetir o relatório inteiro toda vez — é avisar o que MUDOU.
Uma porta que abriu, um cabeçalho que caiu, um arquivo que apareceu. É a
diferença entre o alarme que dispara com folha ao vento e o que dispara quando
alguém pula o muro.

Cada achado tem uma impressão digital estável (plugin + título + recurso); a
severidade e o texto podem variar sem mudar a identidade. Comparar dois
conjuntos dessas impressões dá os NOVOS, os RESOLVIDOS e os que PERSISTEM.

Funções puras, sem rede nem relógio — o diff inteiro é testável.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .plugin import Severity

if TYPE_CHECKING:
    from .core import Relatorio

_POR_ROTULO = {s.rotulo: s for s in Severity}


def impressao(plugin: str, titulo: str, recurso: str) -> str:
    return "|".join((plugin.strip(), titulo.strip(), recurso.strip()))


@dataclass(frozen=True)
class Entrada:
    impressao: str
    severidade: Severity
    titulo: str
    recurso: str
    plugin: str


@dataclass(frozen=True)
class Diff:
    novos: list[Entrada]
    resolvidos: list[Entrada]
    persistentes: list[Entrada]

    @property
    def houve_mudanca(self) -> bool:
        return bool(self.novos or self.resolvidos)


def entradas_do_relatorio(rel: "Relatorio") -> dict[str, Entrada]:
    saida: dict[str, Entrada] = {}
    for r in rel.resultados:
        for f in r.findings:
            imp = impressao(f.plugin, f.titulo, f.recurso)
            saida[imp] = Entrada(imp, f.severidade, f.titulo, f.recurso, f.plugin)
    return saida


def comparar(baseline: dict[str, Entrada], atual: dict[str, Entrada]) -> Diff:
    novos = [v for k, v in atual.items() if k not in baseline]
    resolvidos = [v for k, v in baseline.items() if k not in atual]
    persistentes = [v for k, v in atual.items() if k in baseline]
    ordem = lambda e: (-int(e.severidade), e.plugin, e.titulo)
    return Diff(sorted(novos, key=ordem), sorted(resolvidos, key=ordem),
               sorted(persistentes, key=ordem))


def salvar_baseline(caminho: str, rel: "Relatorio") -> None:
    entradas = entradas_do_relatorio(rel)
    payload = {
        "gerado_em": rel.gerado_em,
        "alvo": rel.alvo,
        "entradas": [{"impressao": e.impressao, "severidade": e.severidade.rotulo,
                      "titulo": e.titulo, "recurso": e.recurso, "plugin": e.plugin}
                     for e in entradas.values()],
    }
    with open(caminho, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def carregar_baseline(caminho: str) -> dict[str, Entrada]:
    """Baseline inexistente ou ilegível vira conjunto vazio: na primeira vez,
    tudo é novo — que é o comportamento certo."""
    try:
        with open(caminho, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    saida: dict[str, Entrada] = {}
    for d in payload.get("entradas", []):
        imp = d.get("impressao") or impressao(d.get("plugin", ""), d.get("titulo", ""),
                                              d.get("recurso", ""))
        sev = _POR_ROTULO.get(d.get("severidade", ""), Severity.INFO)
        saida[imp] = Entrada(imp, sev, d.get("titulo", ""), d.get("recurso", ""),
                            d.get("plugin", ""))
    return saida
