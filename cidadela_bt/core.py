"""Orquestrador: descobre plugins, executa cada um de forma isolada e agrega.

Descoberta é automática: qualquer subclasse de `Plugin` dentro do pacote
`cidadela_bt.plugins` é registrada sozinha. Adicionar um módulo = criar um
arquivo lá; não precisa mexer aqui.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import time
from dataclasses import dataclass, field

from . import plugins as pacote_plugins
from .plugin import Contexto, Plugin, PluginResult, agora_iso

log = logging.getLogger("cidadela_bt.core")


@dataclass
class Relatorio:
    """Agregado de toda a execução."""

    alvo: str
    gerado_em: str
    resultados: list[PluginResult] = field(default_factory=list)

    @property
    def total_achados(self) -> int:
        return sum(len(r.findings) for r in self.resultados)

    def por_severidade(self) -> dict[str, int]:
        contagem: dict[str, int] = {}
        for r in self.resultados:
            for f in r.findings:
                contagem[f.severidade.rotulo] = contagem.get(f.severidade.rotulo, 0) + 1
        return contagem


def descobrir_plugins() -> list[Plugin]:
    """Instancia todas as subclasses de Plugin achadas em cidadela_bt.plugins."""
    encontrados: list[Plugin] = []
    for mod in pkgutil.iter_modules(pacote_plugins.__path__):
        modulo = importlib.import_module(f"{pacote_plugins.__name__}.{mod.name}")
        for _, obj in inspect.getmembers(modulo, inspect.isclass):
            if issubclass(obj, Plugin) and obj is not Plugin and obj.__module__ == modulo.__name__:
                try:
                    encontrados.append(obj())
                except Exception:  # noqa: BLE001 - um plugin quebrado não derruba a descoberta
                    log.exception("Falha ao instanciar plugin %s", obj.__name__)
    encontrados.sort(key=lambda p: p.nome)
    return encontrados


class Orquestrador:
    def __init__(self, plugins: list[Plugin] | None = None) -> None:
        self.plugins = plugins if plugins is not None else descobrir_plugins()

    def listar(self) -> list[Plugin]:
        return self.plugins

    def rodar(self, ctx: Contexto, apenas: set[str] | None = None) -> Relatorio:
        rel = Relatorio(alvo=ctx.alvo, gerado_em=agora_iso())
        for p in self.plugins:
            if apenas and p.nome not in apenas:
                continue
            if not p.aplicavel(ctx):
                log.info("Pulando %s (não aplicável a %s)", p.nome, ctx.so)
                continue
            rel.resultados.append(self._rodar_um(p, ctx))
        return rel

    @staticmethod
    def _rodar_um(p: Plugin, ctx: Contexto) -> PluginResult:
        res = PluginResult(plugin=p.nome, iniciado_em=agora_iso())
        t0 = time.perf_counter()
        try:
            res.findings = list(p.run(ctx))
        except Exception as e:  # noqa: BLE001 - isola a falha de um plugin
            res.erro = f"{type(e).__name__}: {e}"
            log.exception("Plugin %s falhou", p.nome)
        res.duracao_s = round(time.perf_counter() - t0, 3)
        return res
