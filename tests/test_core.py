"""Testes do orquestrador: isolamento de falha e filtragem por plugin."""

from cidadela_bt.core import Orquestrador
from cidadela_bt.plugin import Contexto, Finding, Plugin, Severity


class PluginOk(Plugin):
    nome = "ok"

    def run(self, ctx: Contexto) -> list[Finding]:
        return [self.finding(titulo="t", severidade=Severity.LOW, descricao="d")]


class PluginQuebrado(Plugin):
    nome = "quebrado"

    def run(self, ctx: Contexto) -> list[Finding]:
        raise RuntimeError("boom")


def test_falha_de_um_plugin_nao_derruba_os_outros():
    orq = Orquestrador(plugins=[PluginOk(), PluginQuebrado()])
    rel = orq.rodar(Contexto())
    por_nome = {r.plugin: r for r in rel.resultados}
    assert por_nome["ok"].ok and len(por_nome["ok"].findings) == 1
    assert not por_nome["quebrado"].ok
    assert "boom" in por_nome["quebrado"].erro
    assert rel.total_achados == 1


def test_filtro_apenas():
    orq = Orquestrador(plugins=[PluginOk(), PluginQuebrado()])
    rel = orq.rodar(Contexto(), apenas={"ok"})
    assert [r.plugin for r in rel.resultados] == ["ok"]


def test_nao_aplicavel_por_so():
    class SoLinux(Plugin):
        nome = "so-linux"
        sistemas = ("Linux",)

        def run(self, ctx: Contexto) -> list[Finding]:
            return []

    orq = Orquestrador(plugins=[SoLinux()])
    rel = orq.rodar(Contexto(so="Windows"))
    assert rel.resultados == []
