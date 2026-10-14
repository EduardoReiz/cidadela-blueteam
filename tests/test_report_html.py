"""Testes do relatório HTML."""

from cidadela_bt.core import Relatorio
from cidadela_bt.plugin import Finding, PluginResult, Severity
from cidadela_bt.report import para_html


def _rel(*findings, alvo="localhost"):
    res = PluginResult(plugin="t")
    res.findings = list(findings)
    return Relatorio(alvo=alvo, gerado_em="2026-10-07T00:00:00+00:00", resultados=[res])


def _f(titulo, sev=Severity.HIGH, recurso="r", desc="d", rec="conserta", ref="REF"):
    return Finding(plugin="p", titulo=titulo, severidade=sev, descricao=desc,
                   recurso=recurso, recomendacao=rec, referencia=ref)


def test_html_bem_formado_e_tem_alvo():
    out = para_html(_rel(_f("Porta aberta"), alvo="cidadela.dev.br"))
    assert out.startswith("<!doctype html>")
    assert "</html>" in out
    assert "cidadela.dev.br" in out
    assert "Porta aberta" in out


def test_html_tem_viewport_mobile():
    out = para_html(_rel(_f("x")))
    assert 'name="viewport"' in out


def test_html_escapa_conteudo():
    out = para_html(_rel(_f("<script>x</script>", desc="<b>y</b>")))
    assert "<script>x</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_mostra_severidades():
    out = para_html(_rel(_f("a", Severity.CRITICAL), _f("b", Severity.LOW)))
    assert "CRITICA" in out and "BAIXA" in out


def test_html_sem_achados():
    out = para_html(_rel())
    assert "sem achados" in out or "nenhum achado" in out
