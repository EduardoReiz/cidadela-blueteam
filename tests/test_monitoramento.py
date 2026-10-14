"""Testes do baseline/diff e da montagem do aviso de Telegram."""

from cidadela_bt.baseline import (
    Entrada,
    carregar_baseline,
    comparar,
    entradas_do_relatorio,
    impressao,
    salvar_baseline,
)
from cidadela_bt.core import Relatorio
from cidadela_bt.notificador import config_telegram, montar_mensagem
from cidadela_bt.plugin import Finding, PluginResult, Severity


def _rel(*findings: Finding, alvo="localhost") -> Relatorio:
    res = PluginResult(plugin="t")
    res.findings = list(findings)
    return Relatorio(alvo=alvo, gerado_em="2026-10-07T00:00:00+00:00", resultados=[res])


def _f(titulo, sev=Severity.HIGH, recurso="r", plugin="p"):
    return Finding(plugin=plugin, titulo=titulo, severidade=sev, descricao="d", recurso=recurso)


def _ent(titulo, sev=Severity.HIGH, recurso="r", plugin="p"):
    return Entrada(impressao(plugin, titulo, recurso), sev, titulo, recurso, plugin)


# ---- impressão / extração ----
def test_impressao_estavel_e_ignora_espacos():
    assert impressao("p", "t", "r") == impressao(" p ", " t ", " r ")


def test_entradas_do_relatorio():
    ent = entradas_do_relatorio(_rel(_f("A"), _f("B", recurso="r2")))
    assert len(ent) == 2
    assert all(isinstance(v, Entrada) for v in ent.values())


# ---- diff ----
def test_tudo_novo_contra_baseline_vazio():
    atual = {e.impressao: e for e in (_ent("A"), _ent("B"))}
    diff = comparar({}, atual)
    assert len(diff.novos) == 2 and not diff.resolvidos
    assert diff.houve_mudanca


def test_novos_resolvidos_persistentes():
    base = {e.impressao: e for e in (_ent("A"), _ent("B"))}
    atual = {e.impressao: e for e in (_ent("B"), _ent("C"))}
    diff = comparar(base, atual)
    assert [e.titulo for e in diff.novos] == ["C"]
    assert [e.titulo for e in diff.resolvidos] == ["A"]
    assert [e.titulo for e in diff.persistentes] == ["B"]


def test_sem_mudanca_nao_acusa():
    base = {e.impressao: e for e in (_ent("A"),)}
    diff = comparar(base, dict(base))
    assert not diff.houve_mudanca
    assert [e.titulo for e in diff.persistentes] == ["A"]


def test_novos_vem_do_mais_grave_ao_menos():
    atual = {e.impressao: e for e in (
        _ent("baixa", Severity.LOW), _ent("critica", Severity.CRITICAL),
        _ent("media", Severity.MEDIUM))}
    diff = comparar({}, atual)
    assert [e.titulo for e in diff.novos] == ["critica", "media", "baixa"]


# ---- baseline em disco ----
def test_salvar_e_carregar_roundtrip(tmp_path):
    caminho = str(tmp_path / "b.json")
    salvar_baseline(caminho, _rel(_f("A", Severity.CRITICAL), _f("B", Severity.LOW)))
    carregado = carregar_baseline(caminho)
    assert len(carregado) == 2
    sevs = {e.titulo: e.severidade for e in carregado.values()}
    assert sevs["A"] is Severity.CRITICAL and sevs["B"] is Severity.LOW


def test_baseline_inexistente_vira_vazio():
    assert carregar_baseline("nao_existe_123.json") == {}


def test_diff_apos_roundtrip(tmp_path):
    caminho = str(tmp_path / "b.json")
    salvar_baseline(caminho, _rel(_f("A"), _f("B")))
    base = carregar_baseline(caminho)
    atual = entradas_do_relatorio(_rel(_f("B"), _f("C")))
    diff = comparar(base, atual)
    assert [e.titulo for e in diff.novos] == ["C"]
    assert [e.titulo for e in diff.resolvidos] == ["A"]


# ---- mensagem ----
def test_mensagem_lista_novos():
    diff = comparar({}, {e.impressao: e for e in (_ent("Porta 6379 aberta", Severity.HIGH),)})
    msg = montar_mensagem("cidadela.dev.br", diff)
    assert msg and "Porta 6379 aberta" in msg and "1 novo" in msg
    assert "cidadela.dev.br" in msg


def test_mensagem_none_quando_nada_relevante():
    assert montar_mensagem("x", comparar({}, {})) is None


def test_mensagem_filtra_por_severidade():
    diff = comparar({}, {e.impressao: e for e in (_ent("ruido", Severity.INFO),)})
    assert montar_mensagem("x", diff, min_severidade=Severity.LOW) is None
    assert montar_mensagem("x", diff, min_severidade=Severity.INFO) is not None


def test_mensagem_conta_resolvidos():
    base = {e.impressao: e for e in (_ent("antigo", Severity.HIGH),)}
    msg = montar_mensagem("x", comparar(base, {}))
    assert msg and "resolvido" in msg


def test_mensagem_trunca_lista_longa():
    muitos = {e.impressao: e for e in (_ent(f"achado {i}") for i in range(30))}
    msg = montar_mensagem("x", comparar({}, muitos), max_itens=15)
    assert "e mais 15" in msg


def test_html_e_escapado_na_mensagem():
    diff = comparar({}, {e.impressao: e for e in (_ent("<script>alerta</script>"),)})
    msg = montar_mensagem("x", diff)
    assert "<script>" not in msg and "&lt;script&gt;" in msg


# ---- estilo cinema ----
def test_cinema_tem_painel_e_barra():
    diff = comparar({}, {e.impressao: e for e in (
        _ent("Intrusao detectada", Severity.CRITICAL, "1.2.3.4"),)})
    msg = montar_mensagem("cidadela.dev.br", diff, estilo="cinema")
    assert "VARREDURA DE PERÍMETRO" in msg
    assert "▓▓▓▓▓▓▓▓" in msg          # crítico = barra cheia
    assert "<pre>" in msg and "Intrusao detectada" in msg


def test_cinema_barra_cresce_com_gravidade():
    def barra(sev):
        d = comparar({}, {e.impressao: e for e in (_ent("x", sev, "r"),)})
        return montar_mensagem("a", d, estilo="cinema", min_severidade=Severity.INFO)
    assert "▓░░░░░░░" in barra(Severity.INFO)
    assert "▓▓▓▓░░░░" in barra(Severity.MEDIUM)
    assert "▓▓▓▓▓▓▓▓" in barra(Severity.CRITICAL)


def test_cinema_escapa_html():
    diff = comparar({}, {e.impressao: e for e in (_ent("<b>x</b>", Severity.HIGH, "<i>r</i>"),)})
    msg = montar_mensagem("a", diff, estilo="cinema")
    assert "<b>x</b>" not in msg and "&lt;b&gt;x&lt;/b&gt;" in msg


def test_cinema_sem_mudanca_e_none():
    assert montar_mensagem("a", comparar({}, {}), estilo="cinema") is None


# ---- config do telegram (sem rede) ----
def test_config_vem_das_opcoes():
    cfg = config_telegram({"telegram_token": "123:ABC", "telegram_chat": "999"})
    assert cfg == ("123:ABC", "999")


def test_config_ausente_e_none(monkeypatch):
    monkeypatch.delenv("CIDADELA_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("CIDADELA_TELEGRAM_CHAT", raising=False)
    assert config_telegram({}) is None
    assert config_telegram({"telegram_token": "só-token"}) is None


def test_config_vem_do_ambiente(monkeypatch):
    monkeypatch.setenv("CIDADELA_TELEGRAM_TOKEN", "T")
    monkeypatch.setenv("CIDADELA_TELEGRAM_CHAT", "C")
    assert config_telegram({}) == ("T", "C")


def test_opcao_tem_prioridade_sobre_ambiente(monkeypatch):
    monkeypatch.setenv("CIDADELA_TELEGRAM_TOKEN", "amb")
    monkeypatch.setenv("CIDADELA_TELEGRAM_CHAT", "amb")
    assert config_telegram({"telegram_token": "op", "telegram_chat": "op"}) == ("op", "op")
