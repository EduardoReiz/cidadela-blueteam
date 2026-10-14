"""Testes das avaliações puras de política de senha e contas."""

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.politica_senha_audit import avaliar_politica, avaliar_contas


def _titulos(itens):
    return [t for _, t, _, _ in itens]


def test_politica_forte_nao_gera_achado():
    forte = {"MinimumPasswordLength": 14, "PasswordComplexity": 1,
             "PasswordHistorySize": 24, "LockoutBadCount": 10, "ClearTextPassword": 0}
    assert avaliar_politica(forte) == []


def test_senha_curta_e_media_ou_alta():
    itens = avaliar_politica({"MinimumPasswordLength": 6})
    sev = itens[0][0]
    assert sev is Severity.HIGH  # < 8 => ALTA
    itens2 = avaliar_politica({"MinimumPasswordLength": 10})
    assert itens2[0][0] is Severity.MEDIUM  # 8..13 => MEDIA


def test_sem_bloqueio_e_alta():
    itens = avaliar_politica({"LockoutBadCount": 0})
    assert any(t == "Bloqueio de conta desativado" for _, t, _, _ in itens)
    assert any(s is Severity.HIGH for s, *_ in itens)


def test_texto_reversivel_e_critico():
    itens = avaliar_politica({"ClearTextPassword": 1})
    assert any(s is Severity.CRITICAL for s, *_ in itens)
    assert any(t == "Senhas armazenadas em texto reversível" for _, t, _, _ in itens)


def test_conta_sem_senha_e_critico():
    contas = [{"Name": "teste", "Enabled": True, "PasswordRequired": False}]
    itens = avaliar_contas(contas)
    assert itens and itens[0][0] is Severity.CRITICAL


def test_guest_habilitado():
    contas = [{"Name": "Guest", "Enabled": True, "PasswordRequired": True}]
    assert "Conta de convidado habilitada" in _titulos(avaliar_contas(contas))


def test_conta_desabilitada_nao_gera():
    contas = [{"Name": "Guest", "Enabled": False, "PasswordRequired": False}]
    assert avaliar_contas(contas) == []
