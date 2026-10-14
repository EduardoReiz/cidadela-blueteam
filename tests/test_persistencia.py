"""Testes da heurística de persistência (pura, roda em qualquer SO)."""

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.persistencia_audit import (
    avaliar_comando, severidade_de, tier_caminho, caminho_exe, _primeiro_exe,
)


def _textos(motivos):
    return " | ".join(m for _, m in motivos)


def test_appdata_assinado_fica_baixo_na_heuristica():
    # A heurística marca AppData como BAIXA; a supressão por assinatura é no run().
    motivos = avaliar_comando("OneDrive", r"C:\Users\joao\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background")
    assert severidade_de(motivos) is Severity.LOW
    assert "AppData" in _textos(motivos)


def test_executavel_em_temp_e_alta():
    motivos = avaliar_comando("x", r"C:\Users\joao\AppData\Local\Temp\svch0st.exe")
    assert severidade_de(motivos) is Severity.HIGH
    assert "temporária" in _textos(motivos)


def test_powershell_encoded_pega_lolbin_e_encoded():
    motivos = avaliar_comando("y", "powershell.exe -w hidden -enc SQBFAFgA")
    txt = _textos(motivos)
    assert severidade_de(motivos) is Severity.HIGH
    assert "codificado" in txt and "abusável" in txt


def test_caminho_sem_aspas_com_espaco():
    motivos = avaliar_comando("z", r"C:\Program Files\App Legal\run.exe --go")
    assert "sem aspas" in _textos(motivos)
    assert severidade_de(motivos) >= Severity.MEDIUM


def test_comando_vazio_sem_motivos():
    assert avaliar_comando("v", "   ") == []
    assert severidade_de([]) is Severity.INFO


def test_tier_caminho():
    assert tier_caminho(r"C:\x\Temp\a.exe") == "temp"
    assert tier_caminho(r"C:\Users\j\AppData\Roaming\a.exe") == "appdata"
    assert tier_caminho(r"C:\Program Files\App\a.exe") == "outro"


def test_primeiro_exe_e_caminho_exe():
    assert _primeiro_exe(r'"C:\a b\p.exe" --x') == "p.exe"
    assert _primeiro_exe(r"C:\a\q.EXE arg") == "q.exe"
    assert caminho_exe(r'"C:\a b\p.exe" --x') == r"C:\a b\p.exe"
