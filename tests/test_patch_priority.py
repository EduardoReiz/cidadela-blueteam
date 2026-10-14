"""Testes da priorização de correção.

A parte de rede (NVD) é testada com resposta gravada à mão, no formato do NVD
2.0: o que precisa de prova aqui é o casamento de FAIXA DE VERSÃO, que é o que
separa este módulo de uma busca por palavra-chave.
"""

from datetime import date

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.patch_priority import (
    Escuta,
    Programa,
    _mesmo_software,
    _produto_no_cpe,
    _termo_de_busca,
    atribuir_escutas,
    avaliar_abandonado,
    forca_do_casamento,
    avaliar_patches,
    avaliar_suporte_so,
    comparar_versoes,
    cves_que_casam,
    normalizar_versao,
    pontuar_prioridade,
    priorizar,
    severidade_de_cvss,
    versao_na_faixa,
)

HOJE = date(2026, 10, 7)


def _titulos(itens):
    return [i.titulo for i in itens]


# ---- versões ----
def test_normalizar_versao():
    assert normalizar_versao("2.3.10") == (2, 3, 10)
    assert normalizar_versao("1.0.0-beta2") == (1, 0, 0)
    assert normalizar_versao("130.0.6723.117") == (130, 0, 6723, 117)
    assert normalizar_versao("") == ()
    assert normalizar_versao("sem numero") == ()


def test_comparar_versoes_campo_por_campo():
    assert comparar_versoes("1.2.3", "1.2.3") == 0
    assert comparar_versoes("1.10", "1.9") == 1      # 10 > 9, não "1.1 > 1.9"
    assert comparar_versoes("1.2", "1.2.1") == -1    # campo faltante vale 0
    assert comparar_versoes("2.0", "10.0") == -1


def test_versao_na_faixa():
    assert versao_na_faixa("6.20", fim_excl="6.23")
    assert not versao_na_faixa("6.23", fim_excl="6.23")
    assert versao_na_faixa("6.23", fim_incl="6.23")
    assert versao_na_faixa("5.0", inicio_incl="4.0", fim_excl="6.0")
    assert not versao_na_faixa("3.9", inicio_incl="4.0", fim_excl="6.0")
    assert not versao_na_faixa("4.0", inicio_excl="4.0")


def test_versao_ilegivel_nunca_casa():
    # sem versão não há como priorizar: melhor não casar do que casar errado
    assert not versao_na_faixa("", fim_excl="9.0")
    assert not versao_na_faixa("qualquer", fim_excl="9.0")


# ---- suporte do SO ----
def test_build_fora_de_suporte_e_critico():
    itens = avaliar_suporte_so(19045, HOJE)      # Windows 10 22H2, fim 2025-10-14
    assert itens[0].severidade is Severity.CRITICAL
    assert "fora de suporte" in itens[0].titulo


def test_build_perto_do_fim_e_media():
    itens = avaliar_suporte_so(26100, HOJE)      # 24H2, fim 2026-10-13: 6 dias
    assert itens[0].severidade is Severity.MEDIUM
    assert itens[0].evidencia["dias_restantes"] == 6


def test_build_em_suporte_e_info():
    itens = avaliar_suporte_so(26200, HOJE)      # 25H2
    assert itens[0].severidade is Severity.INFO


def test_build_desconhecido_admite_que_nao_sabe():
    itens = avaliar_suporte_so(99999, HOJE)
    assert itens[0].severidade is Severity.INFO
    assert "não está na tabela" in itens[0].titulo
    assert itens[0].evidencia["tabela_de"]


def test_sem_build_nao_inventa():
    assert avaliar_suporte_so(None, HOJE) == []


# ---- ciclo de patch ----
def test_patch_recente_e_maquina_reiniciada_nao_geram_nada():
    assert avaliar_patches("2026-10-01", HOJE, False, True, 3) == []


def test_patch_muito_antigo_e_alta():
    itens = avaliar_patches("2026-01-01", HOJE, False, True, 1)
    assert itens[0].severidade is Severity.HIGH
    assert itens[0].evidencia["dias"] == 279


def test_faixas_de_atraso_de_patch():
    assert avaliar_patches("2026-08-20", HOJE, False, True, 1)[0].severidade is Severity.MEDIUM
    assert avaliar_patches("2026-08-31", HOJE, False, True, 1)[0].severidade is Severity.LOW


def test_reinicio_pendente_e_media():
    itens = avaliar_patches("2026-10-05", HOJE, True, True, 2)
    assert any(i.severidade is Severity.MEDIUM and "Reinício pendente" in i.titulo
               for i in itens)


def test_servico_de_atualizacao_desligado_e_alta():
    itens = avaliar_patches("2026-10-05", HOJE, False, False, 1)
    assert any(i.severidade is Severity.HIGH and "atualização" in i.titulo for i in itens)


def test_uptime_longo_e_baixa():
    itens = avaliar_patches("2026-10-05", HOJE, False, True, 120)
    assert any(i.severidade is Severity.LOW and "sem reiniciar" in i.titulo for i in itens)


def test_sem_data_de_patch_admite_que_nao_sabe():
    itens = avaliar_patches("", HOJE, False, True, 1)
    assert itens[0].severidade is Severity.INFO


# ---- software abandonado ----
def test_python2_e_alta():
    itens = avaliar_abandonado([Programa("Python 2.7.18", "2.7.18")])
    assert itens[0].severidade is Severity.HIGH


def test_python3_nao_e_acusado():
    assert avaliar_abandonado([Programa("Python 3.14.0", "3.14.0")]) == []


def test_winrar_antigo_sim_novo_nao():
    assert avaliar_abandonado([Programa("WinRAR 5.91", "5.91")])
    assert avaliar_abandonado([Programa("WinRAR 7.01", "7.01")]) == []


def test_node_antigo_pelo_numero_de_versao():
    assert avaliar_abandonado([Programa("Node.js", "16.20.2")])
    assert avaliar_abandonado([Programa("Node.js", "22.9.0")]) == []


def test_inventario_limpo_nao_gera_nada():
    limpo = [Programa("Git", "2.47.0"), Programa("Visual Studio Code", "1.95.0"),
             Programa("Docker Desktop", "4.35.1")]
    assert avaliar_abandonado(limpo) == []


# ---- prioridade e exposição ----
def test_substring_nao_cria_categoria_errada():
    # "redis" dentro de "Redistributable" fazia o runtime do Visual C++ ser
    # classificado como banco de dados
    for nome in ("Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664",
                 "Microsoft Visual C++ v14 Redistributable (x86) - 14.50.35719"):
        p = pontuar_prioridade(Programa(nome, "12.0"), [])
        assert p.escore == 0, (nome, p.motivos)


def test_alvo_de_verdade_continua_casando():
    for nome, rotulo in (("Redis on Windows", "banco"), ("PostgreSQL 17", "banco"),
                         ("Google Chrome", "navegador"), ("7-Zip 24.08", "compactador"),
                         ("Docker Desktop", "virtualização")):
        p = pontuar_prioridade(Programa(nome, "1.0"), [])
        assert p.escore > 0 and rotulo in p.motivos[0], nome


def test_navegador_entra_na_fila():
    p = pontuar_prioridade(Programa("Google Chrome", "130.0.1"), [])
    assert p.escore == 30 and "navegador" in p.motivos[0]


def test_software_que_escuta_para_fora_sobe_na_fila():
    escutas = [Escuta(porta=5432, endereco="0.0.0.0", processo="postgres.exe", pid=10)]
    com = pontuar_prioridade(Programa("PostgreSQL 16", "16.4"), escutas)
    sem = pontuar_prioridade(Programa("PostgreSQL 16", "16.4"), [])
    assert com.escore > sem.escore
    assert com.exposto and com.portas == [5432]


def test_escuta_so_local_pesa_menos_que_exposta():
    local = [Escuta(porta=5432, endereco="127.0.0.1", processo="postgres.exe")]
    fora = [Escuta(porta=5432, endereco="0.0.0.0", processo="postgres.exe")]
    assert (pontuar_prioridade(Programa("PostgreSQL", "16.4"), local).escore <
            pontuar_prioridade(Programa("PostgreSQL", "16.4"), fora).escore)


def test_exposta_distingue_loopback():
    assert Escuta(porta=1, endereco="0.0.0.0", processo="x").exposta
    assert Escuta(porta=1, endereco="::", processo="x").exposta
    assert Escuta(porta=1, endereco="192.168.0.5", processo="x").exposta
    assert not Escuta(porta=1, endereco="127.0.0.1", processo="x").exposta
    assert not Escuta(porta=1, endereco="::1", processo="x").exposta


def test_casamento_programa_processo():
    assert _mesmo_software("Google Chrome", "chrome.exe")
    assert _mesmo_software("PostgreSQL 16", "postgres.exe")
    assert _mesmo_software("Redis on Windows", "redis-server.exe")
    assert not _mesmo_software("Google Chrome", "svchost.exe")
    assert not _mesmo_software("Git", "g.exe")          # nome curto não casa por acaso


def test_palavra_generica_nao_casa_nada():
    # o bug do teste de campo: services.exe (gerenciador de serviços do Windows)
    # casava com todo programa que tivesse "Service" no nome
    for nome in ("Live Wallpaper Service", "Samsung Update Service",
                 "Quick Search Service", "Online Support(S Service) Agent",
                 "Microsoft Update Health Tools"):
        assert forca_do_casamento(nome, "services.exe") == 0, nome


def test_casamento_mais_especifico_ganha():
    especifico = forca_do_casamento("Samsung Analytics Service", "SamsungAnalyticsService")
    generico = forca_do_casamento("Samsung Update Service", "SamsungAnalyticsService")
    assert especifico > generico > 0


def test_porta_tem_um_dono_so():
    inventario = [Programa("Samsung Analytics Service", "1.0"),
                  Programa("Samsung Update Service", "3.0"),
                  Programa("Live Wallpaper Service", "3.3")]
    escutas = [Escuta(porta=12754, endereco="127.0.0.1", processo="SamsungAnalyticsService"),
               Escuta(porta=49687, endereco="0.0.0.0", processo="services")]
    mapa = atribuir_escutas(inventario, escutas)
    assert mapa == {"Samsung Analytics Service": [escutas[0]]}   # services.exe não tem dono


def test_fila_nao_atribui_porta_alheia():
    inventario = [Programa("Live Wallpaper Service", "3.3"),
                  Programa("Samsung Update Service", "3.0")]
    escutas = [Escuta(porta=49687, endereco="0.0.0.0", processo="services")]
    fila = priorizar(inventario, escutas)
    assert fila == []            # nenhum dos dois é alvo frequente nem escuta de verdade


def test_redis_do_porte_antigo_e_alta():
    itens = avaliar_abandonado([Programa("Redis on Windows", "3.0.504")])
    assert itens[0].severidade is Severity.HIGH
    assert "2016" in itens[0].descricao


def test_redis_moderno_nao_e_acusado():
    assert avaliar_abandonado([Programa("Redis", "7.4.1")]) == []


def test_fila_ordenada_e_filtrada():
    inventario = [Programa("Bloco de Notas++", "8.6"), Programa("Google Chrome", "130.0"),
                  Programa("TeamViewer", "15.58")]
    escutas = [Escuta(porta=5938, endereco="0.0.0.0", processo="teamviewer.exe")]
    fila = priorizar(inventario, escutas)
    assert [p.programa.nome for p in fila] == ["TeamViewer", "Google Chrome"]
    assert fila[0].escore > fila[1].escore


def test_termo_de_busca_limpa_o_nome():
    assert _termo_de_busca("Google Chrome (versão 130)") == "google chrome"
    assert _termo_de_busca("Python 3.14.0 (64-bit)") == "python"
    assert _termo_de_busca("Microsoft Visual Studio Code") == "microsoft visual studio"


def test_termo_de_busca_tira_palavra_de_embalagem():
    # era o furo do teste de campo: "redis on windows" nao casa com CPE nenhum
    assert _termo_de_busca("Redis on Windows") == "redis"
    assert _termo_de_busca("Opera GX Stable 136.0.6008.76") == "opera gx"
    assert _termo_de_busca("7-Zip 24.08 (x64 edition)") == "7-zip"


# ---- NVD ----
def test_produto_no_cpe():
    cpe = "cpe:2.3:a:google:chrome:130.0.1:*:*:*:*:*:*:*"
    assert _produto_no_cpe("google chrome", cpe)
    assert not _produto_no_cpe("mozilla firefox", cpe)
    # sublinhado do CPE vira palavra separada
    assert _produto_no_cpe("visual studio code",
                           "cpe:2.3:a:microsoft:visual_studio_code:1.0:*:*:*:*:*:*:*")


def test_produto_de_uma_palavra_pode_casar_pelo_fabricante():
    assert _produto_no_cpe("redis", "cpe:2.3:a:redis:redis:3.0.504:*:*:*:*:*:*:*")
    assert _produto_no_cpe("opera", "cpe:2.3:a:opera:opera_browser:*:*:*:*:*:*:*:*")


def test_fabricante_sozinho_nao_basta_com_dois_nomes():
    # senao "microsoft edge" casaria com qualquer CPE da Microsoft
    office = "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*"
    assert not _produto_no_cpe("microsoft edge", office)
    assert _produto_no_cpe("microsoft edge", "cpe:2.3:a:microsoft:edge:154.0:*:*:*:*:*:*:*")


def test_driver_e_pacote_nao_sao_o_produto():
    # os dois falsos positivos que o teste de campo entregou: o PostgreSQL 17
    # casando com CVE do driver JDBC (42.x) e do pacote Debian common (210)
    assert not _produto_no_cpe(
        "postgresql", "cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.2.4:*:*:*:*:*:*:*")
    assert not _produto_no_cpe(
        "postgresql", "cpe:2.3:a:postgresql:postgresql-common:209:*:*:*:*:*:*:*")
    assert not _produto_no_cpe(
        "redis", "cpe:2.3:a:redis:redis_client_library:1.0:*:*:*:*:*:*:*")
    # o produto de verdade continua casando
    assert _produto_no_cpe("postgresql", "cpe:2.3:a:postgresql:postgresql:17.11:*:*:*:*:*:*:*")


def test_qualificador_no_proprio_nome_buscado_nao_atrapalha():
    # quem procura o driver tem direito de achar o driver
    assert _produto_no_cpe(
        "postgresql jdbc driver",
        "cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.2.4:*:*:*:*:*:*:*")


def test_cpe_malformado_nao_quebra():
    assert not _produto_no_cpe("redis", "cpe:2.3:a")
    assert not _produto_no_cpe("", "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*")


def _resposta_nvd(fim_excl="6.23", inicio_incl="", cvss=9.8, produto="rarlab:winrar"):
    return {"vulnerabilities": [{"cve": {
        "id": "CVE-2023-38831",
        "descriptions": [{"lang": "en", "value": "RARLAB WinRAR permite executar codigo."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss,
                                                    "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:{produto}:*:*:*:*:*:*:*:*",
            "versionStartIncluding": inicio_incl,
            "versionEndExcluding": fim_excl,
        }]}]}],
    }}]}


def test_cve_casa_quando_versao_cai_na_faixa():
    casados = cves_que_casam(_resposta_nvd(), "6.20", "rarlab winrar")
    assert len(casados) == 1
    assert casados[0].id == "CVE-2023-38831" and casados[0].cvss == 9.8
    assert "fim_excl=6.23" in casados[0].faixa


def test_cve_nao_casa_quando_versao_esta_corrigida():
    assert cves_que_casam(_resposta_nvd(), "7.01", "rarlab winrar") == []


def test_cve_de_outro_produto_e_descartada():
    resposta = _resposta_nvd(produto="mozilla:firefox")
    assert cves_que_casam(resposta, "6.20", "rarlab winrar") == []


def test_cve_sem_faixa_declarada_e_descartada():
    # "todas as versões" não prioriza nada; seria o ruído que o módulo evita
    resposta = _resposta_nvd(fim_excl="", inicio_incl="")
    assert cves_que_casam(resposta, "6.20", "rarlab winrar") == []


def test_resposta_vazia_nao_quebra():
    assert cves_que_casam({}, "1.0", "qualquer") == []
    assert cves_que_casam({"vulnerabilities": []}, "1.0", "qualquer") == []


def test_cves_vem_da_mais_grave_para_a_menos():
    resposta = _resposta_nvd()
    leve = _resposta_nvd(cvss=4.2)["vulnerabilities"][0]
    leve["cve"]["id"] = "CVE-2024-00001"
    resposta["vulnerabilities"].append(leve)
    casados = cves_que_casam(resposta, "6.20", "rarlab winrar")
    assert [c.cvss for c in casados] == [9.8, 4.2]


def test_severidade_de_cvss():
    assert severidade_de_cvss(9.8) is Severity.CRITICAL
    assert severidade_de_cvss(7.5) is Severity.HIGH
    assert severidade_de_cvss(5.0) is Severity.MEDIUM
    assert severidade_de_cvss(2.1) is Severity.LOW
