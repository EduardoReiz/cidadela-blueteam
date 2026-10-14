"""Testes da postura web — todas as réguas são puras, não tocam a rede."""

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.postura_web import (
    PosturaWeb,
    avaliar_cabecalhos,
    avaliar_caminhos,
    avaliar_cloudflare,
    avaliar_divulgacao,
    avaliar_listagem,
    avaliar_portas,
    avaliar_redirecionamento,
    avaliar_tls,
)


def _titulos(itens):
    return [i.titulo for i in itens]


# ---- redirecionamento ----
def test_redireciona_para_https_nao_gera():
    assert avaliar_redirecionamento(True) == []


def test_sem_redirecionar_e_media():
    itens = avaliar_redirecionamento(False)
    assert itens[0].severidade is Severity.MEDIUM


def test_redirecionamento_desconhecido_fica_calado():
    assert avaliar_redirecionamento(None) == []


# ---- TLS ----
def test_tls_moderno_e_valido_nao_gera():
    assert avaliar_tls({"versao": "TLSv1.3", "dias_para_expirar": 60}) == []
    assert avaliar_tls({"versao": "TLSv1.2", "dias_para_expirar": 200}) == []


def test_tls_obsoleto_e_alta():
    itens = avaliar_tls({"versao": "TLSv1", "dias_para_expirar": 100})
    assert any(i.severidade is Severity.HIGH and "obsoleto" in i.titulo for i in itens)


def test_certificado_vencido_e_alta():
    itens = avaliar_tls({"versao": "TLSv1.3", "dias_para_expirar": -3})
    assert any(i.severidade is Severity.HIGH and "vencido" in i.titulo for i in itens)


def test_certificado_perto_de_vencer_e_media():
    itens = avaliar_tls({"versao": "TLSv1.3", "dias_para_expirar": 7})
    assert any(i.severidade is Severity.MEDIUM for i in itens)


def test_tls_sem_dados_e_info():
    itens = avaliar_tls({})
    assert len(itens) == 1 and itens[0].severidade is Severity.INFO


# ---- cabeçalhos ----
def _headers_completos():
    return {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff", "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin"}


def test_todos_os_cabecalhos_presentes_nao_gera():
    assert avaliar_cabecalhos(_headers_completos()) == []


def test_sem_hsts_e_sem_csp_geram_media():
    itens = avaliar_cabecalhos({})
    sev = {i.recurso: i.severidade for i in itens}
    assert sev["strict-transport-security"] is Severity.MEDIUM
    assert sev["content-security-policy"] is Severity.MEDIUM


def test_csp_com_frame_ancestors_dispensa_x_frame_options():
    headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
    titulos = _titulos(avaliar_cabecalhos(headers))
    assert "Cabeçalho de segurança ausente: x-frame-options" not in titulos


# ---- divulgação de versão ----
def test_server_com_versao_e_baixa():
    itens = avaliar_divulgacao({"server": "Apache/2.4.41 (Ubuntu)"})
    assert itens and itens[0].severidade is Severity.LOW


def test_cloudflare_sem_versao_nao_e_vazamento():
    assert avaliar_divulgacao({"server": "cloudflare"}) == []


def test_x_powered_by_vaza():
    assert any("x-powered-by" in i.recurso
               for i in avaliar_divulgacao({"x-powered-by": "PHP/8.1.2"}))


# ---- caminhos sensíveis ----
def test_nenhum_caminho_exposto_nao_gera():
    resultados = {"/.env": 404, "/.git/config": 403, "/backup.zip": 404}
    assert avaliar_caminhos(resultados) == []


def test_env_exposto_e_critico():
    itens = avaliar_caminhos({"/.env": 200})
    assert itens[0].severidade is Severity.CRITICAL
    assert "ROTACIONE" in itens[0].recomendacao


def test_caminho_nao_critico_exposto_e_alta():
    itens = avaliar_caminhos({"/phpinfo.php": 200})
    assert itens[0].severidade is Severity.HIGH


def test_status_206_tambem_conta_como_exposto():
    assert avaliar_caminhos({"/dump.sql": 206})[0].severidade is Severity.CRITICAL


# ---- listagem ----
def test_listagem():
    assert avaliar_listagem(False) == []
    assert avaliar_listagem(True)[0].severidade is Severity.MEDIUM


# ---- portas ----
def test_porta_443_sozinha_nao_preocupa():
    assert avaliar_portas([443]) == []       # 443 não está na lista de risco


def test_banco_exposto_e_alta():
    for porta in (3306, 5432, 6379, 27017):
        itens = avaliar_portas([porta])
        assert itens[0].severidade is Severity.HIGH, porta


def test_rdp_e_telnet_sao_alta():
    assert avaliar_portas([3389])[0].severidade is Severity.HIGH
    assert avaliar_portas([23])[0].severidade is Severity.HIGH


def test_ssh_exposto_e_baixa():
    assert avaliar_portas([22])[0].severidade is Severity.LOW


def test_portas_duplicadas_viram_um_achado():
    assert len(avaliar_portas([6379, 6379, 6379])) == 1


# ---- Cloudflare / origem exposta ----
def test_origem_exposta_e_alta():
    itens = avaliar_cloudflare(True, origem_exposta=True)
    assert itens[0].severidade is Severity.HIGH
    assert "porta dos fundos" in itens[0].descricao


def test_origem_nao_verificada_e_info():
    itens = avaliar_cloudflare(True, origem_exposta=None)
    assert itens[0].severidade is Severity.INFO


def test_origem_travada_nao_gera():
    assert avaliar_cloudflare(True, origem_exposta=False) == []


def test_sem_cloudflare_quando_era_esperado_e_info():
    itens = avaliar_cloudflare(False, origem_exposta=None)
    assert itens[0].severidade is Severity.INFO and "não detectado" in itens[0].titulo


# ---- detecção de Cloudflare ----
def test_deteccao_de_cloudflare_por_cabecalho():
    detectar = PosturaWeb._e_cloudflare
    assert detectar({"server": "cloudflare"})
    assert detectar({"cf-ray": "abc123"})
    assert detectar({"cf-cache-status": "HIT"})
    assert not detectar({"server": "nginx"})
