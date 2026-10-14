"""Testes do caçador de segredo exposto.

Igual aos outros detectores, o que importa é pegar o segredo de verdade SEM
acusar o que é legítimo. Daí os dois blocos: COM_SEGREDO e SEM_SEGREDO (linhas de
código comum: import, hash, placeholder, UUID, config de exemplo). E uma regra
inegociável: o segredo nunca sai inteiro no achado.
"""

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.segredo_exposto import (
    classificar_nome,
    deve_ignorar,
    e_placeholder,
    escanear_texto,
    mascarar,
)

_AWS = "AKIA" + "IOSFODNN7EXAMPL0"               # AKIA + 16 chars = 20
_GH = "ghp_" + ("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")   # ghp_ + 36
_GOOGLE = "AIza" + ("0123456789" * 4)[:35]       # AIza + 35
_SLACK = "xoxb" + "-123456789012-abcdefghijklmnop"
_TG = "1234567890" + ":AAFakeFakeFakeFakeFakeFakeFakeFakeFa"

COM_SEGREDO = [
    "-----BEGIN RSA PRIVATE KEY-----",
    f"aws_key = '{_AWS}'",
    f"const gh = '{_GH}'",
    f"GOOGLE = '{_GOOGLE}'",
    f"slack_hook = '{_SLACK}'",
    f"TELEGRAM = '{_TG}'",
    "db = 'postgres://admin:s3nh4Sup3rF0rte@db.interno:5432/app'",
    "SENHA_DO_BANCO = 'Xk9#mQ2vLp8zWn4T'",
]

SEM_SEGREDO = [
    "import os",
    "api_key = os.environ['API_KEY']",                       # vem do ambiente
    "API_KEY = 'your_api_key_here'",                         # placeholder
    "SECRET = 'changeme'",
    "password = '${DB_PASSWORD}'",                           # template
    "token = '<seu-token-aqui>'",
    "senha = 'xxxxxxxxxxxx'",                                # repetição
    "sha = 'd41d8cd98f00b204e9800998ecf8427e'",              # hash md5, sem contexto de segredo
    "id = '550e8400-e29b-41d4-a716-446655440000'",           # uuid
    "# exemplo: SECRET=coloque_sua_chave",
    "versao = '1.2.3-beta.4567890'",
    "url = 'https://cidadela.dev.br/sobre'",
]


def test_todo_segredo_e_pego():
    falhas = [linha[:50] for linha in COM_SEGREDO if not escanear_texto(linha)]
    assert not falhas, f"passaram sem achado: {falhas}"


def test_nada_legitimo_e_acusado():
    falhas = [(linha[:50], [a.regra for a in escanear_texto(linha)])
              for linha in SEM_SEGREDO if escanear_texto(linha)]
    assert not falhas, f"falso positivo: {falhas}"


# ---- mascaramento (a regra inegociável) ----
def test_segredo_nunca_sai_inteiro():
    segredo = "AKIA" + "IOSFODNN7EXAMPL0"      # 20 chars
    achados = escanear_texto(f"k = '{segredo}'")
    assert achados
    for a in achados:
        assert segredo not in a.trecho
        assert a.trecho.startswith("AKIA") and a.trecho.endswith("[20]")


def test_mascarar_curto_e_longo():
    assert mascarar("abc") == "•••[3]"
    assert mascarar("ghp_abcdefghij") == "ghp_…ij[14]"


# ---- severidade ----
def test_chave_privada_e_critica():
    assert escanear_texto("-----BEGIN PRIVATE KEY-----")[0].severidade is Severity.CRITICAL


def test_atribuicao_generica_e_media():
    a = escanear_texto("SENHA_DO_BANCO = 'Xk9#mQ2vLp8zWn4T'")
    assert a and a[0].severidade is Severity.MEDIUM


def test_url_com_credencial_e_alta():
    a = escanear_texto("db = 'mysql://root:P@ssw0rdForte1@host/db'")
    assert any(x.regra == "url-com-credencial" and x.severidade is Severity.HIGH for x in a)


# ---- placeholders ----
def test_placeholders_sao_ignorados():
    for v in ("your_key_here", "CHANGEME", "${VAR}", "<token>", "xxxxxxxx",
              "exemplo123exemplo", "coloque_aqui"):
        assert e_placeholder(v), v


def test_valor_real_nao_e_placeholder():
    for v in ("Xk9#mQ2vLp8zWn4T", "s3nh4Sup3rF0rte", "Tr0ub4dor&3xtr4"):
        assert not e_placeholder(v), v


# ---- não duplicar ----
def test_regra_forte_e_atribuicao_na_mesma_linha_nao_duplicam():
    # a telegram-bot e a atribuicao-sensivel pegam o mesmo valor; deve sair 1
    achados = escanear_texto("TOKEN = '1234567890:AAFakeFakeFakeFakeFakeFakeFakeFakeFa'")
    regras = [a.regra for a in achados]
    assert regras.count("atribuicao-sensivel") == 0
    assert "telegram-bot" in regras


def test_linha_minificada_e_pulada():
    gigante = "var x='" + "A1b2" * 2000 + "';"
    assert escanear_texto(gigante) == []


# ---- nome de arquivo ----
def test_classificar_nome():
    assert classificar_nome("deploy/id_rsa")[0] is Severity.CRITICAL
    assert classificar_nome("certs/server.pem")[0] is Severity.HIGH
    assert classificar_nome(".env")[0] is Severity.HIGH
    assert classificar_nome("backend/.env.production")[0] is Severity.HIGH
    assert classificar_nome("src/main.py") is None
    assert classificar_nome("README.md") is None


# ---- pastas/arquivos ignorados ----
def test_deve_ignorar():
    assert deve_ignorar("node_modules/pkg/index.js")
    assert deve_ignorar("projeto/.git/config")
    assert deve_ignorar("static/logo.png")
    assert deve_ignorar("app.min.js")
    assert not deve_ignorar("src/config.py")
    assert not deve_ignorar("backend/settings.py")


# ---- linha e multiplos ----
def test_linha_e_reportada():
    texto = "linha 1\nlinha 2\n" + "AKIA" + "IOSFODNN7EXAMPL0" + "\n"
    a = escanear_texto(texto)
    assert a and a[0].linha == 3


def test_varios_segredos_em_arquivo():
    texto = "\n".join(COM_SEGREDO)
    achados = escanear_texto(texto)
    regras = {a.regra for a in achados}
    assert {"chave-privada", "aws-access-key", "github-token",
            "google-api-key", "slack-token", "telegram-bot"} <= regras
