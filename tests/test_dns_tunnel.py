"""Testes da detecção de tunelamento DNS (funções puras)."""

import hashlib

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.dns_tunnel_detect import (
    entropia, dominio_registravel, avaliar_dominio,
)


def test_entropia():
    assert entropia("") == 0.0
    assert entropia("aaaa") == 0.0            # sem variação
    assert entropia("ab") == 1.0              # 2 símbolos equiprováveis
    assert entropia("abcd") == 2.0


def test_dominio_registravel():
    assert dominio_registravel("www.google.com") == "google.com"
    assert dominio_registravel("a.b.c.evil.com") == "evil.com"
    assert dominio_registravel("sub.cidadela.dev.br") == "cidadela.dev.br"  # sufixo composto
    assert dominio_registravel("localhost") == "localhost"


def test_trafego_normal_nao_dispara():
    nomes = ["www.google.com", "mail.google.com", "drive.google.com",
             "accounts.google.com", "apis.google.com", "fonts.google.com",
             "ssl.google.com", "play.google.com", "maps.google.com"]
    sev, motivos, _ = avaliar_dominio("google.com", nomes)
    assert motivos == []
    assert sev is Severity.INFO


def test_padrao_de_tunel_dispara_alta():
    # 50 subdomínios distintos, longos e de alta aleatoriedade sob evil.com
    nomes = []
    for i in range(50):
        h = hashlib.sha256(str(i).encode()).hexdigest()  # 64 chars hex, alta entropia
        nomes.append(f"{h}.evil.com")
    sev, motivos, stats = avaliar_dominio("evil.com", nomes)
    assert sev is Severity.HIGH
    assert len(motivos) >= 2                       # vários indícios juntos
    assert stats["subdominios_distintos"] == 50
    assert stats["maior_rotulo"] >= 60
    assert stats["entropia_media"] > 3.6
