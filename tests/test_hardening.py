"""Testes da baseline de hardening (todas as avaliações são puras)."""

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.hardening_audit import (
    CHECAGENS,
    DNS_CLIENT,
    LSA,
    POLITICAS,
    WDIGEST,
    avaliar_criptografia,
    avaliar_defender,
    avaliar_firewall,
    avaliar_netbios,
    avaliar_rdp,
    avaliar_registro,
    avaliar_secure_boot,
    avaliar_servicos,
    avaliar_smb,
    normalizar_exclusoes,
)


def _titulos(itens):
    return [i.titulo for i in itens]


def _baseline_conforme():
    """Monta um registro que satisfaz toda a tabela — não deve sobrar achado."""
    lidos = {}
    for c in CHECAGENS:
        lidos[(c.chave, c.valor)] = c.esperado
    return lidos


# ---- tabela de registro ----
def test_host_conforme_nao_gera_achado():
    assert avaliar_registro(_baseline_conforme()) == []


def test_valor_ausente_seguro_por_padrao_e_ignorado():
    # dict vazio: só devem aparecer as checagens com ausente_ok=False
    titulos = _titulos(avaliar_registro({}))
    assert "UAC desativado" not in titulos          # ausente => padrão seguro
    assert "LLMNR ativo" in titulos                 # ausente => não endurecido
    assert "LSA Protection desativada" in titulos


def test_uac_desligado_e_alta():
    itens = avaliar_registro({(POLITICAS, "EnableLUA"): 0})
    uac = [i for i in itens if i.titulo == "UAC desativado"]
    assert uac and uac[0].severidade is Severity.HIGH
    assert "EnableLUA=0" in uac[0].descricao


def test_wdigest_texto_claro_e_alta():
    itens = avaliar_registro({(WDIGEST, "UseLogonCredential"): 1})
    achado = [i for i in itens if "WDigest" in i.titulo]
    assert achado and achado[0].severidade is Severity.HIGH
    assert "T1003.001" in achado[0].referencia


def test_modo_minimo_aceita_valor_acima():
    base = _baseline_conforme()
    base[(LSA, "LmCompatibilityLevel")] = 5
    assert "Autenticação NTLM legada aceita" not in _titulos(avaliar_registro(base))
    base[(LSA, "LmCompatibilityLevel")] = 3
    assert "Autenticação NTLM legada aceita" in _titulos(avaliar_registro(base))


def test_llmnr_desativado_nao_gera():
    itens = avaliar_registro({(DNS_CLIENT, "EnableMulticast"): 0})
    assert "LLMNR ativo" not in _titulos(itens)


def test_recurso_aponta_o_caminho_do_registro():
    itens = avaliar_registro({(POLITICAS, "EnableLUA"): 0})
    assert itens[0].recurso.startswith("HKLM\\SOFTWARE\\Microsoft")


# ---- RDP ----
def test_rdp_desligado_nao_gera():
    assert avaliar_rdp(1, None) == []
    assert avaliar_rdp(None, None) == []


def test_rdp_ligado_sem_nla_e_alta():
    itens = avaliar_rdp(0, 0)
    assert any(i.severidade is Severity.HIGH and "NLA" in i.titulo for i in itens)


def test_rdp_ligado_com_nla_so_informa():
    itens = avaliar_rdp(0, 1)
    assert len(itens) == 1 and itens[0].severidade is Severity.INFO


# ---- NetBIOS ----
def test_netbios_desativado_em_todas_nao_gera():
    assert avaliar_netbios({"Tcpip_{a}": 2, "Tcpip_{b}": 2}) == []


def test_netbios_ativo_lista_interfaces():
    itens = avaliar_netbios({"Tcpip_{a}": 0, "Tcpip_{b}": 2})
    assert itens and itens[0].evidencia["interfaces"] == ["Tcpip_{a}"]


# ---- firewall ----
def test_firewall_todos_ativos_nao_gera():
    perfis = [{"Name": n, "Enabled": True, "DefaultInboundAction": "Block"}
              for n in ("Domain", "Private", "Public")]
    assert avaliar_firewall(perfis) == []


def test_firewall_perfil_desligado_e_alta():
    perfis = [{"Name": "Public", "Enabled": False, "DefaultInboundAction": "Block"}]
    itens = avaliar_firewall(perfis)
    assert itens[0].severidade is Severity.HIGH and "Public" in itens[0].titulo


def test_firewall_entrada_liberada_e_alta():
    perfis = [{"Name": "Private", "Enabled": True, "DefaultInboundAction": "Allow"}]
    assert any("Entrada liberada" in i.titulo for i in avaliar_firewall(perfis))


def test_firewall_notconfigured_herda_bloqueio():
    perfis = [{"Name": "Domain", "Enabled": True, "DefaultInboundAction": "NotConfigured"}]
    assert avaliar_firewall(perfis) == []


def test_firewall_sem_dados_informa():
    itens = avaliar_firewall([])
    assert itens[0].severidade is Severity.INFO


# ---- Defender ----
def _defender_ok():
    status = {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
              "BehaviorMonitorEnabled": True, "IsTamperProtected": True,
              "AntivirusSignatureAge": 0, "AMRunningMode": "Normal"}
    prefs = {"PUAProtection": 1, "MAPSReporting": 2, "DisableScriptScanning": False,
             "ExclusionPath": []}
    return status, prefs


def test_defender_saudavel_nao_gera():
    assert avaliar_defender(*_defender_ok()) == []


def test_tempo_real_desligado_e_critico():
    status, prefs = _defender_ok()
    status["RealTimeProtectionEnabled"] = False
    itens = avaliar_defender(status, prefs)
    assert any(i.severidade is Severity.CRITICAL for i in itens)


def test_modo_passivo_nao_vira_critico():
    status, prefs = _defender_ok()
    status.update({"AMRunningMode": "Passive Mode", "AntivirusEnabled": False,
                   "RealTimeProtectionEnabled": False})
    itens = avaliar_defender(status, prefs)
    assert all(i.severidade is Severity.INFO for i in itens)


def test_assinatura_velha_e_media():
    status, prefs = _defender_ok()
    status["AntivirusSignatureAge"] = 30
    assert any("desatualizadas" in i.titulo and i.severidade is Severity.MEDIUM
               for i in avaliar_defender(status, prefs))


def test_exclusoes_entram_como_evidencia():
    status, prefs = _defender_ok()
    prefs["ExclusionPath"] = [r"C:\temp", r"D:\jogos"]
    itens = [i for i in avaliar_defender(status, prefs) if "Exclusões" in i.titulo]
    assert itens and itens[0].evidencia["caminhos"] == [r"C:\temp", r"D:\jogos"]


def test_recado_de_falta_de_admin_nao_vira_exclusao():
    # sem elevação o Get-MpPreference devolve um recado, não uma lista
    recado = "N/A: Must be an administrator to view exclusions"
    assert normalizar_exclusoes(recado) == ([], False)
    assert normalizar_exclusoes([recado]) == ([], False)

    status, prefs = _defender_ok()
    prefs["ExclusionPath"] = recado
    itens = avaliar_defender(status, prefs)
    assert len(itens) == 1
    assert itens[0].severidade is Severity.INFO
    assert "listar as exclusões" in itens[0].titulo


def test_exclusao_unica_em_string_ainda_conta():
    # o JSON do PowerShell desembrulha lista de um item em string
    assert normalizar_exclusoes(r"C:\dev") == ([r"C:\dev"], True)
    assert normalizar_exclusoes(None) == ([], True)
    assert normalizar_exclusoes([]) == ([], True)


def test_defender_sem_dados_informa():
    itens = avaliar_defender({}, {})
    assert len(itens) == 1 and itens[0].severidade is Severity.INFO


# ---- criptografia / Secure Boot / SMB / serviços ----
def test_disco_do_sistema_sem_cripto_e_alta():
    volumes = [{"MountPoint": "C:", "ProtectionStatus": "Off",
                "VolumeStatus": "FullyDecrypted", "VolumeType": "OperatingSystem"}]
    itens = avaliar_criptografia(volumes)
    assert itens[0].severidade is Severity.HIGH


def test_volume_de_dados_sem_cripto_e_baixa():
    volumes = [{"MountPoint": "D:", "ProtectionStatus": "Off",
                "VolumeStatus": "FullyDecrypted", "VolumeType": "Data"}]
    assert avaliar_criptografia(volumes)[0].severidade is Severity.LOW


def test_disco_protegido_nao_gera():
    volumes = [{"MountPoint": "C:", "ProtectionStatus": "On",
                "VolumeStatus": "FullyEncrypted", "VolumeType": "OperatingSystem"}]
    assert avaliar_criptografia(volumes) == []


def test_sem_volumes_informa_em_vez_de_aprovar():
    itens = avaliar_criptografia([])
    assert len(itens) == 1 and itens[0].severidade is Severity.INFO


def test_secure_boot():
    assert avaliar_secure_boot(True) == []
    assert avaliar_secure_boot(False)[0].severidade is Severity.MEDIUM
    assert avaliar_secure_boot(None)[0].severidade is Severity.INFO


def test_smb1_ativo_e_alta():
    servidor = {"EnableSMB1Protocol": True, "RequireSecuritySignature": True}
    cliente = {"RequireSecuritySignature": True}
    itens = avaliar_smb(servidor, cliente)
    assert len(itens) == 1 and itens[0].severidade is Severity.HIGH


def test_smb_saudavel_nao_gera():
    servidor = {"EnableSMB1Protocol": False, "RequireSecuritySignature": True}
    assert avaliar_smb(servidor, {"RequireSecuritySignature": True}) == []


def test_assinatura_relatada_uma_vez_por_lado():
    servidor = {"EnableSMB1Protocol": False, "RequireSecuritySignature": False}
    cliente = {"RequireSecuritySignature": False}
    titulos = _titulos(avaliar_smb(servidor, cliente))
    assert titulos == ["Servidor SMB não exige assinatura", "Cliente SMB não exige assinatura"]


def test_registro_e_so_reserva_para_smb1():
    # com cmdlet respondendo, o registro não é consultado (não duplica achado)
    servidor = {"EnableSMB1Protocol": False, "RequireSecuritySignature": True}
    assert avaliar_smb(servidor, {"RequireSecuritySignature": True}, smb1_registro=1) == []
    # sem cmdlet, o registro assume
    itens = avaliar_smb({}, {}, smb1_registro=1)
    assert any(i.titulo == "SMBv1 habilitado" for i in itens)
    assert any(i.severidade is Severity.INFO for i in itens)


def test_servico_parado_nao_gera():
    servicos = {"RemoteRegistry": {"Status": "Stopped", "StartType": "Disabled"}}
    assert avaliar_servicos(servicos) == []


def test_remote_registry_rodando_e_media():
    servicos = {"RemoteRegistry": {"Status": "Running", "StartType": "Automatic"}}
    itens = avaliar_servicos(servicos)
    assert itens[0].severidade is Severity.MEDIUM and "RemoteRegistry" in itens[0].titulo
