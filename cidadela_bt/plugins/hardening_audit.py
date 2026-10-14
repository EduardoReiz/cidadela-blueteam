"""Auditor de endurecimento (hardening) do Windows — baseline CIS.

Este é o módulo "clássico" do blue team: não procura invasor nem ataque em
andamento, e sim as portas abertas que todo ataque usa. Compara a configuração
real do host com uma baseline (CIS Windows Benchmark + recomendações da
Microsoft) e lista o que está fora dela.

O que é checado:
  - UAC e elevação (EnableLUA, prompt do admin, token do admin interno)
  - LSA / credenciais (LSA Protection, WDigest em texto claro, NTLM legado)
  - SMB (SMBv1, assinatura de SMB)
  - RDP (habilitado sem NLA)
  - LLMNR e NetBIOS (vetores de envenenamento/relay — T1557.001)
  - AutoRun de mídia removível
  - Telemetria de PowerShell (script block logging, transcrição) e linha de
    comando no log de criação de processo — sem isso a detecção fica cega
  - Firewall (perfis ativos e ação padrão de entrada)
  - Defender (tempo real, comportamento, tamper, PUA, exclusões)
  - Criptografia de disco e Secure Boot
  - Serviços de risco desnecessários (Remote Registry, Spooler, WinRM, UPnP)

Tudo SÓ LEITURA: registro via winreg e cmdlets de consulta via PowerShell.
Algumas checagens (criptografia, Secure Boot) só respondem em prompt elevado;
quando não dá para ler, o módulo diz isso em vez de calar — "não verificado"
nunca é tratado como "conforme".

A avaliação é separada da coleta: cada `avaliar_*` é função pura, então dá para
testar a baseline inteira sem depender da máquina.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..plugin import Contexto, Finding, Plugin, Severity

try:
    import winreg
except ImportError:  # fora do Windows o plugin nem é aplicável
    winreg = None  # type: ignore[assignment]

CIS = "CIS Windows Benchmark"

# ---- caminhos de registro usados (todos sob HKLM) ----
POLITICAS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
WDIGEST = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
LANMAN_SERVER = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
TERMINAL_SERVER = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
DNS_CLIENT = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
EXPLORER = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
PS_SCRIPTBLOCK = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
PS_TRANSCRICAO = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
AUDIT_POLITICAS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
INSTALLER = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
NETBT_INTERFACES = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"


@dataclass(frozen=True)
class Item:
    """Um desvio de baseline, antes de virar Finding."""

    severidade: Severity
    titulo: str
    descricao: str
    recomendacao: str
    recurso: str = ""
    referencia: str = CIS
    evidencia: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Checagem:
    """Uma linha da baseline que mora no registro.

    `modo` é "igual" (valor exato) ou "minimo" (valor >= esperado).
    `ausente_ok` diz o que fazer quando o valor nem existe: True quando o
    padrão do Windows já é seguro, False quando ausente = não endurecido.
    """

    chave: str
    valor: str
    esperado: int
    modo: str
    severidade: Severity
    titulo: str
    descricao: str              # pode usar {atual}
    recomendacao: str
    ausente_ok: bool = True
    referencia: str = CIS


CHECAGENS: tuple[Checagem, ...] = (
    Checagem(POLITICAS, "EnableLUA", 1, "igual", Severity.HIGH,
             "UAC desativado",
             "O Controle de Conta de Usuário está desligado (EnableLUA={atual}); "
             "todo processo de admin roda elevado sem pedir nada.",
             "Reative o UAC (EnableLUA=1) e reinicie."),
    Checagem(POLITICAS, "ConsentPromptBehaviorAdmin", 2, "minimo", Severity.MEDIUM,
             "UAC eleva sem confirmação",
             "O prompt de elevação do administrador está em {atual} (0 = eleva calado).",
             "Use pelo menos 2 (pedir consentimento); o recomendado é 5."),
    Checagem(POLITICAS, "FilterAdministratorToken", 1, "igual", Severity.LOW,
             "Administrador interno sem UAC",
             "A conta Administrador interna não passa pelo UAC (valor: {atual}).",
             "Defina FilterAdministratorToken=1.",
             ausente_ok=False),
    Checagem(POLITICAS, "LocalAccountTokenFilterPolicy", 0, "igual", Severity.HIGH,
             "UAC remoto desativado para contas locais",
             "LocalAccountTokenFilterPolicy={atual} entrega token completo a conta local "
             "em acesso remoto — é o atalho clássico de movimentação lateral.",
             "Volte para 0 (ou remova o valor).",
             referencia=CIS + " / MITRE T1078.003"),
    Checagem(INSTALLER, "AlwaysInstallElevated", 0, "igual", Severity.HIGH,
             "Instalador MSI sempre elevado",
             "AlwaysInstallElevated={atual}: qualquer usuário instala MSI como SYSTEM.",
             "Desative (0) nas políticas de máquina e de usuário.",
             referencia=CIS + " / MITRE T1548.002"),
    Checagem(LSA, "RunAsPPL", 1, "igual", Severity.MEDIUM,
             "LSA Protection desativada",
             "O LSASS roda sem proteção de processo (RunAsPPL={atual}), então ferramenta "
             "de dump de credencial consegue abri-lo.",
             "Ative a LSA Protection (RunAsPPL=1) e reinicie.",
             ausente_ok=False, referencia=CIS + " / MITRE T1003.001"),
    Checagem(WDIGEST, "UseLogonCredential", 0, "igual", Severity.HIGH,
             "WDigest guarda senha em texto claro",
             "UseLogonCredential={atual}: a senha do usuário fica recuperável na memória do LSASS.",
             "Zere o valor (UseLogonCredential=0) e reinicie.",
             referencia=CIS + " / MITRE T1003.001"),
    Checagem(LSA, "LimitBlankPasswordUse", 1, "igual", Severity.MEDIUM,
             "Senha em branco aceita remotamente",
             "LimitBlankPasswordUse={atual} permite usar conta sem senha fora do console.",
             "Defina 1."),
    Checagem(LSA, "LmCompatibilityLevel", 5, "minimo", Severity.MEDIUM,
             "Autenticação NTLM legada aceita",
             "LmCompatibilityLevel={atual}: o host ainda aceita LM/NTLMv1, que quebra fácil.",
             "Use 5 (só NTLMv2, recusa LM e NTLMv1); teste antes se houver equipamento antigo.",
             ausente_ok=False, referencia=CIS + " / MITRE T1557"),
    Checagem(LSA, "RestrictAnonymousSAM", 1, "igual", Severity.MEDIUM,
             "Enumeração anônima de contas permitida",
             "RestrictAnonymousSAM={atual}: sessão nula consegue listar as contas locais.",
             "Defina 1."),
    # severidade baixa de propósito: quem bloqueia a enumeração de contas é o
    # RestrictAnonymousSAM (acima, ligado por padrão); este fecha a lista de
    # compartilhamentos, que em estação isolada vale pouco.
    Checagem(LSA, "RestrictAnonymous", 1, "igual", Severity.LOW,
             "Enumeração anônima de compartilhamentos permitida",
             "RestrictAnonymous={atual} deixa sessão nula listar os compartilhamentos.",
             "Defina 1 se a máquina fica em rede compartilhada.",
             ausente_ok=False),
    Checagem(DNS_CLIENT, "EnableMulticast", 0, "igual", Severity.MEDIUM,
             "LLMNR ativo",
             "A resolução multicast (LLMNR) está ativa (valor: {atual}); é o que ferramenta de "
             "envenenamento usa para capturar hash na rede local.",
             "Desative o LLMNR (EnableMulticast=0) por política.",
             ausente_ok=False, referencia=CIS + " / MITRE T1557.001"),
    Checagem(EXPLORER, "NoDriveTypeAutoRun", 255, "igual", Severity.MEDIUM,
             "AutoRun de mídia não bloqueado",
             "NoDriveTypeAutoRun={atual}: pendrive ainda pode disparar execução automática.",
             "Defina 255 (0xFF) para bloquear AutoRun em todo tipo de unidade.",
             ausente_ok=False, referencia=CIS + " / MITRE T1091"),
    Checagem(PS_SCRIPTBLOCK, "EnableScriptBlockLogging", 1, "igual", Severity.MEDIUM,
             "Script block logging do PowerShell desligado",
             "O PowerShell não registra os blocos executados (valor: {atual}); script ofuscado "
             "passa sem deixar rastro no log.",
             "Ative o Script Block Logging por política.",
             ausente_ok=False, referencia=CIS + " / MITRE T1059.001"),
    Checagem(PS_TRANSCRICAO, "EnableTranscripting", 1, "igual", Severity.LOW,
             "Transcrição do PowerShell desligada",
             "Não há transcrição das sessões de PowerShell (valor: {atual}).",
             "Ative a transcrição e aponte para uma pasta protegida.",
             ausente_ok=False),
    Checagem(AUDIT_POLITICAS, "ProcessCreationIncludeCmdLine_Enabled", 1, "igual", Severity.LOW,
             "Linha de comando ausente no log de processos",
             "O evento de criação de processo não grava a linha de comando (valor: {atual}).",
             "Ative 'Incluir linha de comando nos eventos de criação de processo'.",
             ausente_ok=False, referencia=CIS + " / MITRE T1059"),
)

# valores lidos fora da tabela (têm lógica condicional própria)
EXTRAS = ((TERMINAL_SERVER, "fDenyTSConnections"), (RDP_TCP, "UserAuthentication"),
          (LANMAN_SERVER, "SMB1"))


def avaliar_registro(lidos: dict[tuple[str, str], Any],
                     checagens: tuple[Checagem, ...] = CHECAGENS) -> list[Item]:
    """Compara os valores lidos com a baseline. Função pura/testável.

    Chave ausente em `lidos` significa "valor não existe no registro".
    """
    itens: list[Item] = []
    for c in checagens:
        presente = (c.chave, c.valor) in lidos
        atual = lidos.get((c.chave, c.valor))

        if not presente:
            if c.ausente_ok:
                continue
            conforme = False
        elif c.modo == "minimo":
            conforme = isinstance(atual, int) and atual >= c.esperado
        else:
            conforme = atual == c.esperado
        if conforme:
            continue

        texto = "não configurado" if not presente else str(atual)
        itens.append(Item(c.severidade, c.titulo, c.descricao.format(atual=texto),
                          c.recomendacao, recurso="HKLM\\" + c.chave + "\\" + c.valor,
                          referencia=c.referencia,
                          evidencia={"valor_atual": texto, "esperado": c.esperado, "modo": c.modo}))
    return itens


def avaliar_rdp(deny: int | None, nla: int | None) -> list[Item]:
    """RDP só interessa se estiver ligado; aí o que importa é o NLA."""
    if deny is None or deny == 1:          # ausente = desligado (padrão do cliente)
        return []
    itens = [Item(Severity.INFO, "Área de Trabalho Remota habilitada",
                  "O host aceita conexões RDP.",
                  "Se não usa, desligue; se usa, restrinja por firewall e exija NLA.",
                  recurso="HKLM\\" + TERMINAL_SERVER + "\\fDenyTSConnections",
                  referencia=CIS + " / MITRE T1021.001")]
    if nla != 1:
        atual = nla if nla is not None else "não configurado"
        itens.append(Item(Severity.HIGH, "RDP sem autenticação em nível de rede (NLA)",
                          f"UserAuthentication={atual}: a autenticação acontece depois de abrir a "
                          "sessão, o que expõe o host a força bruta e a falhas pré-autenticação.",
                          "Exija NLA (UserAuthentication=1).",
                          recurso="HKLM\\" + RDP_TCP + "\\UserAuthentication",
                          referencia=CIS + " / MITRE T1021.001"))
    return itens


def avaliar_netbios(interfaces: dict[str, int]) -> list[Item]:
    """NetbiosOptions: 0 = padrão (geralmente ativo), 1 = ativo, 2 = desativado."""
    ativas = sorted(n for n, v in interfaces.items() if v != 2)
    if not ativas:
        return []
    return [Item(Severity.LOW, "NetBIOS over TCP/IP ativo",
                 f"{len(ativas)} de {len(interfaces)} interface(s) ainda respondem NetBIOS, "
                 "o segundo caminho (junto com o LLMNR) para capturar hash na rede local.",
                 "Desative NetBIOS over TCP/IP nas interfaces que não precisam dele.",
                 recurso="HKLM\\" + NETBT_INTERFACES, referencia="MITRE T1557.001",
                 evidencia={"interfaces": ativas})]


def avaliar_firewall(perfis: list[dict]) -> list[Item]:
    if not perfis:
        return [Item(Severity.INFO, "Não foi possível ler os perfis de firewall",
                     "Get-NetFirewallProfile não retornou dados.",
                     "Verifique manualmente se os três perfis estão ativos.")]
    itens: list[Item] = []
    for p in perfis:
        nome = p.get("Name", "?")
        if not p.get("Enabled"):
            itens.append(Item(Severity.HIGH, f"Firewall desativado no perfil {nome}",
                              f"O perfil {nome} está com o firewall desligado.",
                              f"Reative o firewall no perfil {nome}.",
                              recurso=f"Perfil de firewall {nome}"))
        # NotConfigured herda o padrão (bloquear), então só "Allow" é problema
        if str(p.get("DefaultInboundAction", "")).lower() == "allow":
            itens.append(Item(Severity.HIGH, f"Entrada liberada por padrão no perfil {nome}",
                              f"A ação padrão de entrada do perfil {nome} é permitir.",
                              "Mude a ação padrão de entrada para bloquear.",
                              recurso=f"Perfil de firewall {nome}"))
    return itens


def normalizar_exclusoes(valor: Any) -> tuple[list[str], bool]:
    """Devolve (caminhos, legivel).

    Sem elevação o Get-MpPreference não falha: devolve a frase
    "N/A: Must be an administrator to view exclusions". Tratar isso como lista
    de caminhos daria um achado inventado (e, com o JSON desembrulhando lista de
    um item em string, até letra por letra). Então: string virando caminho só
    quando não é esse recado.
    """
    if valor is None:
        return [], True
    bruto = [valor] if isinstance(valor, str) else [v for v in valor if v]
    caminhos = [str(v) for v in bruto if str(v).strip()]
    if any(c.lower().startswith("n/a") or "must be an administrator" in c.lower()
           for c in caminhos):
        return [], False
    return caminhos, True


def avaliar_defender(status: dict, prefs: dict) -> list[Item]:
    if not status and not prefs:
        return [Item(Severity.INFO, "Não foi possível ler o estado do Defender",
                     "Get-MpComputerStatus/Get-MpPreference não retornaram dados "
                     "(outro antivírus no lugar, ou cmdlets indisponíveis).",
                     "Confirme qual antivírus está ativo e se a proteção em tempo real está ligada.",
                     referencia="CIS Controls 10")]

    itens: list[Item] = []
    modo = str(status.get("AMRunningMode", "") or "")
    passivo = "passive" in modo.lower()
    ref = "CIS Controls 10 / MITRE T1562.001"

    if passivo:
        itens.append(Item(Severity.INFO, "Defender em modo passivo",
                          f"O Defender está em '{modo}' — outro antivírus é o ativo.",
                          "Audite o antivírus que está de fato no comando.", referencia=ref))
    else:
        if status.get("AntivirusEnabled") is False:
            itens.append(Item(Severity.CRITICAL, "Antivírus desativado",
                              "O Defender está desligado e não há outro em modo ativo.",
                              "Reative a proteção antivírus agora.", referencia=ref))
        if status.get("RealTimeProtectionEnabled") is False:
            itens.append(Item(Severity.CRITICAL, "Proteção em tempo real desativada",
                              "Arquivo malicioso só seria visto em varredura manual.",
                              "Reative a proteção em tempo real.", referencia=ref))
        if status.get("BehaviorMonitorEnabled") is False:
            itens.append(Item(Severity.HIGH, "Monitoramento de comportamento desativado",
                              "Sem ele, ataque que só usa ferramenta legítima passa limpo.",
                              "Reative o monitoramento de comportamento.", referencia=ref))

    if status.get("IsTamperProtected") is False:
        itens.append(Item(Severity.MEDIUM, "Proteção contra violação desativada",
                          "Sem tamper protection, malware com privilégio desliga o antivírus.",
                          "Ative a proteção contra violação.", referencia=ref))

    idade = status.get("AntivirusSignatureAge")
    if isinstance(idade, int) and idade > 7:
        itens.append(Item(Severity.MEDIUM, "Assinaturas de antivírus desatualizadas",
                          f"As definições estão com {idade} dias.",
                          "Atualize as definições e verifique o Windows Update.",
                          referencia="CIS Controls 10", evidencia={"dias": idade}))

    if prefs.get("DisableScriptScanning") is True:
        itens.append(Item(Severity.MEDIUM, "Varredura de script desativada",
                          "O Defender não inspeciona scripts.",
                          "Reative a varredura de script.", referencia=ref))

    if prefs.get("PUAProtection") not in (1, None):
        itens.append(Item(Severity.LOW, "Proteção contra aplicativo indesejado (PUA) não bloqueia",
                          f"PUAProtection={prefs.get('PUAProtection')} (1 = bloquear).",
                          "Coloque a proteção PUA em bloquear.", referencia=CIS))

    if prefs.get("MAPSReporting") == 0:
        itens.append(Item(Severity.LOW, "Proteção entregue na nuvem desativada",
                          "Sem MAPS o host perde o veredito em nuvem, que é o que pega ameaça nova.",
                          "Ative a proteção entregue na nuvem.", referencia=CIS))

    exclusoes, legivel = normalizar_exclusoes(prefs.get("ExclusionPath"))
    if not legivel:
        itens.append(Item(Severity.INFO, "Não foi possível listar as exclusões do Defender",
                          "A lista de exclusões só é visível em prompt elevado.",
                          "Rode o auditor como Administrador para revisar as exclusões.",
                          recurso="Defender: ExclusionPath", referencia="MITRE T1562.001"))
    elif exclusoes:
        itens.append(Item(Severity.LOW, "Exclusões de varredura configuradas",
                          f"{len(exclusoes)} caminho(s) fora da varredura. Criar exclusão é "
                          "técnica conhecida de evasão, então cada uma precisa de dono e motivo.",
                          "Revise as exclusões e remova as que não tiverem justificativa.",
                          recurso="Defender: ExclusionPath", referencia="MITRE T1562.001",
                          evidencia={"caminhos": exclusoes}))
    return itens


def avaliar_criptografia(volumes: list[dict], sistema: str = "C:") -> list[Item]:
    if not volumes:
        return [Item(Severity.INFO, "Não foi possível verificar a criptografia de disco",
                     "A consulta de volumes criptografáveis não retornou dados "
                     "(normalmente requer prompt elevado).",
                     "Rode o auditor como Administrador para esta checagem.",
                     referencia="CIS Controls 3")]
    itens: list[Item] = []
    sistema_norm = sistema.rstrip("\\").upper()
    for v in volumes:
        ponto = str(v.get("MountPoint") or "").rstrip("\\").upper()
        if str(v.get("ProtectionStatus", "")).lower() == "on":
            continue
        eh_sistema = str(v.get("VolumeType", "")).lower() == "operatingsystem" or ponto == sistema_norm
        if eh_sistema:
            itens.append(Item(Severity.HIGH, "Disco do sistema sem criptografia",
                              f"O volume {ponto or sistema_norm} não está protegido "
                              f"(status: {v.get('VolumeStatus', 'desconhecido')}). Com o disco em "
                              "mãos, qualquer arquivo é lido sem senha.",
                              "Ative BitLocker/Criptografia de Dispositivo e guarde a chave de "
                              "recuperação fora da máquina.",
                              recurso=f"Volume {ponto or sistema_norm}",
                              referencia="CIS Controls 3", evidencia=dict(v)))
        else:
            itens.append(Item(Severity.LOW, f"Volume {ponto} sem criptografia",
                              f"O volume de dados {ponto} não está protegido.",
                              "Criptografe também os volumes de dados.",
                              recurso=f"Volume {ponto}", referencia="CIS Controls 3",
                              evidencia=dict(v)))
    return itens


def avaliar_secure_boot(estado: bool | None) -> list[Item]:
    if estado is None:
        return [Item(Severity.INFO, "Não foi possível verificar o Secure Boot",
                     "Confirm-SecureBootUEFI não respondeu (firmware legado/BIOS ou falta de elevação).",
                     "Confirme no firmware se o Secure Boot está ativo.")]
    if estado:
        return []
    return [Item(Severity.MEDIUM, "Secure Boot desativado",
                 "O firmware aceita carregar bootloader não assinado — porta para bootkit.",
                 "Ative o Secure Boot no firmware UEFI.",
                 recurso="Firmware UEFI", referencia=CIS + " / MITRE T1542")]


def avaliar_smb(servidor: dict, cliente: dict, smb1_registro: int | None = None) -> list[Item]:
    """SMB em um lugar só.

    Os cmdlets são a fonte boa (enxergam o padrão vigente da versão do Windows);
    o valor de registro entra só como reserva, para não perder a checagem de
    SMBv1 quando os cmdlets não respondem. Assim o mesmo problema não é relatado
    duas vezes.
    """
    itens: list[Item] = []
    ref_relay = CIS + " / MITRE T1557.001"

    if servidor:
        smb1 = servidor.get("EnableSMB1Protocol") is True
    else:
        smb1 = smb1_registro == 1
    if smb1:
        itens.append(Item(Severity.HIGH, "SMBv1 habilitado",
                          "O host ainda atende SMBv1 — protocolo morto, sem assinatura decente "
                          "e com histórico de execução remota (EternalBlue).",
                          "Desative o recurso 'Suporte a Compartilhamento de Arquivos SMB 1.0'.",
                          recurso="SMB (servidor)", referencia=CIS + " / MITRE T1210"))

    if not servidor and not cliente:
        itens.append(Item(Severity.INFO, "Não foi possível ler a configuração de SMB",
                          "Get-SmbServerConfiguration/Get-SmbClientConfiguration não responderam.",
                          "Confira manualmente se a assinatura de SMB está exigida.",
                          referencia=ref_relay))
        return itens

    if servidor.get("RequireSecuritySignature") is False:
        itens.append(Item(Severity.MEDIUM, "Servidor SMB não exige assinatura",
                          "Sessões SMB são aceitas sem assinatura, o que abre espaço para relay.",
                          "Exija assinatura de SMB no servidor.",
                          recurso="SMB (servidor)", referencia=ref_relay))
    if cliente.get("RequireSecuritySignature") is False:
        itens.append(Item(Severity.MEDIUM, "Cliente SMB não exige assinatura",
                          "O host aceita falar com servidor que não assina — é assim que o "
                          "atacante no meio captura e repassa a autenticação.",
                          "Exija assinatura de SMB no cliente.",
                          recurso="SMB (cliente)", referencia=ref_relay))
    return itens


# serviço -> (severidade, porquê, o que fazer)
SERVICOS_RISCO: dict[str, tuple[Severity, str, str]] = {
    "RemoteRegistry": (Severity.MEDIUM,
                       "Permite ler e enumerar o registro pela rede — reconhecimento barato.",
                       "Pare o serviço e deixe o início como Desativado."),
    "Spooler": (Severity.LOW,
                "O spooler de impressão acumula histórico de falhas de elevação (PrintNightmare).",
                "Se a máquina não imprime nem compartilha impressora, desative o serviço."),
    "WinRM": (Severity.LOW,
              "Gerenciamento remoto ativo é caminho de execução remota autenticada.",
              "Desative se não usa, ou restrinja por firewall e HTTPS."),
    "SSDPSRV": (Severity.LOW,
                "UPnP/SSDP expõe descoberta de serviços na rede local.",
                "Desative se não usa dispositivo UPnP."),
    "upnphost": (Severity.LOW,
                 "Host de dispositivo UPnP pode abrir portas sozinho.",
                 "Desative se não usa dispositivo UPnP."),
}


def avaliar_servicos(servicos: dict[str, dict]) -> list[Item]:
    itens: list[Item] = []
    for nome, (sev, porque, acao) in SERVICOS_RISCO.items():
        info = servicos.get(nome)
        if not info or str(info.get("Status", "")).lower() != "running":
            continue
        itens.append(Item(sev, f"Serviço de risco em execução: {nome}", porque, acao,
                          recurso=f"Serviço {nome}", referencia=CIS + " / MITRE T1021",
                          evidencia={"status": info.get("Status"), "inicio": info.get("StartType")}))
    return itens


# Uma passada só no PowerShell: cada bloco isolado em try/catch para que a
# falta de privilégio em um não derrube os outros.
_PS_COLETA = r"""
$ErrorActionPreference = 'Stop'
$r = @{}
try { $r.firewall = @(Get-NetFirewallProfile | Select-Object Name,
        @{n='Enabled';e={[bool]$_.Enabled}},
        @{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}}) } catch { $r.firewall = @() }
try { $r.defender_status = Get-MpComputerStatus | Select-Object AntivirusEnabled,
        RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected,
        AntivirusSignatureAge, @{n='AMRunningMode';e={[string]$_.AMRunningMode}} } catch { $r.defender_status = $null }
try { $r.defender_prefs = Get-MpPreference | Select-Object PUAProtection, MAPSReporting,
        DisableScriptScanning, @{n='ExclusionPath';e={@($_.ExclusionPath)}} } catch { $r.defender_prefs = $null }
try { $r.smb_servidor = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,
        RequireSecuritySignature, EnableSecuritySignature } catch { $r.smb_servidor = $null }
try { $r.smb_cliente = Get-SmbClientConfiguration | Select-Object EnableSMB1Protocol,
        RequireSecuritySignature } catch { $r.smb_cliente = $null }
try { $r.secure_boot = [bool](Confirm-SecureBootUEFI) } catch { $r.secure_boot = $null }
try { $r.volumes = @(Get-BitLockerVolume | Select-Object @{n='MountPoint';e={[string]$_.MountPoint}},
        @{n='VolumeStatus';e={[string]$_.VolumeStatus}},
        @{n='ProtectionStatus';e={[string]$_.ProtectionStatus}},
        @{n='VolumeType';e={[string]$_.VolumeType}}) } catch { $r.volumes = @() }
if (@($r.volumes).Count -eq 0) {
  # edicao Home nao tem os cmdlets de BitLocker; o WMI de criptografia existe nela
  try { $r.volumes = @(Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume | Select-Object @{n='MountPoint';e={[string]$_.DriveLetter}},
        @{n='ProtectionStatus';e={ if ($_.ProtectionStatus -eq 1) {'On'} else {'Off'} }},
        @{n='VolumeStatus';e={ if ($_.ConversionStatus -eq 1) {'FullyEncrypted'} else {'FullyDecrypted'} }},
        @{n='VolumeType';e={ if ($_.DriveLetter -eq $env:SystemDrive) {'OperatingSystem'} else {'Data'} }}) } catch { $r.volumes = @() }
}
$svc = @{}
foreach ($n in @('RemoteRegistry','Spooler','WinRM','SSDPSRV','upnphost')) {
  try { $o = Get-Service -Name $n
        $svc[$n] = @{ Status = [string]$o.Status; StartType = [string]$o.StartType } } catch {}
}
$r.servicos = $svc
$r | ConvertTo-Json -Depth 5 -Compress
"""


class HardeningAudit(Plugin):
    nome = "hardening-audit"
    descricao = ("Compara o endurecimento do host com a baseline CIS "
                 "(UAC, LSA, SMB, RDP, firewall, Defender, disco).")
    sistemas = ("Windows",)

    def run(self, ctx: Contexto) -> list[Finding]:
        itens: list[Item] = []

        lidos = self._ler_registro([(c.chave, c.valor) for c in CHECAGENS] + list(EXTRAS))
        itens += avaliar_registro(lidos)
        itens += avaliar_rdp(lidos.get((TERMINAL_SERVER, "fDenyTSConnections")),
                             lidos.get((RDP_TCP, "UserAuthentication")))
        itens += avaliar_netbios(self._ler_netbios())

        dados = self._coletar_powershell()
        if dados is None:
            itens.append(Item(Severity.INFO, "Coleta via PowerShell falhou",
                              "Não foi possível consultar firewall, Defender, SMB e criptografia.",
                              "Verifique se o PowerShell está acessível e rode de novo."))
        else:
            itens += avaliar_firewall(dados.get("firewall") or [])
            itens += avaliar_defender(dados.get("defender_status") or {},
                                      dados.get("defender_prefs") or {})
            itens += avaliar_smb(dados.get("smb_servidor") or {},
                                 dados.get("smb_cliente") or {},
                                 lidos.get((LANMAN_SERVER, "SMB1")))
            itens += avaliar_secure_boot(dados.get("secure_boot"))
            itens += avaliar_criptografia(dados.get("volumes") or [],
                                          sistema=os.environ.get("SystemDrive", "C:"))
            itens += avaliar_servicos(dados.get("servicos") or {})

        return [self.finding(titulo=i.titulo, severidade=i.severidade, descricao=i.descricao,
                             recomendacao=i.recomendacao, recurso=i.recurso,
                             referencia=i.referencia, evidencia=i.evidencia) for i in itens]

    # ---- coletores (só leitura) ----
    @staticmethod
    def _ler_registro(alvos: list[tuple[str, str]]) -> dict[tuple[str, str], Any]:
        """Lê os valores pedidos; o que não existe simplesmente não entra no dict."""
        lidos: dict[tuple[str, str], Any] = {}
        if winreg is None:
            return lidos
        for chave, valor in dict.fromkeys(alvos):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, chave, 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                    dado, _ = winreg.QueryValueEx(k, valor)
            except OSError:
                continue
            lidos[(chave, valor)] = dado
        return lidos

    @staticmethod
    def _ler_netbios() -> dict[str, int]:
        """NetbiosOptions de cada interface do NetBT."""
        interfaces: dict[str, int] = {}
        if winreg is None:
            return interfaces
        try:
            raiz = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETBT_INTERFACES, 0,
                                  winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            return interfaces
        with raiz:
            i = 0
            while True:
                try:
                    nome = winreg.EnumKey(raiz, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(raiz, nome) as sub:
                        opcao, _ = winreg.QueryValueEx(sub, "NetbiosOptions")
                except OSError:
                    continue
                if isinstance(opcao, int):
                    interfaces[nome] = opcao
        return interfaces

    @staticmethod
    def _coletar_powershell() -> dict[str, Any] | None:
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_COLETA],
                               capture_output=True, text=True, errors="replace",
                               timeout=180, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        saida = (r.stdout or "").strip()
        if not saida:
            return None
        try:
            dados = json.loads(saida)
        except json.JSONDecodeError:
            return None
        return dados if isinstance(dados, dict) else None
