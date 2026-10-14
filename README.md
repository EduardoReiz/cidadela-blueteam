# Cidadela Blue Team

Framework modular de **auditoria defensiva** (blue team). Enumera e avalia a
postura de segurança de um host — **somente leitura**, não altera nada.

Cada capacidade é um *plugin* auto-descoberto; o orquestrador roda todos de
forma isolada (a falha de um não derruba os outros) e gera relatório em
console ou JSON.

## Requisitos
- Python 3.10+
- Núcleo usa só a biblioteca padrão (sem dependências de runtime).

## Uso
```bash
python -m cidadela_bt listar
python -m cidadela_bt rodar
python -m cidadela_bt rodar --apenas persistencia-audit --json relatorio.json
```

O código de saída é `1` quando há achados e `0` quando não há — útil em CI.

## Plugins
| Nome | SO | O que faz |
|------|----|-----------|
| `persistencia-audit` | Windows | Audita autoruns, pastas de inicialização e tarefas agendadas; discrimina por assinatura digital e sinaliza persistência suspeita (MITRE T1547/T1053/T1543). |
| `politica-senha-audit` | Windows | Política local de senha (via `secedit`) e contas locais contra baseline CIS/NIST: comprimento, complexidade, bloqueio, senha reversível. |
| `dns-tunnel-detect` | qualquer | Procura tunelamento/exfiltração por DNS no cache local ou em arquivo de log: entropia, cardinalidade e comprimento de rótulo (MITRE T1071.004/T1048). |
| `hardening-audit` | Windows | Compara o endurecimento do host com a baseline CIS: UAC, LSA/credenciais, SMB, RDP, LLMNR/NetBIOS, AutoRun, telemetria de PowerShell, firewall, Defender, criptografia de disco, Secure Boot e serviços de risco. |
| `ofuscacao-detect` | qualquer | Procura comando e script ofuscados nos processos em execução, nos logs 4104/4688 ou em arquivo. Motor de regras com peso (no espírito do YARA, em regex puro), decodifica base64 e pontua o payload escondido de novo (MITRE T1027/T1059.001/T1218). |
| `patch-priority` | Windows | Monta a fila de correção: idade do patch do SO, fim de suporte do build, reinício pendente, serviço de atualização, software abandonado e exposição de rede (o que escuta, e se escuta para fora). CVE do NVD como enriquecimento opcional. |
| `postura-web` | qualquer | Audita a postura de um site de fora, sem atacá-lo: redirecionamento HTTPS, TLS, cabeçalhos de segurança, versão divulgada, caminhos sensíveis expostos (`.env`/`.git`), listagem de diretório, portas abertas e IP de origem vazando por fora do Cloudflare. Só GET/HEAD e conexão TCP. |
| `segredo-exposto` | qualquer | Varre o projeto atrás de chave, token e senha em arquivo (chave privada, AWS, GitHub, Google, Slack, Telegram, Stripe, JWT, URL com credencial, atribuição sensível). O segredo **nunca** sai inteiro no relatório — fica mascarado (`ghp_…ab[40]`); severidade sobe se o arquivo está no git. |

### Opções do `ofuscacao-detect`
```bash
python -m cidadela_bt rodar --apenas ofuscacao-detect \
    --opcao arquivo=suspeito.ps1 \
    --opcao horas=48 --opcao eventos=500 \
    --opcao ignorar=minha_ferramenta,outro_padrao
```
`ignorar` recebe uma lista por vírgula de trechos a tirar da análise — ferramenta
legítima da casa costuma usar o mesmo formato de um ataque. O que foi suprimido
sai contado em um achado `INFO`: **supressão calada vira ponto cego**.

Checagens que dependem de privilégio (política de senha, criptografia de disco,
Secure Boot, exclusões do Defender) só respondem em prompt elevado. Quando não dá
para ler, o achado sai como `INFO` dizendo isso — **"não verificado" nunca é
tratado como "conforme"**.

### Opções do `patch-priority`
```bash
python -m cidadela_bt rodar --apenas patch-priority                 # só fato local
python -m cidadela_bt rodar --apenas patch-priority --opcao online=1 \
    --opcao max_consultas=5 --opcao nvd_api_key=<chave>
```
Sem `online=1` o módulo não toca na rede. Com ele, consulta o NVD e **casa faixa
de versão pelo CPE** que o próprio NVD devolve — não por palavra-chave. CVE sem
faixa declarada é descartada: "todas as versões" não prioriza nada. Ainda assim
o achado sai marcado como **indício a confirmar**, porque nome de produto no CPE
e nome no registro divergem com frequência. Sem chave de API o NVD limita a 5
requisições por 30s, então o módulo espera entre consultas.

> A tabela de ciclo de vida (`BUILDS_WINDOWS`) e a de software abandonado
> (`ABANDONADOS`) são conhecimento com data: `TABELA_ATUALIZADA` vai dentro do
> achado para ninguém confiar nelas cegamente depois.

### Opções do `segredo-exposto`
```bash
python -m cidadela_bt rodar --apenas segredo-exposto --opcao caminho=C:\projetos\meu-site
```
Sem `caminho`, varre a pasta atual. Pula `node_modules`, `.git`, binários e
arquivos grandes. Se a pasta for um repositório git, achados em arquivo
rastreado sobem de severidade (o segredo foi para o histórico, que se compartilha).

## Relatório em HTML

Além do console e do JSON, dá para gerar um relatório em **HTML** (bom para abrir
no celular ou guardar):
```bash
python -m cidadela_bt rodar --html relatorio.html
```

## Monitoramento contínuo (aviso no celular)

O comando `monitorar` roda a auditoria, compara com a última foto (baseline) e
avisa **só o que mudou** — por Telegram, se configurado.

```bash
# primeira foto (cria a baseline)
python -m cidadela_bt monitorar --baseline baseline.json

# rodadas seguintes: avisa novos/resolvidos e manda no Telegram
python -m cidadela_bt monitorar --baseline baseline.json --telegram --atualizar-baseline
python -m cidadela_bt monitorar --apenas postura-web --opcao url=https://exemplo.com --telegram
```

Telegram (o token e o chat nunca ficam no código):
```bash
# Windows PowerShell
$env:CIDADELA_TELEGRAM_TOKEN = "123456:ABC-DEF..."
$env:CIDADELA_TELEGRAM_CHAT  = "987654321"
# ou por opção: --opcao telegram_token=... --opcao telegram_chat=...
```

`--min-severidade` corta o ruído (padrão BAIXA, ignora INFO). O código de saída
é `1` quando há achado NOVO — serve para agendar (Task Scheduler/cron) e só ser
incomodado quando algo realmente mudou.

## Escrever um plugin novo
Crie um arquivo em `cidadela_bt/plugins/` com uma subclasse de `Plugin`:

```python
from ..plugin import Contexto, Finding, Plugin, Severity

class MeuAudit(Plugin):
    nome = "meu-audit"
    descricao = "o que ele checa"
    sistemas = ("Windows",)  # ou () para qualquer SO

    def run(self, ctx: Contexto) -> list[Finding]:
        return [self.finding(titulo="...", severidade=Severity.MEDIUM, descricao="...")]
```
Pronto — ele é descoberto e executado automaticamente.

## Testes
```bash
pytest -q
```

## Princípio
Isto é **blue team**: entende as técnicas de ataque para **detectar e endurecer**,
nunca para executar. Todos os módulos são read-only e mapeados para MITRE ATT&CK.
