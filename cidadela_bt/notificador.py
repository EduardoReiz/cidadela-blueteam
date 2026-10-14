"""Aviso no celular via Telegram — a sentinela que fala com a rainha.

A ferramenta vê; este módulo conta. Manda para um bot do Telegram só o que
importa: o que mudou desde a última foto, filtrado por severidade para o
celular não virar máquina de spam (alarme que toca o tempo todo logo é ignorado,
e aí não serve pra nada).

O token do bot e o id do chat NUNCA ficam no código. Vêm de variável de
ambiente (CIDADELA_TELEGRAM_TOKEN / CIDADELA_TELEGRAM_CHAT) ou das opções da
linha de comando. Montar a mensagem é função pura/testável; o envio é o único
I/O e fica isolado.
"""

from __future__ import annotations

import html
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from .baseline import Diff, Entrada
from .plugin import Severity

_EMOJI = {
    Severity.CRITICAL: "🟣",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

# quantos blocos acesos na barra de ameaça (de 8) por severidade
_BLOCOS = {Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 4,
           Severity.HIGH: 6, Severity.CRITICAL: 8}


def config_telegram(opcoes: dict[str, str] | None = None) -> tuple[str, str] | None:
    """Devolve (token, chat_id) de opções ou ambiente; None se faltar algum."""
    opcoes = opcoes or {}
    token = opcoes.get("telegram_token") or os.environ.get("CIDADELA_TELEGRAM_TOKEN", "")
    chat = opcoes.get("telegram_chat") or os.environ.get("CIDADELA_TELEGRAM_CHAT", "")
    token, chat = token.strip(), chat.strip()
    return (token, chat) if token and chat else None


def _linha(e: Entrada) -> str:
    recurso = f" — <i>{html.escape(e.recurso)}</i>" if e.recurso else ""
    return f"{_EMOJI.get(e.severidade, '•')} <b>[{e.severidade.rotulo}]</b> {html.escape(e.titulo)}{recurso}"


def montar_mensagem(alvo: str, diff: Diff, *, min_severidade: Severity = Severity.LOW,
                    max_itens: int = 15, estilo: str = "limpo",
                    agora: datetime | None = None) -> str | None:
    """Texto do alerta, ou None quando não há nada digno de incomodar o celular.

    `estilo="cinema"` troca o visual pro painel de vigilância; o conteúdo é o
    mesmo (o que mudou, por gravidade) — muda só a embalagem.
    """
    novos = [e for e in diff.novos if e.severidade >= min_severidade]
    resolvidos = [e for e in diff.resolvidos if e.severidade >= min_severidade]
    if not novos and not resolvidos:
        return None
    if estilo == "cinema":
        return _mensagem_cinema(alvo, novos, resolvidos, max_itens, agora)
    return _mensagem_limpa(alvo, novos, resolvidos, max_itens)


def _mensagem_limpa(alvo: str, novos: list[Entrada], resolvidos: list[Entrada],
                    max_itens: int) -> str:
    linhas = [f"🛡️ <b>Cidadela</b> — {html.escape(alvo)}"]
    if novos:
        pior = max(novos, key=lambda e: int(e.severidade))
        linhas.append(f"\n{_EMOJI.get(pior.severidade, '')} <b>{len(novos)} novo(s)</b> "
                      "desde a última verificação:")
        linhas += [_linha(e) for e in novos[:max_itens]]
        if len(novos) > max_itens:
            linhas.append(f"… e mais {len(novos) - max_itens}.")
    if resolvidos:
        linhas.append(f"\n✅ <b>{len(resolvidos)}</b> resolvido(s) desde a última foto.")
    return "\n".join(linhas)


def _barra_ameaca(sev: Severity) -> str:
    acesos = _BLOCOS.get(sev, 0)
    return "▓" * acesos + "░" * (8 - acesos)


def _mensagem_cinema(alvo: str, novos: list[Entrada], resolvidos: list[Entrada],
                     max_itens: int, agora: datetime | None) -> str:
    quando = (agora or datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
    pior = max((e.severidade for e in novos), default=Severity.INFO)
    rotulo = pior.rotulo if novos else "ESTÁVEL"

    painel = (f"┌─[ VARREDURA DE PERÍMETRO ]\n"
              f"│ ALVO   : {alvo}\n"
              f"│ HORA   : {quando}\n"
              f"│ AMEAÇA : {_barra_ameaca(pior if novos else Severity.INFO)}  {rotulo}\n"
              f"└──────────────────────────")
    linhas = ["🛰 <b>C I D A D E L A</b> · <i>sistema de vigilância</i>",
              f"<pre>{html.escape(painel)}</pre>"]

    if novos:
        linhas.append(f"⚠️ <b>{len(novos)} ASSINATURA(S) DETECTADA(S)</b>\n")
        for e in novos[:max_itens]:
            linhas.append(f"{_EMOJI.get(e.severidade, '•')} <b>[{e.severidade.rotulo}]</b> "
                          f"{html.escape(e.titulo)}")
            if e.recurso:
                linhas.append(f"     ↳ <code>{html.escape(e.recurso)}</code>")
        if len(novos) > max_itens:
            linhas.append(f"… e mais {len(novos) - max_itens} rastro(s).")
    if resolvidos:
        linhas.append(f"\n✅ <b>{len(resolvidos)} perímetro(s) selado(s)</b> desde a última ronda.")
    linhas.append("\n<i>— fim da transmissão —</i>")
    return "\n".join(linhas)


def enviar_telegram(token: str, chat_id: str, texto: str, *, timeout: int = 15) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    dados = urllib.parse.urlencode({
        "chat_id": chat_id, "text": texto, "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=dados), timeout=timeout) as r:
            return 200 <= r.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False
