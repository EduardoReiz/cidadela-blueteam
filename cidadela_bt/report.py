"""Renderização do relatório: console (humano), JSON (máquina) e HTML (celular)."""

from __future__ import annotations

import html
import json
from typing import Any

from .core import Relatorio
from .plugin import Severity

# Ordena do mais grave ao menos grave na saída.
_ORDEM = sorted(Severity, key=lambda s: s.value, reverse=True)


def para_json(rel: Relatorio, *, indent: int = 2) -> str:
    payload: dict[str, Any] = {
        "alvo": rel.alvo,
        "gerado_em": rel.gerado_em,
        "resumo": {
            "total_achados": rel.total_achados,
            "por_severidade": rel.por_severidade(),
            "plugins_executados": len(rel.resultados),
            "plugins_com_erro": [r.plugin for r in rel.resultados if not r.ok],
        },
        "resultados": [
            {
                "plugin": r.plugin,
                "ok": r.ok,
                "erro": r.erro,
                "duracao_s": r.duracao_s,
                "achados": [f.to_dict() for f in r.findings],
            }
            for r in rel.resultados
        ],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def para_console(rel: Relatorio, *, cor: bool = True) -> str:
    linhas: list[str] = []
    linhas.append(f"CIDADELA BLUE TEAM — alvo: {rel.alvo}  ({rel.gerado_em})")
    resumo = rel.por_severidade()
    resumo_txt = "  ".join(f"{k}={v}" for k, v in sorted(resumo.items())) or "nenhum achado"
    linhas.append(f"Resumo: {rel.total_achados} achados  [{resumo_txt}]")
    linhas.append("")

    for r in rel.resultados:
        cab = f"── {r.plugin}  ({r.duracao_s}s)"
        linhas.append(cab if r.ok else f"{cab}  [ERRO: {r.erro}]")
        if not r.findings:
            if r.ok:
                linhas.append("   (sem achados)")
            linhas.append("")
            continue
        for sev in _ORDEM:
            for f in r.findings:
                if f.severidade is not sev:
                    continue
                marca = _marca(f.severidade, cor)
                linhas.append(f"   {marca} [{f.severidade.rotulo}] {f.titulo}")
                if f.recurso:
                    linhas.append(f"        recurso: {f.recurso}")
                linhas.append(f"        {f.descricao}")
                if f.recomendacao:
                    linhas.append(f"        → {f.recomendacao}")
                if f.referencia:
                    linhas.append(f"        ref: {f.referencia}")
        linhas.append("")
    return "\n".join(linhas)


_CORES = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _marca(sev: Severity, cor: bool) -> str:
    bolinha = "●"
    if not cor:
        return bolinha
    return f"{_CORES.get(sev, '')}{bolinha}{_RESET}"


# cor de fundo de cada severidade no HTML (legível em tema claro e escuro)
_HTML_COR = {
    Severity.CRITICAL: "#7c3aed",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


def para_html(rel: Relatorio) -> str:
    """Relatório em HTML — página única, sem dependência externa, boa no celular."""
    e = html.escape
    resumo = rel.por_severidade()
    chips = "".join(
        f'<span class="chip" style="background:{_HTML_COR.get(_sev(k), "#6b7280")}">'
        f'{e(k)}: {v}</span>'
        for k, v in sorted(resumo.items(), key=lambda kv: -_sev(kv[0]).value)
    ) or '<span class="chip" style="background:#16a34a">nenhum achado</span>'

    blocos: list[str] = []
    for r in rel.resultados:
        cabecalho = f"{e(r.plugin)} · {r.duracao_s}s"
        if not r.ok:
            cabecalho += f' <span class="erro">ERRO: {e(r.erro or "")}</span>'
        cartoes: list[str] = []
        for f in sorted(r.findings, key=lambda x: -x.severidade.value):
            cor = _HTML_COR.get(f.severidade, "#6b7280")
            partes = [f'<div class="card" style="border-left-color:{cor}">']
            partes.append(f'<div class="tit"><span class="badge" style="background:{cor}">'
                          f'{e(f.severidade.rotulo)}</span> {e(f.titulo)}</div>')
            if f.recurso:
                partes.append(f'<div class="rec">{e(f.recurso)}</div>')
            partes.append(f'<div class="desc">{e(f.descricao)}</div>')
            if f.recomendacao:
                partes.append(f'<div class="fix">→ {e(f.recomendacao)}</div>')
            if f.referencia:
                partes.append(f'<div class="ref">{e(f.referencia)}</div>')
            partes.append("</div>")
            cartoes.append("".join(partes))
        corpo = "".join(cartoes) or '<div class="vazio">sem achados</div>'
        blocos.append(f'<section><h2>{cabecalho}</h2>{corpo}</section>')

    return f"""<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cidadela Blue Team — {e(rel.alvo)}</title>
<style>
:root{{color-scheme:light dark}}
*{{box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
background:#0f1115;color:#e5e7eb;line-height:1.45}}
header{{padding:20px 16px;background:#161922;border-bottom:1px solid #262b36}}
h1{{margin:0 0 4px;font-size:1.2rem}}
.sub{{color:#9ca3af;font-size:.82rem}}
.chips{{margin-top:12px;display:flex;flex-wrap:wrap;gap:6px}}
.chip,.badge{{color:#fff;border-radius:999px;padding:3px 10px;font-size:.72rem;font-weight:600}}
main{{max-width:760px;margin:0 auto;padding:16px}}
section{{margin:18px 0}}
h2{{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:#9ca3af;
border-bottom:1px solid #262b36;padding-bottom:6px}}
.erro{{color:#f87171}}
.card{{background:#161922;border:1px solid #262b36;border-left-width:4px;
border-radius:8px;padding:12px 14px;margin:10px 0}}
.tit{{font-weight:600;margin-bottom:4px}}
.badge{{margin-right:6px;font-size:.66rem}}
.rec{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;
color:#93c5fd;margin-bottom:4px;word-break:break-all}}
.desc{{font-size:.9rem;color:#d1d5db}}
.fix{{font-size:.85rem;color:#86efac;margin-top:6px}}
.ref{{font-size:.72rem;color:#6b7280;margin-top:6px}}
.vazio{{color:#6b7280;font-size:.85rem;padding:8px 0}}
footer{{text-align:center;color:#6b7280;font-size:.72rem;padding:24px 16px}}
</style></head>
<body>
<header>
<h1>🛡️ Cidadela Blue Team</h1>
<div class="sub">alvo: {e(rel.alvo)} · gerado em {e(rel.gerado_em)} · {rel.total_achados} achado(s)</div>
<div class="chips">{chips}</div>
</header>
<main>{"".join(blocos)}</main>
<footer>Auditoria defensiva somente leitura · Cidadela Blue Team</footer>
</body></html>"""


def _sev(rotulo: str) -> Severity:
    for s in Severity:
        if s.rotulo == rotulo:
            return s
    return Severity.INFO
