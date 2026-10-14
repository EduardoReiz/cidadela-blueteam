"""Interface de linha de comando do Cidadela Blue Team.

Exemplos:
    python -m cidadela_bt listar
    python -m cidadela_bt rodar
    python -m cidadela_bt rodar --apenas persistencia-audit --json saida.json
"""

from __future__ import annotations

import argparse
import logging
import sys

from .baseline import carregar_baseline, comparar, entradas_do_relatorio, salvar_baseline
from .core import Orquestrador
from .notificador import config_telegram, enviar_telegram, montar_mensagem
from .plugin import Contexto, Severity
from .report import para_console, para_html, para_json


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cidadela_bt", description="Framework de auditoria defensiva (blue team).")
    p.add_argument("-v", "--verbose", action="store_true", help="logs detalhados")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("listar", help="lista os plugins disponíveis")

    r = sub.add_parser("rodar", help="executa a auditoria")
    r.add_argument("--alvo", default="localhost", help="rótulo do alvo (padrão: localhost)")
    r.add_argument("--apenas", nargs="*", metavar="PLUGIN", help="roda só estes plugins (por nome)")
    r.add_argument("--json", metavar="ARQUIVO", help="salva o relatório em JSON")
    r.add_argument("--html", metavar="ARQUIVO", help="salva o relatório em HTML")
    r.add_argument("--sem-cor", action="store_true", help="saída sem cores ANSI")
    r.add_argument("--opcao", action="append", metavar="CHAVE=VALOR", default=[],
                   help="opção passada aos plugins (ex.: arquivo=logs_dns.txt). Repetível.")

    m = sub.add_parser("monitorar", help="roda, compara com a última foto e avisa só o que mudou")
    m.add_argument("--alvo", default="localhost", help="rótulo do alvo (padrão: localhost)")
    m.add_argument("--apenas", nargs="*", metavar="PLUGIN", help="roda só estes plugins")
    m.add_argument("--opcao", action="append", metavar="CHAVE=VALOR", default=[],
                   help="opção passada aos plugins/notificador. Repetível.")
    m.add_argument("--baseline", default="baseline.json", metavar="ARQUIVO",
                   help="arquivo da foto anterior (padrão: baseline.json)")
    m.add_argument("--atualizar-baseline", action="store_true",
                   help="grava a foto atual como nova baseline")
    m.add_argument("--telegram", action="store_true",
                   help="envia o que mudou para o Telegram (precisa de token e chat)")
    m.add_argument("--min-severidade", default="BAIXA",
                   choices=[s.rotulo for s in Severity],
                   help="só avisa deste nível para cima (padrão: BAIXA)")
    return p


def _parse_opcoes(pares: list[str]) -> dict[str, str]:
    opcoes: dict[str, str] = {}
    for par in pares:
        chave, _, valor = par.partition("=")
        if chave:
            opcoes[chave.strip()] = valor.strip()
    return opcoes


def main(argv: list[str] | None = None) -> int:
    # Console do Windows costuma ser cp1252; garante que acentos e símbolos
    # do relatório não quebrem a saída.
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass

    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    orq = Orquestrador()

    if args.cmd == "listar":
        for p in orq.listar():
            sos = ",".join(p.sistemas) if p.sistemas else "qualquer"
            print(f"  {p.nome:<24} [{sos:<8}] {p.descricao}")
        return 0

    if args.cmd == "rodar":
        ctx = Contexto(alvo=args.alvo, somente_leitura=True, opcoes=_parse_opcoes(args.opcao))
        rel = orq.rodar(ctx, apenas=set(args.apenas) if args.apenas else None)
        print(para_console(rel, cor=not args.sem_cor))
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(para_json(rel))
            print(f"[+] Relatório JSON salvo em {args.json}")
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(para_html(rel))
            print(f"[+] Relatório HTML salvo em {args.html}")
        # código de saída reflete a pior severidade (útil pra pipeline/CI)
        return 1 if rel.total_achados else 0

    if args.cmd == "monitorar":
        opcoes = _parse_opcoes(args.opcao)
        ctx = Contexto(alvo=args.alvo, somente_leitura=True, opcoes=opcoes)
        rel = orq.rodar(ctx, apenas=set(args.apenas) if args.apenas else None)

        baseline = carregar_baseline(args.baseline)
        primeira_vez = not baseline
        diff = comparar(baseline, entradas_do_relatorio(rel))
        min_sev = next(s for s in Severity if s.rotulo == args.min_severidade)

        print(f"Monitoramento de {args.alvo}: "
              f"{len(diff.novos)} novo(s), {len(diff.resolvidos)} resolvido(s), "
              f"{len(diff.persistentes)} persistente(s).")
        if primeira_vez:
            print(f"[i] Sem baseline em {args.baseline}: primeira foto, tudo conta como novo.")

        mensagem = montar_mensagem(args.alvo, diff, min_severidade=min_sev,
                                   estilo=opcoes.get("estilo", "limpo"))
        if args.telegram:
            cfg = config_telegram(opcoes)
            if cfg is None:
                print("[!] Telegram não configurado (defina CIDADELA_TELEGRAM_TOKEN e "
                      "CIDADELA_TELEGRAM_CHAT, ou passe --opcao telegram_token=... "
                      "--opcao telegram_chat=...).")
            elif mensagem is None:
                print("[i] Nada acima do nível pedido; nenhum aviso enviado.")
            elif enviar_telegram(*cfg, mensagem):
                print("[+] Aviso enviado ao Telegram.")
            else:
                print("[!] Falha ao enviar ao Telegram (confira token/chat e a rede).")

        if args.atualizar_baseline or primeira_vez:
            salvar_baseline(args.baseline, rel)
            print(f"[+] Baseline gravada em {args.baseline}.")
        return 1 if diff.novos else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
