"""Contratos base do framework: severidade, achados e a classe de plugin.

Todo módulo de auditoria/detecção herda de `Plugin` e devolve `Finding`s.
Isso mantém orquestrador, relatório e módulos desacoplados: um módulo novo
só precisa implementar `run()` e devolver achados — o resto é automático.
"""

from __future__ import annotations

import enum
import platform
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Severidade de um achado. IntEnum para permitir ordenação direta."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def rotulo(self) -> str:
        return {
            Severity.INFO: "INFO",
            Severity.LOW: "BAIXA",
            Severity.MEDIUM: "MEDIA",
            Severity.HIGH: "ALTA",
            Severity.CRITICAL: "CRITICA",
        }[self]


@dataclass(frozen=True)
class Finding:
    """Um achado de auditoria. Imutável para não ser alterado após gerado."""

    plugin: str
    titulo: str
    severidade: Severity
    descricao: str
    recurso: str = ""              # o que foi inspecionado (chave, tarefa, host...)
    recomendacao: str = ""         # como corrigir/endurecer
    evidencia: dict[str, Any] = field(default_factory=dict)
    referencia: str = ""           # CIS/MITRE/CVE relacionado, se houver

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severidade"] = self.severidade.rotulo
        return d


@dataclass
class PluginResult:
    """Resultado da execução de um plugin: achados + metadados + erro (se houve)."""

    plugin: str
    findings: list[Finding] = field(default_factory=list)
    erro: str | None = None
    iniciado_em: str = ""
    duracao_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.erro is None


@dataclass
class Contexto:
    """Dados passados a cada plugin na execução (SO, alvo, modo etc.)."""

    alvo: str = "localhost"
    somente_leitura: bool = True
    so: str = field(default_factory=lambda: platform.system())
    opcoes: dict[str, Any] = field(default_factory=dict)


class Plugin(ABC):
    """Classe-base de todo módulo. Subclasses definem `nome`, `descricao` e `run`."""

    nome: str = "plugin-sem-nome"
    descricao: str = ""
    # SOs em que faz sentido rodar ("Windows", "Linux", "Darwin"); vazio = qualquer.
    sistemas: tuple[str, ...] = ()

    def aplicavel(self, ctx: Contexto) -> bool:
        return not self.sistemas or ctx.so in self.sistemas

    @abstractmethod
    def run(self, ctx: Contexto) -> list[Finding]:
        """Executa a auditoria e devolve os achados. Deve ser SÓ LEITURA."""
        raise NotImplementedError

    def finding(self, titulo: str, severidade: Severity, descricao: str, **kw: Any) -> Finding:
        """Atalho para criar um Finding já carimbado com o nome do plugin."""
        return Finding(plugin=self.nome, titulo=titulo, severidade=severidade,
                       descricao=descricao, **kw)


def agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
