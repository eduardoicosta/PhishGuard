"""
PhishGuard — Camada de Resiliência Operacional.

O motivo desta camada existir: a Camada 2 (Gemini) é uma dependência externa
sobre a qual não temos controle de latência nem de disponibilidade. Sem
proteção, um incidente do provedor vira um incidente do PhishGuard — a extensão
trava, o banner fica preso em "analisando" e o usuário perde a proteção.

Três mecanismos, do mais simples ao mais estrutural:

1. Timeout duro por tentativa — nenhuma requisição do usuário fica pendurada.
2. Retry com backoff exponencial e jitter — absorve falhas transitórias (429,
   503, reset de conexão) sem amplificar a carga sobre o provedor.
3. Circuit breaker — após N falhas consecutivas o circuito abre e as chamadas
   passam a falhar *instantaneamente* para o fallback local, em vez de gastar o
   timeout inteiro de cada usuário. Fecha sozinho após o período de recuperação.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Optional, Tuple, Type

logger = logging.getLogger("phishguard.resiliencia")


class CircuitoAberto(RuntimeError):
    """Sinaliza que a dependência externa está isolada e o fallback deve agir."""


class EstadoCircuito(str, Enum):
    FECHADO = "fechado"        # operação normal
    ABERTO = "aberto"          # dependência isolada, chamadas rejeitadas
    MEIO_ABERTO = "meio_aberto"  # uma chamada de teste é permitida


@dataclass
class CircuitBreaker:
    """
    Circuit breaker mínimo e thread-safe o bastante para uso com asyncio.

    `limite_falhas` falhas consecutivas abrem o circuito por
    `segundos_recuperacao`. A primeira chamada após esse período é de teste
    (meio-aberto): se passar, o circuito fecha; se falhar, reabre.
    """

    nome: str
    limite_falhas: int = 5
    segundos_recuperacao: float = 30.0

    _falhas: int = 0
    _aberto_em: float = 0.0
    _estado: EstadoCircuito = EstadoCircuito.FECHADO

    @property
    def estado(self) -> EstadoCircuito:
        if (
            self._estado is EstadoCircuito.ABERTO
            and (time.monotonic() - self._aberto_em) >= self.segundos_recuperacao
        ):
            self._estado = EstadoCircuito.MEIO_ABERTO
            logger.info("Circuito '%s' em meio-aberto: tentativa de recuperação.", self.nome)
        return self._estado

    def permitir(self) -> bool:
        return self.estado is not EstadoCircuito.ABERTO

    def registrar_sucesso(self) -> None:
        if self._estado is not EstadoCircuito.FECHADO:
            logger.info("Circuito '%s' fechado: dependência recuperada.", self.nome)
        self._falhas = 0
        self._estado = EstadoCircuito.FECHADO

    def registrar_falha(self) -> None:
        self._falhas += 1
        if self._falhas >= self.limite_falhas or self._estado is EstadoCircuito.MEIO_ABERTO:
            self._estado = EstadoCircuito.ABERTO
            self._aberto_em = time.monotonic()
            logger.warning(
                "Circuito '%s' ABERTO após %s falha(s). "
                "Fallback local ativo por %.0fs.",
                self.nome,
                self._falhas,
                self.segundos_recuperacao,
            )

    def diagnostico(self) -> dict:
        return {
            "nome": self.nome,
            "estado": self.estado.value,
            "falhas_consecutivas": self._falhas,
            "limite_falhas": self.limite_falhas,
            "segundos_recuperacao": self.segundos_recuperacao,
        }


async def executar_com_resiliencia(
    funcao_sincrona: Callable[..., Any],
    *argumentos: Any,
    timeout_s: float = 12.0,
    tentativas: int = 2,
    backoff_base_s: float = 0.4,
    breaker: Optional[CircuitBreaker] = None,
    excecoes_reprocessaveis: Tuple[Type[BaseException], ...] = (Exception,),
    rotulo: str = "dependencia_externa",
) -> Any:
    """
    Executa uma função bloqueante em thread separada com timeout, retry e breaker.

    Levanta `CircuitoAberto` (imediato) quando o circuito está aberto, ou a
    última exceção observada quando todas as tentativas se esgotam. Em ambos os
    casos o chamador cai no fallback local — o usuário nunca fica sem veredito.
    """
    if breaker is not None and not breaker.permitir():
        raise CircuitoAberto(
            f"Circuito '{breaker.nome}' aberto; usando análise local."
        )

    ultima_excecao: Optional[BaseException] = None

    for tentativa in range(1, max(1, tentativas) + 1):
        inicio = time.monotonic()
        try:
            resultado = await asyncio.wait_for(
                asyncio.to_thread(funcao_sincrona, *argumentos), timeout=timeout_s
            )
            if breaker is not None:
                breaker.registrar_sucesso()
            return resultado
        except asyncio.CancelledError:
            # Cancelamento vem do cliente (navegação rápida), não é falha nossa:
            # propaga sem contaminar o circuito.
            raise
        except (asyncio.TimeoutError, *excecoes_reprocessaveis) as erro:
            ultima_excecao = erro
            decorrido_ms = int((time.monotonic() - inicio) * 1000)
            logger.warning(
                "%s: tentativa %s/%s falhou em %sms (%s: %s)",
                rotulo,
                tentativa,
                tentativas,
                decorrido_ms,
                type(erro).__name__,
                erro,
            )
            if tentativa < tentativas:
                espera = backoff_base_s * (2 ** (tentativa - 1))
                espera += random.uniform(0, backoff_base_s)  # jitter anti-tempestade
                await asyncio.sleep(espera)

    if breaker is not None:
        breaker.registrar_falha()

    assert ultima_excecao is not None
    raise ultima_excecao


class MedidorLatencia:
    """Cronômetro de contexto para instrumentar o caminho crítico."""

    def __init__(self) -> None:
        self._inicio = time.monotonic()

    def __enter__(self) -> "MedidorLatencia":
        self._inicio = time.monotonic()
        return self

    def __exit__(self, *_excecao: Any) -> None:
        return None

    @property
    def ms(self) -> int:
        return int((time.monotonic() - self._inicio) * 1000)


async def aguardar_com_limite(
    corrotina: Awaitable[Any],
    timeout_s: float,
    padrao: Any = None,
) -> Any:
    """Aguarda uma corrotina com teto de tempo, devolvendo `padrao` se estourar."""
    try:
        return await asyncio.wait_for(corrotina, timeout=timeout_s)
    except asyncio.TimeoutError:
        return padrao
