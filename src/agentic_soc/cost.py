"""Token accounting and pricing, so cost per alert is measured, not estimated.

Prices are USD per million tokens, from the Anthropic pricing page. Cache
multipliers apply to the base input price. Anthropic reports cached tokens
separately from input_tokens, so total input = input + cache writes + cache reads.

Prompt caching is not used: Claude Haiku 4.5 only caches prompt prefixes of at
least 4,096 tokens, and this agent's fixed prefix (system prompt and tool
definitions) is far shorter. Cached-token fields are still recorded so the
numbers stay correct if the model or prompt changes.
"""

from __future__ import annotations

from dataclasses import dataclass

PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    # model: (input, output)
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
}
CACHE_WRITE_MULTIPLIER = 1.25  # 5-minute cache write
CACHE_READ_MULTIPLIER = 0.10


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0

    def add(self, other: Usage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.cache_read_tokens += other.cache_read_tokens

    @property
    def total_input_tokens(self) -> int:
        return self.input_tokens + self.cache_write_tokens + self.cache_read_tokens

    def cost_usd(self, model: str) -> float:
        if model not in PRICES_PER_MTOK:
            raise ValueError(f"no price for model {model!r}; add it to PRICES_PER_MTOK")
        price_in, price_out = PRICES_PER_MTOK[model]
        return (
            self.input_tokens * price_in
            + self.cache_write_tokens * price_in * CACHE_WRITE_MULTIPLIER
            + self.cache_read_tokens * price_in * CACHE_READ_MULTIPLIER
            + self.output_tokens * price_out
        ) / 1_000_000
