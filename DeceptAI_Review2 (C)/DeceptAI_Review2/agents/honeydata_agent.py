"""Honeydata Agent -- template-based fake data (local stand-in for the base paper's
LLM generator; swap generate() for an LLM call later without touching other agents).
Returns a full fake filesystem: same paths as the real host, fake secrets
(HP-<token>-FAKE-*) so any later use of a stolen secret is recognisable."""
import random
from agents.shell_emulator import honey_overrides


class HoneydataAgent:
    def generate(self, pillar):
        token = f"{random.randint(1000, 9999)}"
        return honey_overrides(pillar, token)
