"""Gemini retries: one quota slot per real request, no asking a model that just
said 404/429 again. Run: python tests/test_agent.py"""

import asyncio
import sys
import types as T
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ai.agent as ag  # noqa: E402
from core.config import Config  # noqa: E402

MAIN, FALLBACK = "main-model", "fallback-model"


class Err(Exception):
    def __init__(self, code):
        super().__init__(str(code))
        self.code = code


def run(behaviour, fallback=FALLBACK, budget=99):
    """(answer, models asked, quota slots taken) for one _generate call."""
    ag.types = T.SimpleNamespace(GenerateContentConfig=lambda **kw: kw)
    c = Config()
    c.GEMINI_API_KEY, c.GEMINI_TIMEOUT = "x", 0.2
    c.GEMINI_MODEL, c.GEMINI_FALLBACK_MODEL = MAIN, fallback
    a = ag.MariAgent(c)
    a.enabled, calls, slots = True, [], []

    async def generate_content(model, contents, config):
        calls.append(model)
        if isinstance(behaviour[model], int):
            raise Err(behaviour[model])
        return T.SimpleNamespace(text="ok-" + model)

    async def reserve(r):
        slots.append(r)
        return len(slots) <= budget

    a._client = T.SimpleNamespace(aio=T.SimpleNamespace(models=T.SimpleNamespace(generate_content=generate_content)))
    a._reserve_slot = reserve
    return asyncio.run(a._generate("system", "prompt")), calls, len(slots)


def test_every_request_takes_a_quota_slot():
    assert run({MAIN: "ok"}) == ("ok-" + MAIN, [MAIN], 1)
    assert run({MAIN: 503, FALLBACK: "ok"}) == ("ok-" + FALLBACK, [MAIN, FALLBACK], 2)
    assert run({MAIN: 503, FALLBACK: 503}) == (None, [MAIN, FALLBACK, MAIN], 3)
    assert run({MAIN: 503, FALLBACK: "ok"}, budget=1) == (None, [MAIN], 2)  # budget gone: stop


def test_a_model_out_of_quota_or_retired_is_not_asked_again():
    assert run({MAIN: 429, FALLBACK: 503}) == (None, [MAIN, FALLBACK], 2)
    assert run({MAIN: 404, FALLBACK: "ok"}) == ("ok-" + FALLBACK, [MAIN, FALLBACK], 2)
    assert run({MAIN: 400, FALLBACK: "ok"}) == (None, [MAIN], 1)  # a bad request: no retry at all


if __name__ == "__main__":
    tests = [f for name, f in dict(globals()).items() if name.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} passed")
