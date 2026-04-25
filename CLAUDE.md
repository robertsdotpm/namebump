# namebump — project instructions

## Python compatibility

`requires-python = ">=3.5"` is intentional and must not be changed. Do not raise the minimum Python version under any circumstances.

## Dependency versions

Never add version pins to package dependencies in `setup.py`, `pyproject.toml`, or any requirements file. List packages by name only (e.g. `"ecdsa"` not `"ecdsa>=0.18"`). The only version constraint that may appear is `python_requires=">=3.5"`.

## String formatting

Never use f-string literals (`f"..."`). They require Python 3.6+ and break the 3.5 constraint. Use `.format()` or import and use `fstr(template, args_tuple)` from `aionetiface.utility.utils`:

```python
"value is {}".format(val)
fstr("value is {0}", (val,))
```

## Naming

Never use leading-underscore names for variables, attributes, methods, or functions (e.g. no `_foo`, `_cancel_tasks`, `_private`). Use plain names. The single exception is dunder names (`__init__`, `__all__`, etc.) which are required by Python itself.

## Print statements

Never remove or comment out `print()` calls. They are intentional debugging and observability hooks — leave them exactly as found.

## Error handling

- Use `ValueError` for invalid input at API boundaries.
- Use `AssertionError` (or bare `assert`) for internal invariants that should never be false.
- Do not use `RuntimeError` as a catch-all for invariant violations.
- All SQL user values must go through parameter placeholders (`%s`) — never interpolate user data into SQL strings.
- Pick one error idiom per function: either return a sentinel value or raise — not both.

## Writing tests

**Never use pytest-specific code.** All tests use `unittest` with `AsyncTestCase` from `aionetiface.testing`.

### The required pattern

```python
import unittest
from aionetiface.testing import AsyncTestCase

class TestMyFeature(AsyncTestCase):
    async def asyncSetUp(self):
        self.client = await start_something()

    async def asyncTearDown(self):
        await self.client.close()

    async def test_something(self):
        result = await self.client.do_thing()
        self.assertEqual(result, expected)

    async def test_skip_example(self):
        if condition:
            self.skipTest("reason")
        ...
```

### Rules

- Base class is always `AsyncTestCase` — never `unittest.TestCase`, `unittest.IsolatedAsyncioTestCase`, or any pytest class.
- Test methods are `async def` coroutines.
- Use `self.skipTest("reason")` — never `pytest.skip(...)`.
- Never import `pytest`. Never use `@pytest.mark.*` decorators.
- `aionetiface.testing` handles event loop setup, linecache no-op, and Windows firewall automatically on import.

### Running tests

Pull all four repos first:

```cmd
cd C:\Users\<user>\projects\p2pd && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\aionetiface && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\namebump && git fetch origin && git reset --hard origin/main
cd C:\Users\<user>\projects\sidewire && git fetch origin && git reset --hard origin/main
```

Run with `unittest discover`:

```sh
python -m unittest discover -s tests -p "test_*.py" -v
```

### Install quirks (Python 3.5)

```sh
pip install wheel "setuptools<50"
pip install --no-build-isolation --no-deps -e .
pip install --no-build-isolation --no-deps -e ../aionetiface
```

On Python 3.5.0 specifically:

```sh
pip install "pathlib2==2.2.1" "pytest==4.6.11"
```

If pip was accidentally upgraded past 21.x on a 3.5.0 interpreter:

```sh
python -m ensurepip
python -m pip install "pip==20.3.4" "setuptools<50"
```
