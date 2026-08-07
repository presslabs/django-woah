import inspect
from functools import wraps
from typing import Any, Callable


def get_cache_key(
    func: Callable,
    args: tuple,
    kwargs: dict,
    stringify: bool = True,
    include_defaults: bool = True,
    ignore: tuple = ("self", "cls"),
) -> Any:
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    if include_defaults:
        bound.apply_defaults()

    arguments = {k: v for k, v in bound.arguments.items() if k not in ignore}
    identity = f"{func.__module__}.{func.__qualname__}"
    frozen = (identity, _freeze(arguments))

    return repr(frozen) if stringify else frozen


def _freeze(obj):
    if type(obj).__hash__ is not None:
        return obj

    if isinstance(obj, dict):
        return tuple(sorted((str(k), _freeze(v)) for k, v in obj.items()))

    if isinstance(obj, (list, tuple, set, frozenset)):
        return tuple(_freeze(v) for v in obj)

    return f"{type(obj).__module__}.{type(obj).__qualname__}:{obj!r}"


def cached(func=None, *, key_func=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(self, *args, **kwargs):
            key = (
                key_func(self, *args, **kwargs)
                if key_func
                else get_cache_key(fn, (self, *args), kwargs, stringify=False)
            )

            try:
                cache = self._cache
            except AttributeError:
                cache = self._cache = {}

            try:
                result = cache[key]
            except KeyError:
                result = cache[key] = fn(self, *args, **kwargs)

            return result

        return wrapper

    return decorator(func) if func else decorator
