from dataclasses import dataclass, field
from typing import Any, Callable, Literal


@dataclass
class FinderSpec:
    name: str
    description: str
    fn: Callable
    scope: Literal["artifact", "release", "metadata", "comparison"]
    kind: Literal["informational", "sketchy"] = "informational"
    default_enabled: bool = True
    needs_content: bool = False  # True = must read file bytes (expensive)


_registry: list[FinderSpec] = []


def register(
    name: str,
    description: str,
    scope: Literal["artifact", "release", "metadata", "comparison"] = "artifact",
    kind: Literal["informational", "sketchy"] = "informational",
    default_enabled: bool = True,
    needs_content: bool = False,
) -> Callable:
    def decorator(fn: Callable) -> Callable:
        _registry.append(
            FinderSpec(
                name=name,
                description=description,
                fn=fn,
                scope=scope,
                kind=kind,
                default_enabled=default_enabled,
                needs_content=needs_content,
            )
        )
        return fn
    return decorator


def get_finders(scope: str | None = None) -> list[FinderSpec]:
    if scope is None:
        return list(_registry)
    return [s for s in _registry if s.scope == scope]
