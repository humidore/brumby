from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    name: str
    value: Any
    source: str | None = None  # artifact filename
    resource: str | None = None  # like-for-like grouping key, e.g. wheel/sdist

    def __hash__(self) -> int:
        return hash((self.name, self.value, self.source, self.resource))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self.name == other.name
            and self.value == other.value
            and self.source == other.source
            and self.resource == other.resource
        )

    def __str__(self) -> str:
        if self.value is True:
            return self.name
        return f"{self.name}={self.value}"
