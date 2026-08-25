from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from .canonical import canonical_fingerprint

PROVIDER_IMPLEMENTATION_REGISTRY_FINGERPRINT_FORMAT = "gvr.provider_implementation_registry.v1"


class IndependenceTrustState(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class VerifiedIndependenceFamily:
    family_id: str
    implementation_ids: tuple[str, ...] = ()
    trust_state: IndependenceTrustState = IndependenceTrustState.UNVERIFIED

    def __post_init__(self) -> None:
        if not self.family_id:
            raise ValueError("independence family_id must be non-empty")
        object.__setattr__(self, "family_id", str(self.family_id))
        object.__setattr__(self, "implementation_ids", tuple(sorted({str(item) for item in self.implementation_ids if str(item)})))
        object.__setattr__(self, "trust_state", IndependenceTrustState(self.trust_state))

    def to_dict(self) -> dict[str, object]:
        return {
            "family_id": self.family_id,
            "implementation_ids": self.implementation_ids,
            "trust_state": self.trust_state.value,
        }


@dataclass(frozen=True)
class ProviderImplementationRegistration:
    implementation_id: str
    provider_kind: str
    family: VerifiedIndependenceFamily

    def __post_init__(self) -> None:
        if not self.implementation_id or not self.provider_kind:
            raise ValueError("provider implementation registration fields must be non-empty")
        if self.family.trust_state is not IndependenceTrustState.VERIFIED:
            raise ValueError("registered independence families must be VERIFIED")
        if self.family.implementation_ids and self.implementation_id not in self.family.implementation_ids:
            raise ValueError("registered implementation must be bound to its independence family")
        object.__setattr__(self, "implementation_id", str(self.implementation_id))
        object.__setattr__(self, "provider_kind", str(self.provider_kind))

    def to_dict(self) -> dict[str, object]:
        return {
            "implementation_id": self.implementation_id,
            "provider_kind": self.provider_kind,
            "family": self.family.to_dict(),
        }


@dataclass(frozen=True)
class ProviderImplementationRegistry:
    registrations: tuple[ProviderImplementationRegistration, ...] = ()
    sealed_provider_kinds: tuple[tuple[str, str], ...] = ()
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        registrations = tuple(sorted(self.registrations, key=lambda item: (item.provider_kind, item.implementation_id, item.family.family_id)))
        keys: dict[tuple[str, str], ProviderImplementationRegistration] = {}
        for item in registrations:
            key = (item.provider_kind, item.implementation_id)
            existing = keys.get(key)
            if existing is not None and existing != item:
                raise ValueError("conflicting provider implementation registration")
            keys[key] = item
        sealed = tuple(sorted((str(kind), str(family)) for kind, family in self.sealed_provider_kinds))
        object.__setattr__(self, "registrations", tuple(keys[key] for key in sorted(keys)))
        object.__setattr__(self, "sealed_provider_kinds", sealed)
        object.__setattr__(self, "fingerprint", canonical_fingerprint(self.to_dict(), fingerprint_format=PROVIDER_IMPLEMENTATION_REGISTRY_FINGERPRINT_FORMAT))

    def to_dict(self) -> dict[str, object]:
        return {
            "registrations": [item.to_dict() for item in self.registrations],
            "sealed_provider_kinds": self.sealed_provider_kinds,
        }

    def with_registration(
        self,
        *,
        implementation_id: str,
        provider_kind: str,
        family: VerifiedIndependenceFamily,
    ) -> "ProviderImplementationRegistry":
        return ProviderImplementationRegistry(
            registrations=self.registrations + (ProviderImplementationRegistration(implementation_id, provider_kind, family),),
            sealed_provider_kinds=self.sealed_provider_kinds,
        )

    def resolve(self, identity: object) -> VerifiedIndependenceFamily:
        implementation_id = str(getattr(identity, "implementation_id", ""))
        provider_kind = str(getattr(identity, "provider_kind", ""))
        for item in self.registrations:
            if item.implementation_id == implementation_id and item.provider_kind == provider_kind:
                return item.family
        for kind, family_id in self.sealed_provider_kinds:
            if provider_kind == kind and implementation_id:
                return VerifiedIndependenceFamily(family_id, (implementation_id,), IndependenceTrustState.VERIFIED)
        descriptive = str(getattr(identity, "family_id", "")) or str(getattr(identity, "provider_id", "")) or "unverified"
        return VerifiedIndependenceFamily(descriptive, (), IndependenceTrustState.UNVERIFIED)


def builtin_provider_implementation_registry() -> ProviderImplementationRegistry:
    return ProviderImplementationRegistry(sealed_provider_kinds=(("codeflow", "codeflow"), ("graphify", "graphify")))


BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY = builtin_provider_implementation_registry()
