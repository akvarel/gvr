from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import secrets
from typing import Any, Mapping

from .canonical import canonical_fingerprint, canonical_json

PROVIDER_IMPLEMENTATION_REGISTRY_FINGERPRINT_FORMAT = "gvr.provider_implementation_registry.v2"
_PROVIDER_ORIGIN_FORMAT = "gvr.provider_origin_attestation.v1"
_BUILTIN_CONFIGURATION_IDENTITY = "gvr.builtin_provider_adapters.v1"
_CONSTRUCTION_TOKEN = object()
_BUILTIN_SECRET = hashlib.sha256(b"gvr.provider-origin.builtin-adapter-authority.v1").digest()


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
        return {"family_id": self.family_id, "implementation_ids": self.implementation_ids, "trust_state": self.trust_state.value}


class ProviderOriginAuthority:
    """Opaque runtime authority. Descriptive provider fields never create one."""

    __slots__ = ("configuration_identity", "_secret", "_builtin")

    def __init__(self, configuration_identity: str, secret: bytes, builtin: bool, *, _token: object) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise TypeError("provider origin authorities are created by an authorized runtime")
        if not configuration_identity:
            raise ValueError("provider origin configuration identity must be non-empty")
        self.configuration_identity = str(configuration_identity)
        self._secret = secret
        self._builtin = builtin

    @classmethod
    def host_runtime(cls, configuration_identity: str) -> "ProviderOriginAuthority":
        return cls(str(configuration_identity), secrets.token_bytes(32), False, _token=_CONSTRUCTION_TOKEN)

    def _seal(self, document: Mapping[str, Any]) -> str:
        encoded = canonical_json(document, fingerprint_format=_PROVIDER_ORIGIN_FORMAT)
        return hmac.new(self._secret, encoded.encode("utf-8"), hashlib.sha256).hexdigest()


_BUILTIN_AUTHORITY = ProviderOriginAuthority(_BUILTIN_CONFIGURATION_IDENTITY, _BUILTIN_SECRET, True, _token=_CONSTRUCTION_TOKEN)


@dataclass(frozen=True)
class ProviderImplementationRegistration:
    implementation_id: str
    provider_kind: str
    family_id: str

    def __post_init__(self) -> None:
        if not self.implementation_id or not self.provider_kind or not self.family_id:
            raise ValueError("provider implementation registration fields must be non-empty")
        object.__setattr__(self, "implementation_id", str(self.implementation_id))
        object.__setattr__(self, "provider_kind", str(self.provider_kind))
        object.__setattr__(self, "family_id", str(self.family_id))

    @property
    def family(self) -> VerifiedIndependenceFamily:
        return VerifiedIndependenceFamily(self.family_id, (self.implementation_id,), IndependenceTrustState.VERIFIED)

    def to_dict(self) -> dict[str, str]:
        return {"implementation_id": self.implementation_id, "provider_kind": self.provider_kind, "family_id": self.family_id}


class ProviderOriginAttestation:
    __slots__ = ("provider_kind", "implementation_id", "family", "configuration_identity", "registry_fingerprint", "seal")

    def __init__(self, *, provider_kind: str, implementation_id: str, family: VerifiedIndependenceFamily,
                 configuration_identity: str, registry_fingerprint: str, seal: str, _token: object) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise TypeError("provider origin attestations are issued by a sealed authority")
        self.provider_kind = provider_kind
        self.implementation_id = implementation_id
        self.family = family
        self.configuration_identity = configuration_identity
        self.registry_fingerprint = registry_fingerprint
        self.seal = seal

    @property
    def trust_state(self) -> IndependenceTrustState:
        return self.family.trust_state

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_dict(), "seal": self.seal}

    def _unsigned_dict(self) -> dict[str, object]:
        return {
            "format": _PROVIDER_ORIGIN_FORMAT,
            "provider_kind": self.provider_kind,
            "implementation_id": self.implementation_id,
            "family": self.family.to_dict(),
            "configuration_identity": self.configuration_identity,
            "registry_fingerprint": self.registry_fingerprint,
        }


@dataclass(frozen=True)
class ProviderImplementationRegistry:
    registrations: tuple[ProviderImplementationRegistration, ...] = ()
    configuration_identity: str = "untrusted"
    _authority: ProviderOriginAuthority | None = field(default=None, repr=False, compare=False)
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        registrations = tuple(sorted(self.registrations, key=lambda item: (item.provider_kind, item.implementation_id, item.family_id)))
        keys: dict[tuple[str, str], ProviderImplementationRegistration] = {}
        for item in registrations:
            key = (item.provider_kind, item.implementation_id)
            if key in keys and keys[key] != item:
                raise ValueError("conflicting provider implementation registration")
            keys[key] = item
        if self._authority is not None and self.configuration_identity != self._authority.configuration_identity:
            raise ValueError("registry configuration identity does not match authority")
        object.__setattr__(self, "registrations", tuple(keys[key] for key in sorted(keys)))
        object.__setattr__(self, "fingerprint", canonical_fingerprint(self.to_dict(), fingerprint_format=PROVIDER_IMPLEMENTATION_REGISTRY_FINGERPRINT_FORMAT))

    @classmethod
    def host_runtime(cls, authority: ProviderOriginAuthority) -> "ProviderImplementationRegistry":
        if not isinstance(authority, ProviderOriginAuthority) or authority._builtin:
            raise ValueError("custom registry requires host/runtime authority")
        return cls(configuration_identity=authority.configuration_identity, _authority=authority)

    def to_dict(self) -> dict[str, object]:
        return {"registrations": [item.to_dict() for item in self.registrations], "configuration_identity": self.configuration_identity}

    def with_registration(self, *, implementation_id: str, provider_kind: str,
                          family_id: str | None = None, authority: ProviderOriginAuthority | None = None,
                          family: VerifiedIndependenceFamily | None = None) -> "ProviderImplementationRegistry":
        # Legacy caller-built families and registries are intentionally non-authoritative.
        if authority is None or authority is not self._authority:
            if family_id is not None and family is None and self._authority is None:
                return self
            raise ValueError("provider registration requires matching host/runtime authority")
        resolved_family = str(family_id or (family.family_id if family is not None else ""))
        if not resolved_family:
            raise ValueError("provider registration family_id must be non-empty")
        return ProviderImplementationRegistry(
            registrations=self.registrations + (ProviderImplementationRegistration(implementation_id, provider_kind, resolved_family),),
            configuration_identity=self.configuration_identity,
            _authority=self._authority,
        )

    def resolve(self, identity: object) -> VerifiedIndependenceFamily:
        return VerifiedIndependenceFamily(
            str(getattr(identity, "family_id", "")) or str(getattr(identity, "provider_id", "")) or "unverified",
            (), IndependenceTrustState.UNVERIFIED,
        )

    def attest(self, identity: object, *, authority: ProviderOriginAuthority | None = None) -> ProviderOriginAttestation:
        if self._authority is None or authority is not self._authority:
            return self._unverified_attestation(identity)
        registration = self._registration(identity)
        if registration is None:
            return self._unverified_attestation(identity)
        return self._issue(identity, registration.family)

    def _registration(self, identity: object) -> ProviderImplementationRegistration | None:
        key = (str(getattr(identity, "provider_kind", "")), str(getattr(identity, "implementation_id", "")))
        return next((item for item in self.registrations if (item.provider_kind, item.implementation_id) == key), None)

    def _issue(self, identity: object, family: VerifiedIndependenceFamily) -> ProviderOriginAttestation:
        assert self._authority is not None
        unsigned = {
            "format": _PROVIDER_ORIGIN_FORMAT,
            "provider_kind": str(getattr(identity, "provider_kind", "")),
            "implementation_id": str(getattr(identity, "implementation_id", "")),
            "family": family.to_dict(),
            "configuration_identity": self.configuration_identity,
            "registry_fingerprint": self.fingerprint,
        }
        return ProviderOriginAttestation(
            provider_kind=unsigned["provider_kind"], implementation_id=unsigned["implementation_id"],
            family=family, configuration_identity=unsigned["configuration_identity"],
            registry_fingerprint=unsigned["registry_fingerprint"], seal=self._authority._seal(unsigned),
            _token=_CONSTRUCTION_TOKEN,
        )

    def _unverified_attestation(self, identity: object) -> ProviderOriginAttestation:
        family = self.resolve(identity)
        unsigned = {
            "format": _PROVIDER_ORIGIN_FORMAT,
            "provider_kind": str(getattr(identity, "provider_kind", "")),
            "implementation_id": str(getattr(identity, "implementation_id", "")),
            "family": family.to_dict(),
            "configuration_identity": "untrusted",
            "registry_fingerprint": self.fingerprint,
        }
        return ProviderOriginAttestation(
            provider_kind=unsigned["provider_kind"], implementation_id=unsigned["implementation_id"],
            family=family, configuration_identity=unsigned["configuration_identity"],
            registry_fingerprint=unsigned["registry_fingerprint"], seal="", _token=_CONSTRUCTION_TOKEN,
        )

    def validate(self, identity: object, document: Mapping[str, Any]) -> ProviderOriginAttestation:
        configuration = str(document.get("configuration_identity", ""))
        registry_fingerprint = str(document.get("registry_fingerprint", ""))
        if configuration != self.configuration_identity:
            raise ValueError("provider origin configuration identity mismatch")
        if registry_fingerprint != self.fingerprint:
            raise ValueError("provider origin registry fingerprint mismatch")
        registration = self._registration(identity)
        if self._authority is not None and self._authority._builtin:
            kind = str(getattr(identity, "provider_kind", ""))
            implementation_id = str(getattr(identity, "implementation_id", ""))
            registration = (
                ProviderImplementationRegistration(implementation_id, kind, kind)
                if kind in {"graphify", "codeflow"} and implementation_id
                else None
            )
        if registration is None or self._authority is None:
            raise ValueError("provider origin is not authorized by this registry")
        expected = self._issue(identity, registration.family)
        same_document = canonical_json(document, fingerprint_format=_PROVIDER_ORIGIN_FORMAT) == canonical_json(
            expected.to_dict(), fingerprint_format=_PROVIDER_ORIGIN_FORMAT
        )
        if not hmac.compare_digest(str(document.get("seal", "")), expected.seal) or not same_document:
            raise ValueError("provider origin attestation seal mismatch")
        return expected


def builtin_provider_implementation_registry() -> ProviderImplementationRegistry:
    return ProviderImplementationRegistry(
        registrations=(
            ProviderImplementationRegistration("codeflow", "codeflow", "codeflow"),
            ProviderImplementationRegistration("graphify", "graphify", "graphify"),
        ),
        configuration_identity=_BUILTIN_CONFIGURATION_IDENTITY,
        _authority=_BUILTIN_AUTHORITY,
    )


def _attest_builtin_provider_origin(identity: object, *, adapter_kind: str) -> ProviderOriginAttestation:
    if str(getattr(identity, "provider_kind", "")) != adapter_kind:
        raise ValueError("built-in adapter origin kind mismatch")
    registry = BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY
    implementation_id = str(getattr(identity, "implementation_id", ""))
    if adapter_kind not in {"graphify", "codeflow"} or not implementation_id:
        raise ValueError("unknown built-in adapter implementation")
    family = VerifiedIndependenceFamily(adapter_kind, (implementation_id,), IndependenceTrustState.VERIFIED)
    return registry._issue(identity, family)


BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY = builtin_provider_implementation_registry()
