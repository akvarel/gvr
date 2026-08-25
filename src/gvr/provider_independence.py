from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import secrets
from typing import Any, Iterator, Mapping, TYPE_CHECKING

from .canonical import canonical_fingerprint, canonical_json

if TYPE_CHECKING:
    from .code_graph import GraphEvidenceModel
    from .model import Evidence

PROVIDER_IMPLEMENTATION_REGISTRY_FINGERPRINT_FORMAT = "gvr.provider_implementation_registry.v3"
_PROVIDER_ORIGIN_FORMAT = "gvr.provider_origin_assertion.v2"
_UNTRUSTED_CONFIGURATION = "untrusted"
_CONSTRUCTION_TOKEN = object()


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


class ProviderOriginAssertion:
    """Serializable claim about provider origin. It is not trusted until validated."""

    __slots__ = ("provider_kind", "implementation_id", "family", "configuration_identity", "registry_fingerprint", "context_key_id", "seal")

    def __init__(
        self,
        *,
        provider_kind: str,
        implementation_id: str,
        family: VerifiedIndependenceFamily,
        configuration_identity: str,
        registry_fingerprint: str,
        context_key_id: str,
        seal: str,
        _token: object,
    ) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise TypeError("provider origin assertions are constructed by GVR trust machinery")
        self.provider_kind = str(provider_kind)
        self.implementation_id = str(implementation_id)
        self.family = family
        self.configuration_identity = str(configuration_identity)
        self.registry_fingerprint = str(registry_fingerprint)
        self.context_key_id = str(context_key_id)
        self.seal = str(seal)

    @property
    def trust_state(self) -> IndependenceTrustState:
        return self.family.trust_state

    def _unsigned_dict(self) -> dict[str, object]:
        return {
            "format": _PROVIDER_ORIGIN_FORMAT,
            "provider_kind": self.provider_kind,
            "implementation_id": self.implementation_id,
            "family": self.family.to_dict(),
            "configuration_identity": self.configuration_identity,
            "registry_fingerprint": self.registry_fingerprint,
            "context_key_id": self.context_key_id,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_dict(), "seal": self.seal}


class ValidatedProviderOrigin:
    """Non-serializable result of validation by the active trust context."""

    __slots__ = ("assertion", "_validation_token")

    def __init__(self, assertion: ProviderOriginAssertion, *, _token: object) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise TypeError("validated provider origins are created by an active ProviderTrustContext")
        self.assertion = assertion
        self._validation_token = object()

    @property
    def family(self) -> VerifiedIndependenceFamily:
        return self.assertion.family

    @property
    def trust_state(self) -> IndependenceTrustState:
        return self.family.trust_state

    @property
    def provider_kind(self) -> str:
        return self.assertion.provider_kind

    @property
    def implementation_id(self) -> str:
        return self.assertion.implementation_id


_BUILTIN_REGISTRATIONS = (
    ProviderImplementationRegistration("codeflow", "codeflow", "codeflow"),
    ProviderImplementationRegistration("graphify", "graphify", "graphify"),
)


@dataclass(frozen=True)
class ProviderImplementationRegistry:
    """Descriptive registry. It cannot issue or validate trust on its own."""

    registrations: tuple[ProviderImplementationRegistration, ...] = ()
    configuration_identity: str = _UNTRUSTED_CONFIGURATION
    fingerprint: str = ""

    def __post_init__(self) -> None:
        registrations = tuple(sorted(self.registrations, key=lambda item: (item.provider_kind, item.implementation_id, item.family_id)))
        keys: dict[tuple[str, str], ProviderImplementationRegistration] = {}
        for item in registrations:
            key = (item.provider_kind, item.implementation_id)
            if key in keys and keys[key] != item:
                raise ValueError("conflicting provider implementation registration")
            keys[key] = item
        object.__setattr__(self, "registrations", tuple(keys[key] for key in sorted(keys)))
        document = {"registrations": [item.to_dict() for item in self.registrations], "configuration_identity": str(self.configuration_identity)}
        object.__setattr__(self, "configuration_identity", str(self.configuration_identity))
        object.__setattr__(self, "fingerprint", canonical_fingerprint(document, fingerprint_format=PROVIDER_IMPLEMENTATION_REGISTRY_FINGERPRINT_FORMAT))

    def to_dict(self) -> dict[str, object]:
        return {"registrations": [item.to_dict() for item in self.registrations], "configuration_identity": self.configuration_identity}

    def with_registration(self, *, implementation_id: str, provider_kind: str, family_id: str | None = None, **_: object) -> "ProviderImplementationRegistry":
        # Public registries remain descriptive and cannot create authority.
        if family_id is None:
            return self
        return ProviderImplementationRegistry(self.registrations + (ProviderImplementationRegistration(implementation_id, provider_kind, family_id),), self.configuration_identity)

    def resolve(self, identity: object) -> VerifiedIndependenceFamily:
        return _unverified_family(identity)


class _AdapterCapability:
    __slots__ = ("context", "adapter_kind")

    def __init__(self, context: "ProviderTrustContext", adapter_kind: str) -> None:
        self.context = context
        self.adapter_kind = adapter_kind


@dataclass(frozen=True)
class _ActiveTrust:
    context: "ProviderTrustContext"
    capabilities: Mapping[str, _AdapterCapability]


_ACTIVE_TRUST: ContextVar[_ActiveTrust | None] = ContextVar("gvr_provider_trust_context", default=None)


class ProviderTrustContext:
    """Host/runtime-owned provider trust with an explicit activation lifetime.

    The random signing key never appears in public APIs or serialized evidence.
    This boundary prevents offline forgery by untrusted evidence producers. It is
    not a sandbox against malicious code already executing in the trusted host
    process, which can inspect Python objects or invoke private implementation
    details. Hosts must keep untrusted plugins outside that process boundary.
    """

    __slots__ = ("configuration_identity", "registry", "_key", "_key_id", "_capabilities")

    def __init__(self, configuration_identity: str, registrations: tuple[ProviderImplementationRegistration, ...], *, _token: object) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise TypeError("ProviderTrustContext instances are created by host_runtime()")
        if not configuration_identity:
            raise ValueError("provider trust configuration identity must be non-empty")
        self.configuration_identity = str(configuration_identity)
        self.registry = ProviderImplementationRegistry(_BUILTIN_REGISTRATIONS + tuple(registrations), self.configuration_identity)
        self._key = secrets.token_bytes(32)
        self._key_id = hashlib.sha256(self._key).hexdigest()
        self._capabilities = {kind: _AdapterCapability(self, kind) for kind in ("graphify", "codeflow")}

    @classmethod
    def host_runtime(
        cls,
        configuration_identity: str,
        *,
        registrations: tuple[ProviderImplementationRegistration, ...] = (),
    ) -> "ProviderTrustContext":
        return cls(str(configuration_identity), tuple(registrations), _token=_CONSTRUCTION_TOKEN)

    @contextmanager
    def activate(self) -> Iterator["ProviderTrustContext"]:
        token = _ACTIVE_TRUST.set(_ActiveTrust(self, self._capabilities))
        try:
            yield self
        finally:
            _ACTIVE_TRUST.reset(token)

    def encode_code_graph_observation_evidence(self, graph_model: "GraphEvidenceModel", **kwargs: Any) -> "Evidence":
        from .code_graph import _encode_code_graph_observation_evidence

        if _active_context() is not self:
            raise RuntimeError("ProviderTrustContext must be active while encoding trusted provider evidence")
        assertion = self._issue_registered(graph_model.provider_identity)
        return _encode_code_graph_observation_evidence(graph_model, _validated_origin=assertion, **kwargs)

    def _seal(self, document: Mapping[str, Any]) -> str:
        encoded = canonical_json(document, fingerprint_format=_PROVIDER_ORIGIN_FORMAT)
        return hmac.new(self._key, encoded.encode("utf-8"), hashlib.sha256).hexdigest()

    def _registration(self, identity: object) -> ProviderImplementationRegistration | None:
        key = (str(getattr(identity, "provider_kind", "")), str(getattr(identity, "implementation_id", "")))
        return next((item for item in self.registry.registrations if (item.provider_kind, item.implementation_id) == key), None)

    def _issue_registered(self, identity: object) -> ProviderOriginAssertion:
        registration = self._registration(identity)
        if registration is None or registration.provider_kind in {"graphify", "codeflow"}:
            return _unverified_assertion(identity)
        return self._issue(identity, registration.family)

    def _issue_builtin(self, identity: object, capability: _AdapterCapability) -> ProviderOriginAssertion:
        if capability.context is not self or capability is not self._capabilities.get(capability.adapter_kind):
            raise RuntimeError("invalid built-in provider capability")
        if str(getattr(identity, "provider_kind", "")) != capability.adapter_kind:
            raise ValueError("built-in adapter origin kind mismatch")
        registration = self._registration(identity)
        if registration is None or registration.provider_kind != capability.adapter_kind:
            raise ValueError("unknown built-in adapter implementation")
        return self._issue(identity, registration.family)

    def _issue(self, identity: object, family: VerifiedIndependenceFamily) -> ProviderOriginAssertion:
        assertion = ProviderOriginAssertion(
            provider_kind=str(getattr(identity, "provider_kind", "")),
            implementation_id=str(getattr(identity, "implementation_id", "")),
            family=family,
            configuration_identity=self.configuration_identity,
            registry_fingerprint=self.registry.fingerprint,
            context_key_id=self._key_id,
            seal="",
            _token=_CONSTRUCTION_TOKEN,
        )
        return ProviderOriginAssertion(
            provider_kind=assertion.provider_kind,
            implementation_id=assertion.implementation_id,
            family=assertion.family,
            configuration_identity=assertion.configuration_identity,
            registry_fingerprint=assertion.registry_fingerprint,
            context_key_id=assertion.context_key_id,
            seal=self._seal(assertion._unsigned_dict()),
            _token=_CONSTRUCTION_TOKEN,
        )

    def validate(self, identity: object, document: Mapping[str, Any]) -> ValidatedProviderOrigin:
        if str(document.get("configuration_identity", "")) != self.configuration_identity:
            raise ValueError("provider origin configuration identity mismatch")
        if str(document.get("registry_fingerprint", "")) != self.registry.fingerprint:
            raise ValueError("provider origin registry fingerprint mismatch")
        if str(document.get("context_key_id", "")) != self._key_id:
            raise ValueError("provider origin context key mismatch")
        registration = self._registration(identity)
        if registration is None:
            raise ValueError("provider origin is not authorized by this context")
        expected = self._issue(identity, registration.family)
        same_document = canonical_json(document, fingerprint_format=_PROVIDER_ORIGIN_FORMAT) == canonical_json(expected.to_dict(), fingerprint_format=_PROVIDER_ORIGIN_FORMAT)
        if not hmac.compare_digest(str(document.get("seal", "")), expected.seal) or not same_document:
            raise ValueError("provider origin assertion seal mismatch")
        return ValidatedProviderOrigin(expected, _token=_CONSTRUCTION_TOKEN)


def _active_context() -> ProviderTrustContext | None:
    active = _ACTIVE_TRUST.get()
    return None if active is None else active.context


def _attest_active_builtin_provider_origin(identity: object, *, adapter_kind: str) -> ProviderOriginAssertion:
    active = _ACTIVE_TRUST.get()
    if active is None:
        return _unverified_assertion(identity)
    capability = active.capabilities.get(adapter_kind)
    if capability is None:
        raise RuntimeError("active ProviderTrustContext lacks built-in adapter capability")
    return active.context._issue_builtin(identity, capability)


def _validate_recorded_provider_origin(identity: object, document: Mapping[str, Any]) -> tuple[ProviderOriginAssertion, ValidatedProviderOrigin | None]:
    if str(document.get("configuration_identity", "")) == _UNTRUSTED_CONFIGURATION:
        expected = _unverified_assertion(identity)
        if canonical_json(document, fingerprint_format=_PROVIDER_ORIGIN_FORMAT) != canonical_json(expected.to_dict(), fingerprint_format=_PROVIDER_ORIGIN_FORMAT):
            raise ValueError("unverified provider origin mismatch")
        return expected, None
    context = _active_context()
    if context is None:
        raise ValueError("verified provider origin requires an active ProviderTrustContext")
    validated = context.validate(identity, document)
    return validated.assertion, validated


def _unverified_family(identity: object) -> VerifiedIndependenceFamily:
    return VerifiedIndependenceFamily(
        str(getattr(identity, "family_id", "")) or str(getattr(identity, "provider_id", "")) or "unverified",
        (),
        IndependenceTrustState.UNVERIFIED,
    )


def _unverified_assertion(identity: object) -> ProviderOriginAssertion:
    family = _unverified_family(identity)
    registry = ProviderImplementationRegistry()
    return ProviderOriginAssertion(
        provider_kind=str(getattr(identity, "provider_kind", "")),
        implementation_id=str(getattr(identity, "implementation_id", "")),
        family=family,
        configuration_identity=_UNTRUSTED_CONFIGURATION,
        registry_fingerprint=registry.fingerprint,
        context_key_id="",
        seal="",
        _token=_CONSTRUCTION_TOKEN,
    )


def builtin_provider_implementation_registry() -> ProviderImplementationRegistry:
    return ProviderImplementationRegistry(_BUILTIN_REGISTRATIONS, "builtin-descriptive")


BUILTIN_PROVIDER_IMPLEMENTATION_REGISTRY = builtin_provider_implementation_registry()
