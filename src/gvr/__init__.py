from .core import (
    Action,
    Goal,
    GoalSatisfactionVerifier,
    PreconditionsVerifier,
    EffectSupportVerifier,
    Predicate,
    Proposal,
    StateEffect,
    VerificationContext,
    VerifierRegistry,
    default_registry,
    evaluate_predicate,
    simulate,
)
from .dependencies import (
    ClaimDependencyGraph,
    ClaimRecord,
    DependencyCycleError,
    EvidenceRecord,
    UnknownDependencyError,
    stable_fingerprint,
)
from .ledger import ClaimDefinition, ClaimLedger, ClaimStatus, VerificationSnapshot
from .model import (
    Evidence,
    EvidenceState,
    Freshness,
    INDETERMINATE,
    MISSING,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
    combine_verdicts,
)
from .protocol import ProtocolError, handle_request, safe_handle_request
from .text_search import TextSearchAssertion, TextSearchResult, evaluate_text_search
from .wire import SCHEMA_VERSION, decode_markers, envelope

__all__ = [
    "Action", "ClaimDependencyGraph", "ClaimRecord", "DependencyCycleError",
    "ClaimDefinition", "ClaimLedger", "ClaimStatus", "VerificationSnapshot", "Evidence", "EvidenceRecord", "EvidenceState", "Freshness", "Goal",
    "GoalSatisfactionVerifier", "PreconditionsVerifier", "EffectSupportVerifier", "INDETERMINATE", "MISSING", "Predicate",
    "Proposal", "ProtocolError", "handle_request", "safe_handle_request", "SCHEMA_VERSION", "StateEffect", "TextSearchAssertion",
    "TextSearchResult", "UnknownDependencyError", "VerificationContext",
    "VerificationIssue", "VerificationReport", "VerificationVerdict",
    "VerifierRegistry", "combine_verdicts", "decode_markers", "default_registry",
    "envelope", "evaluate_predicate", "evaluate_text_search", "simulate",
    "stable_fingerprint",
]

from .software import Coverage, DeltaKind, FunctionalDeltaItem, FunctionalDeltaResult, FunctionalSnapshot, Observable, RevisionRef, compare_functionality
__all__ += ["Coverage", "DeltaKind", "FunctionalDeltaItem", "FunctionalDeltaResult", "FunctionalSnapshot", "Observable", "RevisionRef", "compare_functionality"]
