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
    evidence_semantic_fingerprint,
    stable_fingerprint,
)
from .bundle import (
    VERIFICATION_BUNDLE_KIND,
    VERIFICATION_BUNDLE_SCHEMA_VERSION,
    BundleValidationError,
    VerificationBundle,
    build_verification_bundle,
    validate_verification_bundle,
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
from .adapters.graphify import GraphifyTraversalEvidence, ingest_traversal_result
from .protocol import ProtocolError, handle_request, safe_handle_request
from .text_search import TextSearchAssertion, TextSearchResult, evaluate_text_search
from .verifiers.data_flow import (
    BLOCKING_RESOLUTIONS,
    COMPLETE_COVERAGE,
    DATA_FLOW_VERIFIER,
    SUPPORTED_DATA_FLOW_RELATIONS,
    DataFlowClaim,
    DataFlowClaimKind,
    DataFlowQueryScope,
    build_query_result_evidence,
    verify_data_flow_claim,
    verify_data_flow_claim_bundle,
)
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
    "stable_fingerprint", "evidence_semantic_fingerprint",
    "GraphifyTraversalEvidence", "ingest_traversal_result",
    "BLOCKING_RESOLUTIONS", "COMPLETE_COVERAGE", "DATA_FLOW_VERIFIER",
    "SUPPORTED_DATA_FLOW_RELATIONS", "DataFlowClaim", "DataFlowClaimKind",
    "DataFlowQueryScope", "build_query_result_evidence", "verify_data_flow_claim",
    "verify_data_flow_claim_bundle", "VERIFICATION_BUNDLE_KIND",
    "VERIFICATION_BUNDLE_SCHEMA_VERSION", "BundleValidationError",
    "VerificationBundle", "build_verification_bundle",
    "validate_verification_bundle",
]

from .software import Coverage, DeltaKind, FunctionalDeltaItem, FunctionalDeltaResult, FunctionalSnapshot, Observable, RevisionRef, compare_functionality, FUNCTIONAL_REGRESSION_VERIFIER, verify_functional_regression
__all__ += ["Coverage", "DeltaKind", "FunctionalDeltaItem", "FunctionalDeltaResult", "FunctionalSnapshot", "Observable", "RevisionRef", "compare_functionality", "FUNCTIONAL_REGRESSION_VERIFIER", "verify_functional_regression"]
