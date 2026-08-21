from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from gvr import (
    COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
    INDEPENDENT_RECOMPUTE_STRATEGY_ID,
    INVARIANT_CHECK_STRATEGY_ID,
    METAMORPHIC_TRANSFORM_STRATEGY_ID,
    REPRESENTATION_CHECK_STRATEGY_ID,
    WITNESS_SEARCH_STRATEGY_ID,
    AtomicClaim,
    AtomicClaimBinding,
    ClaimGraph,
    EvidenceProviderCapabilityRegistry,
    EvidenceProviderRuntimeRegistry,
    FalsificationCompleteness,
    FalsificationOutcome,
    FalsificationRequirement,
    FalsificationResult,
    FalsificationStrategyBinding,
    FalsificationStrategyCapabilityRegistry,
    FalsificationStrategyDescriptor,
    FalsificationStrategyError,
    FalsificationStrategyKind,
    FalsificationStrategyRuntimeRegistry,
    UnknownFalsificationStrategyError,
    VerificationExecutionError,
    VerificationExecutionLimits,
    VerificationExecutionRequest,
    VerificationExecutionStepStatus,
    VerificationPlanStepKind,
    VerificationPlanTermination,
    VerificationPlanningBudget,
    VerificationPlanningRequest,
    VerificationVerdict,
    VerifierCapability,
    VerifierCapabilityRegistry,
    VerifierCost,
    VerifierDeterminism,
    VerifierRuntimeRegistry,
    VerificationReport,
    builtin_falsification_strategy_capability_registry,
    builtin_falsification_strategy_runtime_registry,
    compile_verification_plan,
    execute_verification_plan,
    handle_request,
)


FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "latvian_weekdays_falsification.json").read_text(
        encoding="utf-8"
    )
)
STRATEGY_VERSION = "1"
CLAIM_KIND = "gvr.text.sequence_predicate"
VERIFIER_ID = "test.falsification_aware.verifier.v1"


class CapturingVerifierRuntime:
    def __init__(
        self,
        capability: VerifierCapability,
        *,
        verdict: VerificationVerdict = VerificationVerdict.PASS,
        events: list[str] | None = None,
    ) -> None:
        self.verifier_id = capability.verifier_id
        self.version = capability.version
        self.capability = capability
        self.verdict = verdict
        self.calls = 0
        self.inputs: list[Any] = []
        self.events = events

    def verify(self, verifier_input: Any) -> VerificationReport:
        self.calls += 1
        self.inputs.append(verifier_input)
        if self.events is not None:
            self.events.append(f"verify:{verifier_input.claim.claim_id}")
        return VerificationReport(
            verdict=self.verdict,
            verifier=self.verifier_id,
        )


class RuntimeWrapper:
    def __init__(
        self,
        descriptor: FalsificationStrategyDescriptor,
        delegate: Any,
        *,
        events: list[str] | None = None,
    ) -> None:
        self.strategy_id = descriptor.strategy_id
        self.version = descriptor.version
        self.descriptor = descriptor
        self.side_effect_free = True
        self.delegate = delegate
        self.calls = 0
        self.events = events

    def run(self, strategy_input: Any) -> Any:
        self.calls += 1
        if self.events is not None:
            self.events.append(f"falsify:{strategy_input.claim.claim_id}")
        return self.delegate.run(strategy_input)


class MalformedRuntime(RuntimeWrapper):
    def run(self, strategy_input: Any) -> Any:
        self.calls += 1
        return {"outcome": "NO_COUNTEREXAMPLE_FOUND"}


class RaisingRuntime(RuntimeWrapper):
    def run(self, strategy_input: Any) -> Any:
        self.calls += 1
        raise RuntimeError("SECRET-STRATEGY-FAILURE-991")


class ContradictoryRuntime(RuntimeWrapper):
    def run(self, strategy_input: Any) -> Any:
        result = super().run(strategy_input)
        assert result.probes
        object.__setattr__(result, "outcome", FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND)
        return result


class EmptyProbeRuntime(RuntimeWrapper):
    def run(self, strategy_input: Any) -> Any:
        result = super().run(strategy_input)
        return FalsificationResult(
            binding_id=result.binding_id,
            declared_verifier_id=result.declared_verifier_id,
            strategy_id=result.strategy_id,
            strategy_version=result.strategy_version,
            strategy_kind=result.strategy_kind,
            strategy_capability_fingerprint=(
                result.strategy_capability_fingerprint
            ),
            claim_id=result.claim_id,
            claim_fingerprint=result.claim_fingerprint,
            outcome=result.outcome,
            probes=(),
            coverage=result.coverage,
            provenance=result.provenance,
        )


class SideEffectingRuntime(RuntimeWrapper):
    def __init__(self, descriptor: FalsificationStrategyDescriptor, delegate: Any) -> None:
        super().__init__(descriptor, delegate)
        self.side_effect_free = False


def _verifier_capability(
    strategy_kinds: tuple[FalsificationStrategyKind, ...],
    *,
    requirement: FalsificationRequirement = FalsificationRequirement.OPTIONAL,
    description: str | None = None,
) -> VerifierCapability:
    return VerifierCapability(
        verifier_id=VERIFIER_ID,
        version="1",
        claim_kinds=(CLAIM_KIND,),
        accepted_evidence_kinds=(),
        required_evidence_kinds=(),
        input_schema={},
        output_schema={},
        determinism=VerifierDeterminism.D1,
        side_effect_free=True,
        cost=VerifierCost.LOW,
        bounds={"finite": True},
        coverage={"requires_complete_falsification_for_pass": requirement.value},
        authoritative=True,
        accepted_falsification_strategy_kinds=strategy_kinds,
        falsification_requirement=requirement,
        description=description,
    )


def _scan_parameters(
    *,
    needle: str = "e",
    predicate_kind: str = "EXACT_MEMBERSHIP",
    expected_members: tuple[str, ...] | None = None,
    expected_count: int | None = None,
    normalization: str = "NFC",
    casefold: bool = False,
    reverse: bool = False,
    duplicate_semantics: str = "PRESERVE",
    corpus: tuple[str, ...] | None = None,
    max_items: int | None = None,
    transformation_id: str | None = None,
) -> dict[str, Any]:
    selected_corpus = tuple(FIXTURE["corpus"]) if corpus is None else corpus
    predicate: dict[str, Any] = {"kind": predicate_kind}
    if expected_members is not None:
        predicate["expected_members"] = expected_members
    if expected_count is not None:
        predicate["expected_count"] = expected_count
    value: dict[str, Any] = {
        "input_kind": "gvr.falsification.finite_text_sequence.v1",
        "corpus": selected_corpus,
        "needle": needle,
        "predicate": predicate,
        "unicode_unit": "CODE_POINT",
        "normalization": normalization,
        "casefold": casefold,
        "reverse": reverse,
        "duplicate_semantics": duplicate_semantics,
    }
    if max_items is not None:
        value["max_items"] = max_items
    if transformation_id is not None:
        value["transformation"] = {
            "transformation_id": transformation_id,
            "version": "1",
            "operation": "REVERSE_BOTH",
            "unicode_unit": "CODE_POINT",
        }
    return value


def _descriptor(strategy_id: str) -> FalsificationStrategyDescriptor:
    return builtin_falsification_strategy_capability_registry().lookup(
        strategy_id,
        STRATEGY_VERSION,
    )


def _fixture(
    *,
    strategy_id: str = COUNTEREXAMPLE_SEARCH_STRATEGY_ID,
    parameters: dict[str, Any] | None = None,
    requirement: FalsificationRequirement = FalsificationRequirement.OPTIONAL,
    verifier_verdict: VerificationVerdict = VerificationVerdict.PASS,
    include_binding: bool = True,
    runtime_factory: Any | None = None,
    budget: VerificationPlanningBudget | None = None,
    limits: VerificationExecutionLimits | None = None,
    events: list[str] | None = None,
    with_dependency: bool = False,
) -> SimpleNamespace:
    descriptor = _descriptor(strategy_id)
    strategy_registry = FalsificationStrategyCapabilityRegistry((descriptor,))
    verifier_capability = _verifier_capability(
        (descriptor.strategy_kind,),
        requirement=requirement,
    )
    verifier_registry = VerifierCapabilityRegistry((verifier_capability,))
    provider_registry = EvidenceProviderCapabilityRegistry()

    target = AtomicClaim(
        claim_id="target",
        claim_kind=CLAIM_KIND,
        spec={"candidate": "fixture"},
        verifier=VERIFIER_ID,
        dependencies=(("dependency",) if with_dependency else ()),
    )
    nodes: list[AtomicClaim] = []
    bindings: list[AtomicClaimBinding] = []
    if with_dependency:
        dependency = AtomicClaim(
            claim_id="dependency",
            claim_kind=CLAIM_KIND,
            spec={"candidate": "dependency"},
            verifier=VERIFIER_ID,
        )
        nodes.append(dependency)
        bindings.append(AtomicClaimBinding(
            claim_id="dependency",
            verifier_id=VERIFIER_ID,
            verifier_version="1",
            verifier_capability_fingerprint=verifier_capability.fingerprint,
        ))
    nodes.append(target)

    falsification_bindings = ()
    if include_binding:
        falsification_bindings = (FalsificationStrategyBinding(
            binding_id="falsify-target",
            verifier_id=VERIFIER_ID,
            strategy_id=descriptor.strategy_id,
            strategy_version=descriptor.version,
            strategy_capability_fingerprint=descriptor.fingerprint,
            parameters=(parameters or _scan_parameters(
                expected_members=tuple(FIXTURE["plain_e"]["expected_members"])
            )),
        ),)
    bindings.append(AtomicClaimBinding(
        claim_id="target",
        verifier_id=VERIFIER_ID,
        verifier_version="1",
        verifier_capability_fingerprint=verifier_capability.fingerprint,
        falsification_bindings=falsification_bindings,
    ))

    graph = ClaimGraph(nodes=tuple(nodes))
    planning_request = VerificationPlanningRequest(
        claim_graph=graph,
        bindings=tuple(bindings),
        verifier_capability_registry=verifier_registry,
        verifier_capability_registry_fingerprint=verifier_registry.fingerprint,
        evidence_provider_capability_registry=provider_registry,
        evidence_provider_capability_registry_fingerprint=provider_registry.fingerprint,
        falsification_strategy_capability_registry=(
            strategy_registry if include_binding else None
        ),
        falsification_strategy_capability_registry_fingerprint=(
            strategy_registry.fingerprint if include_binding else None
        ),
        budget=(budget or VerificationPlanningBudget()),
    )
    plan = compile_verification_plan(planning_request)

    verifier_runtime = CapturingVerifierRuntime(
        verifier_capability,
        verdict=verifier_verdict,
        events=events,
    )
    verifier_runtime_registry = VerifierRuntimeRegistry(
        capability_registry=verifier_registry,
        runtime_verifiers={(VERIFIER_ID, "1"): verifier_runtime},
    )
    provider_runtime_registry = EvidenceProviderRuntimeRegistry(
        capability_registry=provider_registry,
        runtime_providers={},
    )

    builtin_runtime_registry = builtin_falsification_strategy_runtime_registry(
        strategy_registry
    )
    builtin_runtime = builtin_runtime_registry.runtime_strategies[
        (descriptor.strategy_id, descriptor.version)
    ]
    selected_runtime = (
        runtime_factory(descriptor, builtin_runtime)
        if runtime_factory is not None
        else RuntimeWrapper(descriptor, builtin_runtime, events=events)
    )
    strategy_runtime_registry = FalsificationStrategyRuntimeRegistry(
        capability_registry=strategy_registry,
        runtime_strategies={(descriptor.strategy_id, descriptor.version): selected_runtime},
    )

    execution_request = None
    if plan.termination is VerificationPlanTermination.COMPLETE:
        execution_request = VerificationExecutionRequest(
            plan=plan,
            plan_fingerprint=plan.fingerprint,
            claim_graph=graph,
            claim_graph_fingerprint=graph.fingerprint,
            roots=("target",),
            verifier_runtime_registry=verifier_runtime_registry,
            verifier_capability_registry_fingerprint=verifier_registry.fingerprint,
            evidence_provider_runtime_registry=provider_runtime_registry,
            evidence_provider_capability_registry_fingerprint=provider_registry.fingerprint,
            evidence_requests={},
            falsification_strategy_runtime_registry=(
                strategy_runtime_registry if include_binding else None
            ),
            falsification_strategy_capability_registry_fingerprint=(
                strategy_registry.fingerprint if include_binding else None
            ),
            limits=(limits or VerificationExecutionLimits()),
        )
    return SimpleNamespace(
        descriptor=descriptor,
        strategy_registry=strategy_registry,
        verifier_capability=verifier_capability,
        verifier_registry=verifier_registry,
        provider_registry=provider_registry,
        graph=graph,
        planning_request=planning_request,
        plan=plan,
        verifier_runtime=verifier_runtime,
        verifier_runtime_registry=verifier_runtime_registry,
        provider_runtime_registry=provider_runtime_registry,
        strategy_runtime=selected_runtime,
        strategy_runtime_registry=strategy_runtime_registry,
        execution_request=execution_request,
    )


def _root_verdict(result: Any) -> VerificationVerdict:
    return result.session.claim_state("target").effective_verdict


def _all_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            keys.add(str(key).lower())
            keys.update(_all_keys(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            keys.update(_all_keys(item))
    return keys


def test_01_descriptor_is_strict_deeply_immutable_and_canonical() -> None:
    descriptor = FalsificationStrategyDescriptor(
        strategy_id="test.strategy",
        version="1",
        strategy_kind=FalsificationStrategyKind.INVARIANT_CHECK,
        claim_kinds=("z", "a"),
        input_schema={"b": [2, 1], "a": {"x": True}},
        output_schema={},
        determinism=VerifierDeterminism.D0,
        side_effect_free=True,
        cost=VerifierCost.LOW,
        bounds={"finite": True},
        coverage={"complete": True},
    )
    reordered = replace(
        descriptor,
        claim_kinds=("a", "z"),
        input_schema={"a": {"x": True}, "b": [2, 1]},
    )
    assert descriptor.fingerprint == reordered.fingerprint
    assert descriptor.claim_kinds == ("a", "z")
    with pytest.raises(FrozenInstanceError):
        descriptor.version = "2"  # type: ignore[misc]
    with pytest.raises(TypeError):
        descriptor.input_schema["new"] = True  # type: ignore[index]


def test_02_builtin_registry_publishes_exactly_six_kinds_ids_and_version_one() -> None:
    registry = builtin_falsification_strategy_capability_registry()
    expected = {
        WITNESS_SEARCH_STRATEGY_ID: FalsificationStrategyKind.WITNESS_SEARCH,
        COUNTEREXAMPLE_SEARCH_STRATEGY_ID: FalsificationStrategyKind.COUNTEREXAMPLE_SEARCH,
        INVARIANT_CHECK_STRATEGY_ID: FalsificationStrategyKind.INVARIANT_CHECK,
        METAMORPHIC_TRANSFORM_STRATEGY_ID: FalsificationStrategyKind.METAMORPHIC_TRANSFORM,
        INDEPENDENT_RECOMPUTE_STRATEGY_ID: FalsificationStrategyKind.INDEPENDENT_RECOMPUTE,
        REPRESENTATION_CHECK_STRATEGY_ID: FalsificationStrategyKind.REPRESENTATION_CHECK,
    }
    assert {
        item.strategy_id: item.strategy_kind for item in registry.list_capabilities()
    } == expected
    assert {item.version for item in registry.list_capabilities()} == {"1"}


def test_03_capability_registry_requires_exact_version_and_fingerprints_semantics() -> None:
    descriptor = _descriptor(COUNTEREXAMPLE_SEARCH_STRATEGY_ID)
    registry = FalsificationStrategyCapabilityRegistry((descriptor,))
    assert registry.lookup(descriptor.strategy_id, "1") is descriptor
    with pytest.raises(UnknownFalsificationStrategyError):
        registry.lookup(descriptor.strategy_id, "2")
    changed = replace(descriptor, bounds={"finite": True, "max_items": 8})
    assert changed.fingerprint != descriptor.fingerprint
    assert FalsificationStrategyCapabilityRegistry((changed,)).fingerprint != registry.fingerprint


def test_04_runtime_registry_fingerprints_exact_keys_and_rejects_side_effecting_runtime() -> None:
    descriptor = _descriptor(COUNTEREXAMPLE_SEARCH_STRATEGY_ID)
    registry = FalsificationStrategyCapabilityRegistry((descriptor,))
    builtin = builtin_falsification_strategy_runtime_registry(registry)
    runtime = builtin.runtime_strategies[(descriptor.strategy_id, descriptor.version)]
    exact = FalsificationStrategyRuntimeRegistry(
        capability_registry=registry,
        runtime_strategies={(descriptor.strategy_id, descriptor.version): runtime},
    )
    assert exact.runtime_keys == ((descriptor.strategy_id, "1"),)
    with pytest.raises(FalsificationStrategyError):
        FalsificationStrategyRuntimeRegistry(
            capability_registry=registry,
            runtime_strategies={
                (descriptor.strategy_id, descriptor.version): SideEffectingRuntime(
                    descriptor, runtime
                )
            },
        )


def test_05_atomic_binding_without_falsification_preserves_task19_shape() -> None:
    capability = _verifier_capability((), requirement=FalsificationRequirement.NONE)
    binding = AtomicClaimBinding(
        claim_id="legacy",
        verifier_id=VERIFIER_ID,
        verifier_version="1",
        verifier_capability_fingerprint=capability.fingerprint,
    )
    assert "falsification_bindings" not in binding.to_dict()
    assert binding.falsification_bindings == ()


def test_06_planner_never_auto_selects_and_required_binding_fails_closed() -> None:
    optional = _fixture(include_binding=False, requirement=FalsificationRequirement.OPTIONAL)
    assert optional.plan.termination is VerificationPlanTermination.COMPLETE
    assert all(
        step.kind is not VerificationPlanStepKind.RUN_FALSIFICATION
        for step in optional.plan.steps
    )
    required = _fixture(include_binding=False, requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS)
    assert required.plan.termination is VerificationPlanTermination.UNSUPPORTED_CLAIM
    assert "MISSING_REQUIRED_FALSIFICATION_BINDING" in {
        issue.code for issue in required.plan.issues
    }


def test_07_run_falsification_step_is_canonical_and_required_by_verifier_step() -> None:
    fixture = _fixture()
    run_step = next(
        step for step in fixture.plan.steps
        if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION
    )
    verify_step = next(
        step for step in fixture.plan.steps
        if step.kind is VerificationPlanStepKind.VERIFY_ATOMIC_CLAIM
    )
    assert run_step.claim_id == "target"
    assert run_step.strategy_id == COUNTEREXAMPLE_SEARCH_STRATEGY_ID
    assert run_step.strategy_version == "1"
    assert run_step.strategy_capability_fingerprint == fixture.descriptor.fingerprint
    assert run_step.step_id in verify_step.dependency_step_ids
    assert run_step.fingerprint == replace(run_step).fingerprint


def test_08_planner_rejects_strategy_id_or_version_substitution() -> None:
    fixture = _fixture()
    binding = fixture.planning_request.bindings[-1]
    original = binding.falsification_bindings[0]
    for changed in (
        replace(original, strategy_id="missing.strategy"),
        replace(original, strategy_version="2"),
    ):
        request = replace(
            fixture.planning_request,
            bindings=(replace(binding, falsification_bindings=(changed,)),),
        )
        assert "UNKNOWN_FALSIFICATION_STRATEGY" in {
            issue.code for issue in compile_verification_plan(request).issues
        }


def test_09_planner_rejects_falsification_capability_fingerprint_substitution() -> None:
    fixture = _fixture()
    binding = fixture.planning_request.bindings[-1]
    changed = replace(
        binding.falsification_bindings[0],
        strategy_capability_fingerprint="0" * 64,
    )
    request = replace(
        fixture.planning_request,
        bindings=(replace(binding, falsification_bindings=(changed,)),),
    )
    assert "FALSIFICATION_STRATEGY_CAPABILITY_FINGERPRINT_MISMATCH" in {
        issue.code for issue in compile_verification_plan(request).issues
    }


def test_10_planning_and_execution_budgets_count_falsification_work_exactly() -> None:
    blocked_plan = _fixture(
        budget=VerificationPlanningBudget(max_falsification_steps=0)
    ).plan
    assert blocked_plan.termination is VerificationPlanTermination.BUDGET_EXHAUSTED
    assert blocked_plan.consumption.falsification_steps == 1

    fixture = _fixture(
        limits=VerificationExecutionLimits(max_falsification_invocations=0)
    )
    assert fixture.execution_request is not None
    result = execute_verification_plan(fixture.execution_request)
    run_step = next(
        step for step in result.steps
        if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION
    )
    assert run_step.status is VerificationExecutionStepStatus.BLOCKED
    assert result.consumption.falsification_invocations == 0
    assert _root_verdict(result) is not VerificationVerdict.PASS


def test_11_finite_scan_distinguishes_e_and_long_e_with_nfc_nfd() -> None:
    plain = _fixture(
        strategy_id=INVARIANT_CHECK_STRATEGY_ID,
        parameters=_scan_parameters(predicate_kind="UNIVERSAL", needle="e"),
    )
    plain_result = execute_verification_plan(plain.execution_request)
    assert next(iter(plain_result.falsification_results.values())).outcome is FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND

    long_e = _fixture(
        parameters=_scan_parameters(
            needle=FIXTURE["long_e"]["nfd_needle"],
            normalization="NFC",
            expected_members=tuple(FIXTURE["long_e"]["expected_members"]),
        ),
    )
    long_result = execute_verification_plan(long_e.execution_request)
    falsification = next(iter(long_result.falsification_results.values()))
    assert falsification.outcome is FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
    assert falsification.coverage.completeness is FalsificationCompleteness.COMPLETE
    assert falsification.provenance.transformation["normalization"] == "NFC"


def test_12_existential_reverse_and_duplicate_semantics_are_explicit() -> None:
    reverse = _fixture(
        strategy_id=WITNESS_SEARCH_STRATEGY_ID,
        parameters=_scan_parameters(
            predicate_kind="EXISTENTIAL",
            needle="ē",
            reverse=True,
        ),
    )
    reverse_result = next(
        iter(execute_verification_plan(reverse.execution_request).falsification_results.values())
    )
    assert reverse_result.outcome is FalsificationOutcome.WITNESS_FOUND
    assert reverse_result.provenance.transformation["reverse"] is True
    assert reverse_result.provenance.transformation["unicode_unit"] == "CODE_POINT"

    preserve = _fixture(
        parameters=_scan_parameters(
            corpus=tuple(FIXTURE["duplicates"]),
            expected_count=3,
            predicate_kind="EXACT_COUNT",
            duplicate_semantics="PRESERVE",
        ),
    )
    distinct = _fixture(
        parameters=_scan_parameters(
            corpus=tuple(FIXTURE["duplicates"]),
            expected_count=2,
            predicate_kind="EXACT_COUNT",
            duplicate_semantics="DISTINCT",
        ),
    )
    assert next(iter(execute_verification_plan(preserve.execution_request).falsification_results.values())).outcome is FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND
    assert next(iter(execute_verification_plan(distinct.execution_request).falsification_results.values())).outcome is FalsificationOutcome.NO_COUNTEREXAMPLE_FOUND


def test_13_independent_recompute_uses_separate_path_and_catches_wrong_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    import gvr.falsification as falsification_module

    monkeypatch.setattr(
        falsification_module,
        "_primary_finite_sequence_scan",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("primary path used")),
    )
    fixture = _fixture(
        strategy_id=INDEPENDENT_RECOMPUTE_STRATEGY_ID,
        parameters=_scan_parameters(
            expected_members=tuple(FIXTURE["historical_wrong_candidate"]),
        ),
        verifier_verdict=VerificationVerdict.PASS,
    )
    result = execute_verification_plan(fixture.execution_request)
    falsification = next(iter(result.falsification_results.values()))
    assert falsification.outcome is FalsificationOutcome.COUNTEREXAMPLE_FOUND
    assert falsification.provenance.implementation_path == "independent_finite_sequence_recompute_v1"
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN


def test_14_metamorphic_identity_and_provenance_are_fully_fingerprinted() -> None:
    first = _fixture(
        strategy_id=METAMORPHIC_TRANSFORM_STRATEGY_ID,
        parameters=_scan_parameters(
            expected_members=tuple(FIXTURE["plain_e"]["expected_members"]),
            transformation_id="gvr.transform.reverse_both.codepoint.v1",
        ),
    )
    second_parameters = _scan_parameters(
        expected_members=tuple(FIXTURE["plain_e"]["expected_members"]),
        transformation_id="gvr.transform.reverse_both.codepoint.v2",
    )
    second = _fixture(
        strategy_id=METAMORPHIC_TRANSFORM_STRATEGY_ID,
        parameters=second_parameters,
    )
    assert first.plan.fingerprint != second.plan.fingerprint
    first_result = next(
        iter(execute_verification_plan(first.execution_request).falsification_results.values())
    )
    second_result = next(
        iter(execute_verification_plan(second.execution_request).falsification_results.values())
    )
    assert first_result.provenance.transformation_fingerprint != second_result.provenance.transformation_fingerprint
    assert first_result.fingerprint != second_result.fingerprint


def test_15_executor_runs_exact_strategy_after_dependencies_once_and_scopes_output() -> None:
    events: list[str] = []
    fixture = _fixture(with_dependency=True, events=events)
    result = execute_verification_plan(fixture.execution_request)
    assert events == ["verify:dependency", "falsify:target", "verify:target"]
    assert fixture.strategy_runtime.calls == 1
    dependency_input, target_input = fixture.verifier_runtime.inputs
    assert dependency_input.falsification_results == ()
    assert len(target_input.falsification_results) == 1
    assert target_input.falsification_results[0].declared_verifier_id == VERIFIER_ID
    assert set(result.falsification_results) == {
        next(step.step_id for step in fixture.plan.steps if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION)
    }


def test_16_missing_or_incomplete_required_output_can_never_be_pass() -> None:
    missing = _fixture(
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        runtime_factory=lambda descriptor, delegate: MalformedRuntime(descriptor, delegate),
    )
    missing_result = execute_verification_plan(missing.execution_request)
    assert _root_verdict(missing_result) is VerificationVerdict.UNKNOWN

    incomplete = _fixture(
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        parameters=_scan_parameters(
            expected_members=tuple(FIXTURE["plain_e"]["expected_members"]),
            max_items=2,
        ),
    )
    incomplete_result = execute_verification_plan(incomplete.execution_request)
    falsification = next(iter(incomplete_result.falsification_results.values()))
    assert falsification.outcome is FalsificationOutcome.INCOMPLETE
    assert _root_verdict(incomplete_result) is VerificationVerdict.UNKNOWN


def test_17_verifier_pass_cannot_ignore_a_complete_counterexample() -> None:
    fixture = _fixture(
        strategy_id=INDEPENDENT_RECOMPUTE_STRATEGY_ID,
        parameters=_scan_parameters(
            expected_members=tuple(FIXTURE["historical_wrong_candidate"]),
        ),
        verifier_verdict=VerificationVerdict.PASS,
    )
    result = execute_verification_plan(fixture.execution_request)
    assert fixture.verifier_runtime.calls == 1
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN
    assert "VERIFIER_IGNORED_FALSIFICATION_COUNTEREXAMPLE" in {
        issue.code for issue in result.issues
    }


def test_18_only_verifier_decides_truth_and_executor_does_not_auto_fail_or_pass() -> None:
    counterexample = _fixture(
        strategy_id=INDEPENDENT_RECOMPUTE_STRATEGY_ID,
        parameters=_scan_parameters(
            expected_members=tuple(FIXTURE["historical_wrong_candidate"]),
        ),
        verifier_verdict=VerificationVerdict.FAIL,
    )
    assert _root_verdict(execute_verification_plan(counterexample.execution_request)) is VerificationVerdict.FAIL

    clean_unknown = _fixture(verifier_verdict=VerificationVerdict.UNKNOWN)
    assert _root_verdict(execute_verification_plan(clean_unknown.execution_request)) is VerificationVerdict.UNKNOWN


def test_19_malformed_runtime_output_fails_closed_and_never_becomes_pass() -> None:
    fixture = _fixture(
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        runtime_factory=lambda descriptor, delegate: MalformedRuntime(descriptor, delegate),
    )
    result = execute_verification_plan(fixture.execution_request)
    run_step = next(step for step in result.steps if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION)
    assert run_step.status is VerificationExecutionStepStatus.FAILED
    assert "FALSIFICATION_RESULT_INVALID" in run_step.issue_codes
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN


def test_20_strategy_exception_is_stable_secret_safe_and_not_retried() -> None:
    first = _fixture(
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        runtime_factory=lambda descriptor, delegate: RaisingRuntime(descriptor, delegate),
    )
    second = _fixture(
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        runtime_factory=lambda descriptor, delegate: RaisingRuntime(descriptor, delegate),
    )
    first_result = execute_verification_plan(first.execution_request)
    second_result = execute_verification_plan(second.execution_request)
    assert first.strategy_runtime.calls == 1
    assert second.strategy_runtime.calls == 1
    assert first_result.fingerprint == second_result.fingerprint
    assert "SECRET-STRATEGY-FAILURE-991" not in json.dumps(first_result.to_dict())
    assert _root_verdict(first_result) is VerificationVerdict.UNKNOWN


def test_21_runtime_identity_and_side_effect_contract_are_rechecked_before_call() -> None:
    fixture = _fixture()
    fixture.strategy_runtime.strategy_id = "substituted.strategy"
    with pytest.raises(VerificationExecutionError):
        execute_verification_plan(fixture.execution_request)
    assert fixture.strategy_runtime.calls == 0


def test_22_strategy_version_and_runtime_registry_fingerprint_substitution_fail() -> None:
    fixture = _fixture()
    request = fixture.execution_request
    assert request is not None
    runtime = fixture.strategy_runtime_registry.runtime_strategies[
        (fixture.descriptor.strategy_id, fixture.descriptor.version)
    ]
    forged_descriptor = replace(fixture.descriptor, version="2")
    forged_registry = FalsificationStrategyCapabilityRegistry((forged_descriptor,))
    with pytest.raises(FalsificationStrategyError):
        FalsificationStrategyRuntimeRegistry(
            capability_registry=forged_registry,
            runtime_strategies={(forged_descriptor.strategy_id, "2"): runtime},
        )
    object.__setattr__(
        request.falsification_strategy_runtime_registry,
        "fingerprint",
        "0" * 64,
    )
    with pytest.raises(VerificationExecutionError):
        execute_verification_plan(request)


def test_23_contradictory_outcome_and_probe_is_rejected_fail_closed() -> None:
    fixture = _fixture(
        strategy_id=INDEPENDENT_RECOMPUTE_STRATEGY_ID,
        parameters=_scan_parameters(
            expected_members=tuple(FIXTURE["historical_wrong_candidate"]),
        ),
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        runtime_factory=lambda descriptor, delegate: ContradictoryRuntime(descriptor, delegate),
    )
    result = execute_verification_plan(fixture.execution_request)
    assert not result.falsification_results
    assert "FALSIFICATION_RESULT_INVALID" in {issue.code for issue in result.issues}
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN


def test_24_falsification_contract_contains_no_confidence_llm_fallback_retry_or_product_policy() -> None:
    fixture = _fixture()
    result = execute_verification_plan(fixture.execution_request)
    exposed = {
        "descriptor": fixture.descriptor.to_dict(),
        "capability_registry": fixture.strategy_registry.to_dict(),
        "runtime_registry": fixture.strategy_runtime_registry.to_dict(),
        "planning_request": fixture.planning_request.to_dict(),
        "plan": fixture.plan.to_dict(),
        "falsification_results": [item.to_dict() for item in result.falsification_results.values()],
    }
    forbidden = {
        "confidence", "score", "llm", "model", "fallback", "retry",
        "ranking", "product_policy", "authorization", "truth", "verdict",
    }
    assert _all_keys(exposed).isdisjoint(forbidden)


def test_25_schema_v1_legacy_planner_executor_and_protocol_remain_backward_compatible() -> None:
    legacy = _fixture(include_binding=False, requirement=FalsificationRequirement.NONE)
    assert legacy.plan.termination is VerificationPlanTermination.COMPLETE
    assert "falsification_strategy_capability_registry_fingerprint" not in legacy.plan.to_dict()
    result = execute_verification_plan(legacy.execution_request)
    assert "falsification_results" not in result.to_dict()
    protocol = handle_request({
        "schema_version": 1,
        "op": "describe_verifier_capabilities",
        "payload": {},
    })
    assert protocol["schema_version"] == 1
    assert protocol["kind"] == "verifier_capability_registry"


def test_26_schema_v1_protocol_round_trips_exact_planner_and_executor_falsification() -> None:
    fixture = _fixture()
    compiled = handle_request({
        "schema_version": 1,
        "op": "compile_verification_plan",
        "payload": fixture.planning_request.to_dict(),
    })
    assert compiled["payload"]["fingerprint"] == fixture.plan.fingerprint

    executed = handle_request(
        {
            "schema_version": 1,
            "op": "execute_verification_plan",
            "payload": fixture.execution_request.to_dict(),
        },
        verifier_runtime_registry=fixture.verifier_runtime_registry,
        evidence_provider_runtime_registry=fixture.provider_runtime_registry,
        falsification_strategy_runtime_registry=fixture.strategy_runtime_registry,
    )
    assert executed["kind"] == "verification_execution_result"
    assert executed["payload"]["fingerprint"] == execute_verification_plan(
        fixture.execution_request
    ).fingerprint


def test_27_required_complete_result_without_any_probe_cannot_enable_pass() -> None:
    fixture = _fixture(
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
        runtime_factory=lambda descriptor, delegate: EmptyProbeRuntime(
            descriptor,
            delegate,
        ),
    )
    result = execute_verification_plan(fixture.execution_request)
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN
    assert "FALSIFICATION_RESULT_INVALID" in {issue.code for issue in result.issues}


def test_28_representation_check_requires_an_explicit_expected_code_point_sequence() -> None:
    fixture = _fixture(
        strategy_id=REPRESENTATION_CHECK_STRATEGY_ID,
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
    )
    result = execute_verification_plan(fixture.execution_request)
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN
    assert "FALSIFICATION_RESULT_INVALID" in {issue.code for issue in result.issues}


def test_29_metamorphic_identity_fields_must_be_stable_identifiers() -> None:
    parameters = _scan_parameters(
        expected_members=tuple(FIXTURE["plain_e"]["expected_members"]),
        transformation_id="gvr.transform.reverse_both.codepoint.v1",
    )
    parameters["transformation"]["version"] = None
    fixture = _fixture(
        strategy_id=METAMORPHIC_TRANSFORM_STRATEGY_ID,
        parameters=parameters,
        requirement=FalsificationRequirement.REQUIRED_BEFORE_PASS,
    )
    result = execute_verification_plan(fixture.execution_request)
    assert _root_verdict(result) is VerificationVerdict.UNKNOWN
    assert "FALSIFICATION_RESULT_INVALID" in {issue.code for issue in result.issues}


def test_30_verifier_input_rejects_falsification_declared_for_another_verifier() -> None:
    fixture = _fixture()
    execute_verification_plan(fixture.execution_request)
    verifier_input = fixture.verifier_runtime.inputs[0]
    falsification_result = verifier_input.falsification_results[0]
    foreign_provenance = replace(
        falsification_result.provenance,
        declared_verifier_id="other.verifier",
    )
    foreign_result = replace(
        falsification_result,
        declared_verifier_id="other.verifier",
        provenance=foreign_provenance,
    )

    with pytest.raises(VerificationExecutionError, match="declared verifier"):
        replace(verifier_input, falsification_results=(foreign_result,))


def test_31_execution_result_rejects_falsification_under_a_forged_step_id() -> None:
    fixture = _fixture()
    result = execute_verification_plan(fixture.execution_request)
    falsification_result = next(iter(result.falsification_results.values()))

    with pytest.raises(VerificationExecutionError, match="RUN_FALSIFICATION step"):
        replace(
            result,
            falsification_results={"forged-run": falsification_result},
        )


def test_32_execution_result_rejects_a_substituted_falsification_fingerprint() -> None:
    fixture = _fixture()
    result = execute_verification_plan(fixture.execution_request)
    tampered_steps = tuple(
        replace(step, falsification_result_fingerprint="0" * 64)
        if step.kind is VerificationPlanStepKind.RUN_FALSIFICATION
        else step
        for step in result.steps
    )

    with pytest.raises(VerificationExecutionError, match="fingerprint"):
        replace(result, steps=tampered_steps)
