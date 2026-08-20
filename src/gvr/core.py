from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol

from .model import (
    INDETERMINATE,
    MISSING,
    VerificationIssue,
    VerificationReport,
    VerificationVerdict,
    combine_verdicts,
)


@dataclass(frozen=True)
class Predicate:
    slot: str
    op: str
    expected: Any = None


@dataclass(frozen=True)
class StateEffect:
    slot: str
    value: Any
    supported: bool = True


@dataclass(frozen=True)
class Action:
    id: str
    preconditions: tuple[Predicate, ...] = ()
    effects: tuple[StateEffect, ...] = ()


@dataclass(frozen=True)
class Goal:
    predicates: tuple[Predicate, ...]


@dataclass(frozen=True)
class Proposal:
    actions: tuple[Action, ...]


@dataclass(frozen=True)
class VerificationContext:
    initial_state: Mapping[str, Any]
    goal: Goal


@dataclass(frozen=True)
class SimulationResult:
    state: Mapping[str, Any]
    issues: tuple[VerificationIssue, ...]
    action_verdicts: tuple[VerificationVerdict, ...]


def evaluate_predicate(predicate: Predicate, state: Mapping[str, Any]) -> VerificationVerdict:
    actual = state.get(predicate.slot, MISSING)

    if predicate.op == "exists":
        return VerificationVerdict.PASS if actual is not MISSING else VerificationVerdict.FAIL
    if predicate.op == "missing":
        return VerificationVerdict.PASS if actual is MISSING else VerificationVerdict.FAIL

    if actual is MISSING or actual is INDETERMINATE:
        return VerificationVerdict.UNKNOWN

    if predicate.op == "eq":
        return VerificationVerdict.PASS if actual == predicate.expected else VerificationVerdict.FAIL
    if predicate.op == "neq":
        return VerificationVerdict.PASS if actual != predicate.expected else VerificationVerdict.FAIL
    if predicate.op == "truthy":
        return VerificationVerdict.PASS if bool(actual) else VerificationVerdict.FAIL
    if predicate.op == "falsy":
        return VerificationVerdict.PASS if not bool(actual) else VerificationVerdict.FAIL

    return VerificationVerdict.UNKNOWN


def _affected_slots(action: Action) -> set[str]:
    return {effect.slot for effect in action.effects}


def simulate(proposal: Proposal, context: VerificationContext) -> SimulationResult:
    state: dict[str, Any] = dict(context.initial_state)
    issues: list[VerificationIssue] = []
    action_verdicts: list[VerificationVerdict] = []

    for action in proposal.actions:
        pre = [evaluate_predicate(p, state) for p in action.preconditions]
        pre_verdict = combine_verdicts(*pre) if pre else VerificationVerdict.PASS

        if pre_verdict is VerificationVerdict.FAIL:
            issues.append(VerificationIssue(
                code="ACTION_PRECONDITION_FAILED",
                message=f"Action {action.id} has a failed precondition; effects were not applied.",
                verdict=VerificationVerdict.FAIL,
            ))
            action_verdicts.append(VerificationVerdict.FAIL)
            continue

        if pre_verdict is VerificationVerdict.UNKNOWN:
            for slot in _affected_slots(action):
                state[slot] = INDETERMINATE
            issues.append(VerificationIssue(
                code="ACTION_PRECONDITION_UNKNOWN",
                message=f"Action {action.id} precondition is unknown; affected state was tainted.",
                verdict=VerificationVerdict.UNKNOWN,
            ))
            action_verdicts.append(VerificationVerdict.UNKNOWN)
            continue

        unsupported = False
        for effect in action.effects:
            if effect.supported:
                state[effect.slot] = effect.value
            else:
                state[effect.slot] = INDETERMINATE
                unsupported = True

        if unsupported:
            issues.append(VerificationIssue(
                code="UNSUPPORTED_EFFECT",
                message=f"Action {action.id} contains unsupported effects; affected state is indeterminate.",
                verdict=VerificationVerdict.UNKNOWN,
            ))
            action_verdicts.append(VerificationVerdict.UNKNOWN)
        else:
            action_verdicts.append(VerificationVerdict.PASS)

    return SimulationResult(state=state, issues=tuple(issues), action_verdicts=tuple(action_verdicts))


class Verifier(Protocol):
    name: str
    def verify(self, proposal: Proposal, context: VerificationContext) -> VerificationReport: ...


class GoalSatisfactionVerifier:
    name = "goal_satisfaction"

    def verify(self, proposal: Proposal, context: VerificationContext) -> VerificationReport:
        simulation = simulate(proposal, context)
        goal_results = tuple(evaluate_predicate(p, simulation.state) for p in context.goal.predicates)
        verdict = combine_verdicts(*goal_results) if goal_results else VerificationVerdict.UNKNOWN

        issues = list(simulation.issues)
        for predicate, result in zip(context.goal.predicates, goal_results):
            if result is not VerificationVerdict.PASS:
                issues.append(VerificationIssue(
                    code="GOAL_NOT_PROVEN" if result is VerificationVerdict.UNKNOWN else "GOAL_NOT_SATISFIED",
                    message=f"Goal predicate {predicate.slot}:{predicate.op} was {result.value}.",
                    verdict=result,
                ))

        return VerificationReport(
            verdict=verdict,
            verifier=self.name,
            issues=tuple(issues),
            metadata={"final_state": dict(simulation.state)},
        )


class PreconditionsVerifier:
    name = "preconditions"

    def verify(self, proposal: Proposal, context: VerificationContext) -> VerificationReport:
        simulation = simulate(proposal, context)
        relevant = tuple(i for i in simulation.issues if i.code.startswith("ACTION_PRECONDITION_"))
        if any(i.verdict is VerificationVerdict.FAIL for i in relevant):
            verdict = VerificationVerdict.FAIL
        elif any(i.verdict is VerificationVerdict.UNKNOWN for i in relevant):
            verdict = VerificationVerdict.UNKNOWN
        else:
            verdict = VerificationVerdict.PASS
        return VerificationReport(verdict=verdict, verifier=self.name, issues=relevant)


class EffectSupportVerifier:
    name = "effect_support"

    def verify(self, proposal: Proposal, context: VerificationContext) -> VerificationReport:
        simulation = simulate(proposal, context)
        relevant = tuple(i for i in simulation.issues if i.code == "UNSUPPORTED_EFFECT")
        verdict = VerificationVerdict.UNKNOWN if relevant else VerificationVerdict.PASS
        return VerificationReport(verdict=verdict, verifier=self.name, issues=relevant)


@dataclass
class VerifierRegistry:
    verifiers: list[Verifier] = field(default_factory=list)

    def register(self, verifier: Verifier) -> None:
        self.verifiers.append(verifier)

    def verify(self, proposal: Proposal, context: VerificationContext) -> VerificationReport:
        if not self.verifiers:
            return VerificationReport(
                verdict=VerificationVerdict.UNKNOWN,
                verifier="registry",
                issues=(VerificationIssue(
                    code="NO_VERIFIERS",
                    message="No verifier is registered.",
                    verdict=VerificationVerdict.UNKNOWN,
                ),),
            )
        reports = [v.verify(proposal, context) for v in self.verifiers]
        verdict = combine_verdicts(*(r.verdict for r in reports))
        return VerificationReport(
            verdict=verdict,
            verifier="registry",
            issues=tuple(issue for r in reports for issue in r.issues),
            evidence_ids=tuple(dict.fromkeys(eid for r in reports for eid in r.evidence_ids)),
            metadata={
                "reports": tuple(reports),
                "by_verifier": {r.verifier: r for r in reports},
            },
        )


def default_registry() -> VerifierRegistry:
    return VerifierRegistry([PreconditionsVerifier(), EffectSupportVerifier(), GoalSatisfactionVerifier()])
