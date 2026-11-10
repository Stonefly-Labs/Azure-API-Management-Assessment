from collections.abc import Callable
from dataclasses import dataclass

from apim_assess.models.findings import Evaluation, Evidence, Outcome, Thresholds
from apim_assess.models.policy import EffectivePolicy, SubResource
from apim_assess.models.snapshot import Instance, Snapshot


@dataclass(frozen=True)
class Context:
    instance: Instance
    snapshot: Snapshot
    views: list[EffectivePolicy]
    thresholds: Thresholds

    def resources(self, kind: str) -> list[SubResource]:
        inventory = self.instance.inventory
        return [item for item in inventory.resources if item.kind == kind] if inventory else []

    def complete(self, collection: str) -> bool:
        inventory = self.instance.inventory
        if inventory is None:
            return False
        required = {collection, "workspaces"}
        required.update(item.path + "/" + collection for item in self.resources("workspace"))
        return all(
            name in inventory.collections and inventory.collections[name].status == "complete"
            for name in required
        )


Check = Callable[[Context], Evaluation]


def result(outcome: Outcome, detail: str, source: str) -> Evaluation:
    return Evaluation(
        outcome=outcome, summary=detail, evidence=[Evidence(source=source, detail=detail)]
    )


def combine(
    observations: list[tuple[Outcome, Evidence]], *, complete: bool, summary: str
) -> Evaluation:
    outcomes = {outcome for outcome, _ in observations}
    outcome: Outcome = (
        "fail"
        if "fail" in outcomes
        else "unknown"
        if not complete or "unknown" in outcomes
        else "unsupported"
        if "unsupported" in outcomes
        else "pass"
        if "pass" in outcomes
        else "not_applicable"
    )
    evidence = [evidence for _, evidence in observations]
    if not complete:
        evidence.append(
            Evidence(
                source="collection_coverage",
                detail=(
                    "Required inventory is incomplete; "
                    "absence and healthy coverage are not established."
                ),
            )
        )
    return Evaluation(outcome=outcome, summary=summary, evidence=evidence)


def boolean(value: bool | None, *, good: bool = True) -> Outcome:
    return "unknown" if value is None else "pass" if value == good else "fail"
