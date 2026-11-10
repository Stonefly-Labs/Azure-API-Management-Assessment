from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.findings import Evaluation, Evidence
from apim_assess.models.snapshot import Instance, Snapshot


def developer_sku(instance: Instance, snapshot: Snapshot) -> Evaluation:
    if instance.sku is None:
        return Evaluation(outcome="unknown", summary="SKU was not collected.")
    sku = instance.sku.name
    evidence = [Evidence(source="ARM service.sku.name", detail=sku)]
    if sku not in CLASSIC | V2 | {"Consumption"}:
        return Evaluation(outcome="unknown", summary="Unrecognized SKU.", evidence=evidence)
    return Evaluation(
        outcome="fail" if sku == "Developer" else "pass",
        summary=(
            "Developer tier has no production SLA; use an SLA-backed tier for production."
            if sku == "Developer"
            else "The service is not on the SLA-less Developer tier."
        ),
        evidence=evidence,
    )


def zone_redundancy(instance: Instance, snapshot: Snapshot) -> Evaluation:
    if not instance.sku:
        return Evaluation(outcome="unknown", summary="SKU was not collected.")
    sku = instance.sku.name
    if sku in {"Developer", "Basic", "Standard", "BasicV2", "Consumption"}:
        return Evaluation(
            outcome="unsupported",
            summary="This SKU does not support configurable availability zones; not a pass.",
        )
    if sku in {"StandardV2", "PremiumV2"}:
        return Evaluation(
            outcome="unknown",
            summary="The selected ARM API's zone list cannot establish v2 zone-redundancy state.",
        )
    if sku != "Premium":
        return Evaluation(
            outcome="unknown", summary="Zone capability for this SKU is not established."
        )
    regions = [(instance.location, instance.zones, instance.sku.capacity)]
    if instance.additional_locations is not None:
        regions += [
            (region.location, region.zones, region.capacity)
            for region in instance.additional_locations
        ]
    evidence = [
        Evidence(
            source="ARM service.zones / properties.additionalLocations[].zones",
            detail=f"{location or 'uncollected region'}: zones={zones}; units={capacity}",
        )
        for location, zones, capacity in regions
    ]
    if any(zones is not None and len(set(zones)) == 1 for _, zones, _ in regions):
        return Evaluation(
            outcome="fail",
            summary="At least one region is explicitly pinned to a single availability zone.",
            evidence=evidence,
        )
    if instance.additional_locations is None or any(
        not location or not zones for location, zones, _ in regions
    ):
        return Evaluation(
            outcome="unknown",
            summary=(
                "Empty/missing zones may mean automatic distribution, not disabled redundancy. "
                "Regional capability and automatic placement were not independently collected."
            ),
            evidence=evidence,
        )
    if any(
        capacity is None or capacity == 0 or capacity % len(set(zones or [])) != 0
        for _, zones, capacity in regions
    ):
        return Evaluation(
            outcome="unknown",
            summary="Unit counts do not establish a valid manual zone distribution.",
            evidence=evidence,
        )
    return Evaluation(
        outcome="pass",
        summary="Every collected region explicitly selects multiple availability zones.",
        evidence=evidence,
    )
