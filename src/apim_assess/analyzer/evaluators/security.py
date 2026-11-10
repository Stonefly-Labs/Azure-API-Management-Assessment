from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.findings import Evaluation, Evidence
from apim_assess.models.snapshot import Instance, Snapshot


def network_posture(instance: Instance, snapshot: Snapshot) -> Evaluation:
    if not instance.sku:
        return Evaluation(outcome="unknown", summary="SKU was not collected.")
    sku = instance.sku.name
    if sku in {"BasicV2", "Consumption"}:
        return Evaluation(
            outcome="unsupported",
            summary="This SKU does not support the assessed VNet/private-endpoint options.",
        )
    if sku not in CLASSIC | V2:
        return Evaluation(outcome="unknown", summary="Network capability for this SKU is unknown.")
    mode = instance.virtual_network_type
    connections = instance.private_endpoint_statuses
    evidence = [
        Evidence(
            source="ARM service properties (2024-05-01)",
            detail=(
                f"virtualNetworkType={mode}; private endpoint states={connections}; "
                f"publicNetworkAccess={instance.public_network_access}"
            ),
        )
    ]
    injected = (sku in {"Developer", "Premium"} and mode in {"Internal", "External"}) or (
        sku == "PremiumV2" and mode == "Internal"
    )
    if injected or (connections is not None and "Approved" in connections):
        return Evaluation(
            outcome="pass",
            summary=(
                "VNet injection or an approved inbound private endpoint is configured. "
                "This does not prove runtime isolation, NSG enforcement, or blocked public access."
            ),
            evidence=evidence,
        )
    if mode is None or connections is None or "Unknown" in connections:
        return Evaluation(
            outcome="unknown",
            summary="Network mode or private endpoint evidence was not fully collected.",
            evidence=evidence,
        )
    return Evaluation(
        outcome="fail",
        summary=(
            "No VNet injection or approved inbound private endpoint was observed. "
            "Outbound-only v2 integration is not inbound isolation."
        ),
        evidence=evidence,
    )
