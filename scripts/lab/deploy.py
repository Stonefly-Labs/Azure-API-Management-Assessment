"""Multi-phase deployment orchestrator for the apim-assess Azure validation lab.

Orchestrates:
1. Ensuring the disposable lab resource group (`rg-apv-lab-wus3-001`) exists with
   `SecurityControl=Ignore`.
2. Resolving persistent OIDC/bootstrap identities (`id-apv-gh-deploy-wus3-001` and
   `id-apv-gh-assess-wus3-001`).
3. Deploying `infra/lab/main.bicep` in `foundation` phase (AVM VNet, NSGs, Log
   Analytics, App Insights, ACR, Storage, Key Vault, and Microsoft Foundry models).
4. Building and pushing the lab workload/runner container image into ACR using
   `az acr build`.
5. Deploying `infra/lab/main.bicep` in `full` phase (Container Apps environment,
   REST/MCP/A2A apps, smoke/assess Container Apps Jobs, Developer APIM, BasicV2
   APIM, Private DNS, and APIM configuration).
6. Persisting sanitized deployment metadata to `.azure/lab-deployment.json`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MAIN_BICEP = REPO_ROOT / "infra" / "lab" / "main.bicep"
DEFAULT_OUTPUT_FILE = REPO_ROOT / ".azure" / "lab-deployment.json"


def _az_executable() -> str:
    exe = shutil.which("az") or shutil.which("az.cmd")
    if not exe:
        raise RuntimeError("Azure CLI ('az') was not found on PATH.")
    return exe


def run_az(args: list[str], *, check: bool = True) -> Any:
    cmd = [_az_executable(), *args, "--output", "json"]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Azure CLI command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr.strip()}"
        )
    stdout = proc.stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return stdout


def ensure_resource_group(subscription_id: str, resource_group: str, location: str) -> None:
    run_az(
        [
            "group",
            "create",
            "--subscription",
            subscription_id,
            "--name",
            resource_group,
            "--location",
            location,
            "--tags",
            "SecurityControl=Ignore",
            "project=apim-assess",
            "environment=validation-lab",
            "managedBy=bicep",
        ]
    )


def resolve_identity(
    subscription_id: str,
    ops_rg: str,
    identity_name: str,
) -> dict[str, str]:
    result = run_az(
        [
            "identity",
            "show",
            "--subscription",
            subscription_id,
            "--resource-group",
            ops_rg,
            "--name",
            identity_name,
        ],
        check=False,
    )
    if isinstance(result, dict) and result.get("id"):
        return {
            "resourceId": str(result["id"]),
            "clientId": str(result.get("clientId") or ""),
            "principalId": str(result.get("principalId") or ""),
        }
    return {"resourceId": "", "clientId": "", "principalId": ""}


def deploy_bicep_phase(
    *,
    subscription_id: str,
    resource_group: str,
    location: str,
    phase: str,
    tenant_id: str,
    apim_gateway_app_id: str,
    mcp_app_id: str,
    a2a_app_id: str,
    smoke_client_app_id: str,
    deploy_identity: dict[str, str],
    assess_identity: dict[str, str],
    workload_image: str,
    assess_image: str,
    apim_dev_name: str,
    apim_bv2_name: str,
) -> dict[str, Any]:
    deployment_name = f"apv-lab-{phase}"
    params = [
        f"location={location}",
        f"deploymentPhase={phase}",
        f"tenantId={tenant_id}",
        f"apimGatewayAppClientId={apim_gateway_app_id}",
        f"mcpBackendAppClientId={mcp_app_id}",
        f"a2aBackendAppClientId={a2a_app_id}",
        f"smokeClientAppClientId={smoke_client_app_id}",
        f"deployIdentityResourceId={deploy_identity['resourceId']}",
        f"deployIdentityClientId={deploy_identity['clientId']}",
        f"deployIdentityPrincipalId={deploy_identity['principalId']}",
        f"assessIdentityResourceId={assess_identity['resourceId']}",
        f"assessIdentityClientId={assess_identity['clientId']}",
        f"assessIdentityPrincipalId={assess_identity['principalId']}",
        f"workloadImage={workload_image}",
        f"assessImage={assess_image}",
        f"apimDevName={apim_dev_name}",
        f"apimBv2Name={apim_bv2_name}",
    ]
    result = run_az(
        [
            "deployment",
            "group",
            "create",
            "--subscription",
            subscription_id,
            "--resource-group",
            resource_group,
            "--name",
            deployment_name,
            "--template-file",
            str(MAIN_BICEP),
            "--parameters",
            *params,
        ]
    )
    if not isinstance(result, dict):
        raise RuntimeError(f"Unexpected Bicep deployment output for phase '{phase}'.")
    raw_outputs = result.get("properties", {}).get("outputs", {})
    return {
        key: val.get("value") if isinstance(val, dict) else val for key, val in raw_outputs.items()
    }


def build_and_push_acr_image(
    *,
    subscription_id: str,
    acr_name: str,
    image_tag: str,
) -> str:
    dockerfile_rel = "samples/validation_lab/Dockerfile"
    run_az(
        [
            "acr",
            "build",
            "--subscription",
            subscription_id,
            "--registry",
            acr_name,
            "--image",
            image_tag,
            "--file",
            dockerfile_rel,
            str(REPO_ROOT),
        ]
    )
    return f"{acr_name}.azurecr.io/{image_tag}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy the apim-assess validation lab.")
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
        help="Azure subscription ID.",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("AZURE_TENANT_ID", ""),
        help="Microsoft Entra tenant ID.",
    )
    parser.add_argument(
        "--resource-group",
        default=os.environ.get("AZURE_LAB_RESOURCE_GROUP", "rg-apv-lab-wus3-001"),
        help="Disposable lab resource group.",
    )
    parser.add_argument(
        "--bootstrap-resource-group",
        "--ops-resource-group",
        dest="bootstrap_resource_group",
        default=os.environ.get(
            "AZURE_BOOTSTRAP_RESOURCE_GROUP",
            os.environ.get("AZURE_OPS_RESOURCE_GROUP", "rg-apv-bootstrap-wus3-001"),
        ),
        help="Persistent OIDC bootstrap resource group.",
    )
    parser.add_argument(
        "--location",
        default=os.environ.get("AZURE_LOCATION", "westus3"),
        help="Azure region for the validation lab.",
    )
    parser.add_argument(
        "--apim-dev-name",
        default=os.environ.get("LAB_APIM_DEV_NAME", "apim-apv-dev-wus3-001"),
    )
    parser.add_argument(
        "--apim-bv2-name",
        default=os.environ.get("LAB_APIM_BV2_NAME", "apim-apv-bv2-wus3-001"),
    )
    parser.add_argument(
        "--image-tag",
        default=os.environ.get("LAB_IMAGE_TAG", "apim-assess-lab:latest"),
        help="Container image repository:tag inside ACR.",
    )
    parser.add_argument(
        "--phase",
        choices=["foundation", "full", "all"],
        default="all",
        help="Deployment stage to execute.",
    )
    parser.add_argument(
        "--skip-image-build",
        action="store_true",
        help="Skip `az acr build` if the image already exists in ACR.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help="Path to write sanitized deployment outputs JSON.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    account = run_az(["account", "show"]) if not (args.subscription_id and args.tenant_id) else {}
    subscription_id = args.subscription_id or str(account.get("id") or "")
    tenant_id = args.tenant_id or str(account.get("tenantId") or "")
    if not subscription_id or not tenant_id:
        raise RuntimeError("Subscription ID and Tenant ID are required.")

    bootstrap_meta_path = REPO_ROOT / ".azure" / "lab-bootstrap.json"
    bootstrap_meta: dict[str, Any] = {}
    if bootstrap_meta_path.exists():
        bootstrap_meta = json.loads(bootstrap_meta_path.read_text(encoding="utf-8"))

    mcp_app_id = (
        os.environ.get("LAB_ENTRA_MCP_APP_ID")
        or bootstrap_meta.get("LAB_ENTRA_MCP_APP_ID")
        or bootstrap_meta.get("entraApps", {}).get("mcp", {}).get("appId")
        or "00000000-0000-0000-0000-000000000002"
    )
    apim_gateway_app_id = (
        os.environ.get("LAB_ENTRA_GATEWAY_APP_ID")
        or bootstrap_meta.get("LAB_ENTRA_GATEWAY_APP_ID")
        or bootstrap_meta.get("entraApps", {}).get("gateway", {}).get("appId")
        or mcp_app_id
    )
    a2a_app_id = (
        os.environ.get("LAB_ENTRA_A2A_APP_ID")
        or bootstrap_meta.get("LAB_ENTRA_A2A_APP_ID")
        or bootstrap_meta.get("entraApps", {}).get("a2a", {}).get("appId")
        or "00000000-0000-0000-0000-000000000003"
    )
    smoke_client_app_id = (
        os.environ.get("LAB_ENTRA_CLIENT_APP_ID")
        or bootstrap_meta.get("LAB_ENTRA_CLIENT_APP_ID")
        or bootstrap_meta.get("entraApps", {}).get("client", {}).get("appId")
        or "00000000-0000-0000-0000-000000000004"
    )

    ensure_resource_group(subscription_id, args.resource_group, args.location)
    deploy_identity = resolve_identity(
        subscription_id, args.bootstrap_resource_group, "id-apv-gh-deploy-wus3-001"
    )
    assess_identity = resolve_identity(
        subscription_id, args.bootstrap_resource_group, "id-apv-gh-assess-wus3-001"
    )

    placeholder_image = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
    outputs: dict[str, Any] = {}
    if args.output_file.exists():
        try:
            existing_summary = json.loads(args.output_file.read_text(encoding="utf-8"))
            if isinstance(existing_summary.get("outputs"), dict):
                outputs = dict(existing_summary["outputs"])
        except json.JSONDecodeError:
            outputs = {}

    if args.phase in {"foundation", "all"}:
        print(
            f"[lab-deploy] Deploying foundation phase to {args.resource_group} ({args.location})..."
        )
        outputs = deploy_bicep_phase(
            subscription_id=subscription_id,
            resource_group=args.resource_group,
            location=args.location,
            phase="foundation",
            tenant_id=tenant_id,
            apim_gateway_app_id=apim_gateway_app_id,
            mcp_app_id=mcp_app_id,
            a2a_app_id=a2a_app_id,
            smoke_client_app_id=smoke_client_app_id,
            deploy_identity=deploy_identity,
            assess_identity=assess_identity,
            workload_image=placeholder_image,
            assess_image=placeholder_image,
            apim_dev_name=args.apim_dev_name,
            apim_bv2_name=args.apim_bv2_name,
        )

    acr_name = str(outputs.get("acrName") or os.environ.get("LAB_ACR_NAME") or "")
    acr_login_server = str(
        outputs.get("acrLoginServer") or (f"{acr_name}.azurecr.io" if acr_name else "")
    )
    full_image = f"{acr_login_server}/{args.image_tag}" if acr_login_server else placeholder_image

    if args.phase in {"full", "all"}:
        if acr_name and not args.skip_image_build:
            print(f"[lab-deploy] Building and pushing container image {full_image} via ACR...")
            full_image = build_and_push_acr_image(
                subscription_id=subscription_id,
                acr_name=acr_name,
                image_tag=args.image_tag,
            )
        print(f"[lab-deploy] Deploying full lab topology to {args.resource_group}...")
        outputs = deploy_bicep_phase(
            subscription_id=subscription_id,
            resource_group=args.resource_group,
            location=args.location,
            phase="full",
            tenant_id=tenant_id,
            apim_gateway_app_id=apim_gateway_app_id,
            mcp_app_id=mcp_app_id,
            a2a_app_id=a2a_app_id,
            smoke_client_app_id=smoke_client_app_id,
            deploy_identity=deploy_identity,
            assess_identity=assess_identity,
            workload_image=full_image,
            assess_image=full_image,
            apim_dev_name=args.apim_dev_name,
            apim_bv2_name=args.apim_bv2_name,
        )

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "subscriptionId": subscription_id,
        "tenantId": tenant_id,
        "resourceGroup": args.resource_group,
        "location": args.location,
        "image": full_image,
        "outputs": outputs,
    }
    args.output_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[lab-deploy] Deployment outputs written to {args.output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
