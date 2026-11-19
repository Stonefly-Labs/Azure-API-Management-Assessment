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
import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.lab.acme_cloudflare import (  # noqa: E402
    DEFAULT_CERT_NAME,
    DEFAULT_ZONE_NAME,
    LETSENCRYPT_PROD_DIRECTORY,
    ensure_keyvault_wildcard_certificate,
    generate_short_lived_custom_pfx_base64,
    upsert_lab_dns_records,
)

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


def resolve_hostname_ipv4(hostname: str) -> str:
    """Resolve an IPv4 address for a hostname, returning empty string if not resolvable."""
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return ""


def resolve_existing_keyvault_name(subscription_id: str, resource_group: str) -> str:
    """Find the lab Key Vault (`kv-apv-lab-*`) inside the resource group."""
    result = run_az(
        [
            "keyvault",
            "list",
            "--subscription",
            subscription_id,
            "--resource-group",
            resource_group,
        ],
        check=False,
    )
    if isinstance(result, list):
        for item in result:
            name = str(item.get("name") or "")
            if name.startswith("kv-apv-lab-"):
                return name
    return ""


def ensure_caller_kv_cert_officer(
    subscription_id: str,
    resource_group: str,
    vault_name: str,
) -> None:
    """Best-effort grant of Key Vault Certificates Officer to the signed-in user for local runs."""
    user = run_az(["ad", "signed-in-user", "show"], check=False)
    if not isinstance(user, dict) or not user.get("id"):
        return
    principal_id = str(user["id"])
    scope = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.KeyVault/vaults/{vault_name}"
    )
    run_az(
        [
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            principal_id,
            "--assignee-principal-type",
            "User",
            "--role",
            "a4417e6f-fecd-4de8-b567-7b0420556985",
            "--scope",
            scope,
        ],
        check=False,
    )


def is_apim_dev_custom_domain_converged(
    subscription_id: str,
    resource_group: str,
    apim_dev_name: str,
    expected_hostname: str,
) -> bool:
    """Return True if Developer APIM is Succeeded and already binds the custom domain."""
    info = run_az(
        [
            "apim",
            "show",
            "--subscription",
            subscription_id,
            "--resource-group",
            resource_group,
            "--name",
            apim_dev_name,
        ],
        check=False,
    )
    if not isinstance(info, dict):
        return False
    if str(info.get("provisioningState") or "") != "Succeeded":
        return False
    if str(info.get("virtualNetworkType") or "") != "Internal":
        return False
    if not expected_hostname:
        return True
    hostnames = info.get("hostnameConfigurations")
    if not isinstance(hostnames, list):
        return False
    for item in hostnames:
        if not isinstance(item, dict):
            continue
        host = str(item.get("hostName") or "").lower()
        source = str(item.get("certificateSource") or "")
        if host == expected_hostname.lower() and source == "Custom":
            cert_obj = item.get("certificate")
            expiry_raw = cert_obj.get("expiry") if isinstance(cert_obj, dict) else None
            if isinstance(expiry_raw, str) and expiry_raw:
                try:
                    expiry = dt.datetime.fromisoformat(expiry_raw.replace("Z", "+00:00"))
                    days = (expiry - dt.datetime.now(dt.UTC)).total_seconds() / 86400.0
                    if 1.0 <= days <= 25.0:
                        return True
                except ValueError:
                    return True
            else:
                return True
    return False


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
    custom_domain_zone: str = DEFAULT_ZONE_NAME,
    wildcard_cert_secret_uri: str = "",
    dev_custom_cert_pfx_base64: str = "",
    apim_bv2_public_ip: str = "",
    foundry_public_ip: str = "",
    skip_apim_dev_service_update: bool = False,
) -> dict[str, Any]:
    deployment_name = f"apv-lab-{phase}"
    clean_zone = custom_domain_zone.strip().lstrip("*.").rstrip(".")
    param_values: dict[str, Any] = {
        "location": location,
        "deploymentPhase": phase,
        "tenantId": tenant_id,
        "apimGatewayAppClientId": apim_gateway_app_id,
        "mcpBackendAppClientId": mcp_app_id,
        "a2aBackendAppClientId": a2a_app_id,
        "smokeClientAppClientId": smoke_client_app_id,
        "deployIdentityResourceId": deploy_identity["resourceId"],
        "deployIdentityClientId": deploy_identity["clientId"],
        "deployIdentityPrincipalId": deploy_identity["principalId"],
        "assessIdentityResourceId": assess_identity["resourceId"],
        "assessIdentityClientId": assess_identity["clientId"],
        "assessIdentityPrincipalId": assess_identity["principalId"],
        "workloadImage": workload_image,
        "assessImage": assess_image,
        "apimDevName": apim_dev_name,
        "apimBv2Name": apim_bv2_name,
        "apimBv2PublicIp": apim_bv2_public_ip,
        "foundryPublicIp": foundry_public_ip,
        "wildcardCertKeyVaultSecretUri": wildcard_cert_secret_uri,
        "agwBv2HostName": f"agw-bv2.{clean_zone}",
        "agwDevHostName": f"agw-dev.{clean_zone}",
        "bv2CustomDomainHostName": f"api-bv2.{clean_zone}" if wildcard_cert_secret_uri else "",
        "devCustomDomainHostName": f"api-dev.{clean_zone}" if dev_custom_cert_pfx_base64 else "",
        "devCustomDomainEncodedCertificate": dev_custom_cert_pfx_base64,
        "devCustomDomainCertificatePassword": "",
        "skipApimDevServiceUpdate": skip_apim_dev_service_update,
    }
    arm_params_doc = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {k: {"value": v} for k, v in param_values.items()},
    }
    with tempfile.TemporaryDirectory() as tmp_dir:
        params_file = Path(tmp_dir) / f"{deployment_name}.parameters.json"
        params_file.write_text(json.dumps(arm_params_doc), encoding="utf-8")
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
                f"@{params_file}",
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
        default=os.environ.get("AZURE_LAB_RESOURCE_GROUP", "rg-apim-assess-lab"),
        help="Validation lab resource group.",
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
        "--custom-domain-zone",
        default=os.environ.get("LAB_CUSTOM_DOMAIN_ZONE", DEFAULT_ZONE_NAME),
        help="Cloudflare DNS zone for Application Gateway and APIM custom domains.",
    )
    parser.add_argument(
        "--cloudflare-api-token",
        default=os.environ.get("CLOUDFLARE_API_TOKEN", ""),
        help="Cloudflare API token with Zone:Read and DNS:Edit permissions.",
    )
    parser.add_argument(
        "--keyvault-cert-name",
        default=os.environ.get("LAB_KEYVAULT_CERT_NAME", DEFAULT_CERT_NAME),
        help="Key Vault certificate name for the ACME wildcard certificate.",
    )
    parser.add_argument(
        "--acme-directory-url",
        default=os.environ.get("LAB_ACME_DIRECTORY_URL", LETSENCRYPT_PROD_DIRECTORY),
        help="ACME v2 directory URL.",
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
            f"[lab-deploy] Deploying foundation phase to {args.resource_group} "
            f"({args.location})...",
            flush=True,
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
            print(
                f"[lab-deploy] Building and pushing container image {full_image} via ACR...",
                flush=True,
            )
            full_image = build_and_push_acr_image(
                subscription_id=subscription_id,
                acr_name=acr_name,
                image_tag=args.image_tag,
            )

        key_vault_name = str(
            outputs.get("keyVaultName")
            or os.environ.get("LAB_KEY_VAULT_NAME")
            or resolve_existing_keyvault_name(subscription_id, args.resource_group)
        )
        wildcard_cert_secret_uri = ""
        dev_custom_cert_pfx_base64 = ""
        if key_vault_name:
            ensure_caller_kv_cert_officer(subscription_id, args.resource_group, key_vault_name)
            try:
                wildcard_cert_secret_uri = ensure_keyvault_wildcard_certificate(
                    vault_name=key_vault_name,
                    cert_name=args.keyvault_cert_name,
                    cloudflare_api_token=args.cloudflare_api_token,
                    zone_name=args.custom_domain_zone,
                    directory_url=args.acme_directory_url,
                    run_az_fn=run_az,
                )
            except RuntimeError as exc:
                if args.cloudflare_api_token:
                    raise
                print(f"[lab-deploy] Skipping Key Vault wildcard cert setup: {exc}", flush=True)

        if wildcard_cert_secret_uri:
            dev_custom_cert_pfx_base64 = generate_short_lived_custom_pfx_base64(
                hostname=f"api-dev.{args.custom_domain_zone}",
                validity_days=14,
            )

        apim_bv2_public_ip = resolve_hostname_ipv4(f"{args.apim_bv2_name}.azure-api.net")
        foundry_public_ip = (
            resolve_hostname_ipv4("cognitiveusw3prod.azure-api.net") or "20.125.157.138"
        )
        apim_bv2_default_host = f"{args.apim_bv2_name}.azure-api.net"
        apim_dev_private_ip = str(outputs.get("apimDevPrivateIp") or "10.240.1.4")

        if args.cloudflare_api_token and wildcard_cert_secret_uri:
            print(
                f"[lab-deploy] Pre-seeding APIM custom domain DNS records in "
                f"{args.custom_domain_zone} before Bicep ownership check...",
                flush=True,
            )
            upsert_lab_dns_records(
                cloudflare_api_token=args.cloudflare_api_token,
                zone_name=args.custom_domain_zone,
                appgw_public_ip=str(outputs.get("appGwPublicIpAddress") or ""),
                apim_bv2_default_hostname=apim_bv2_default_host,
                apim_dev_private_ip=apim_dev_private_ip,
            )
            time.sleep(10.0)

        clean_zone = args.custom_domain_zone.strip().lstrip("*.").rstrip(".")
        expected_dev_host = f"api-dev.{clean_zone}" if dev_custom_cert_pfx_base64 else ""
        skip_dev_update = is_apim_dev_custom_domain_converged(
            subscription_id=subscription_id,
            resource_group=args.resource_group,
            apim_dev_name=args.apim_dev_name,
            expected_hostname=expected_dev_host,
        )
        if skip_dev_update:
            print(
                f"[lab-deploy] {args.apim_dev_name} already converged with {expected_dev_host}; "
                "skipping 15-min stv2 service update.",
                flush=True,
            )

        print(f"[lab-deploy] Deploying full lab topology to {args.resource_group}...", flush=True)
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
            custom_domain_zone=args.custom_domain_zone,
            wildcard_cert_secret_uri=wildcard_cert_secret_uri,
            dev_custom_cert_pfx_base64=dev_custom_cert_pfx_base64,
            apim_bv2_public_ip=apim_bv2_public_ip,
            foundry_public_ip=foundry_public_ip,
            skip_apim_dev_service_update=skip_dev_update,
        )

        appgw_public_ip = str(outputs.get("appGwPublicIpAddress") or "")
        if args.cloudflare_api_token and appgw_public_ip:
            apim_dev_private_ip = str(outputs.get("apimDevPrivateIp") or apim_dev_private_ip)
            print(
                f"[lab-deploy] Upserting Cloudflare DNS records in {args.custom_domain_zone} "
                f"(AppGW IP {appgw_public_ip})...",
                flush=True,
            )
            upsert_lab_dns_records(
                cloudflare_api_token=args.cloudflare_api_token,
                zone_name=args.custom_domain_zone,
                appgw_public_ip=appgw_public_ip,
                apim_bv2_default_hostname=apim_bv2_default_host,
                apim_dev_private_ip=apim_dev_private_ip,
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
    print(f"[lab-deploy] Deployment outputs written to {args.output_file}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
