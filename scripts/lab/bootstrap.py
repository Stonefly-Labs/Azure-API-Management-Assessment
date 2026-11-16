from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_LOCATION = "westus3"
DEFAULT_BOOTSTRAP_RG = "rg-apv-bootstrap-wus3-001"
DEFAULT_LAB_RG = "rg-apv-lab-wus3-001"
DEFAULT_REPO = "Stonefly-Labs/Azure-API-Management-Assessment"
DEFAULT_GH_ENV = "azure-lab"
DEFAULT_BOOTSTRAP_META_FILE = Path(".azure/lab-bootstrap.json")

MCP_APP_DISPLAY_NAME = "app-apv-mcp-api"
MCP_ROLE_VALUE = "Mcp.Tool.Invoke"
MCP_ROLE_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "apim-assess.lab.mcp.role"))

A2A_APP_DISPLAY_NAME = "app-apv-a2a-api"
A2A_ROLE_VALUE = "A2A.Agent.Invoke"
A2A_ROLE_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "apim-assess.lab.a2a.role"))

CLIENT_APP_DISPLAY_NAME = "app-apv-lab-client"


@dataclass(frozen=True)
class BootstrapResult:
    subscription_id: str
    tenant_id: str
    location: str
    bootstrap_resource_group: str
    lab_resource_group: str
    deploy_client_id: str
    deploy_principal_id: str
    assess_client_id: str
    assess_principal_id: str
    mcp_app_id: str
    mcp_sp_object_id: str
    mcp_identifier_uri: str
    a2a_app_id: str
    a2a_sp_object_id: str
    a2a_identifier_uri: str
    client_app_id: str
    client_sp_object_id: str

    def github_variables(self) -> dict[str, str]:
        return {
            "AZURE_TENANT_ID": self.tenant_id,
            "AZURE_SUBSCRIPTION_ID": self.subscription_id,
            "AZURE_LOCATION": self.location,
            "AZURE_BOOTSTRAP_RESOURCE_GROUP": self.bootstrap_resource_group,
            "AZURE_LAB_RESOURCE_GROUP": self.lab_resource_group,
            "AZURE_DEPLOY_CLIENT_ID": self.deploy_client_id,
            "AZURE_ASSESS_CLIENT_ID": self.assess_client_id,
            "AZURE_ASSESS_PRINCIPAL_ID": self.assess_principal_id,
            "LAB_ENTRA_GATEWAY_APP_ID": self.mcp_app_id,
            "LAB_ENTRA_MCP_APP_ID": self.mcp_app_id,
            "LAB_ENTRA_MCP_AUDIENCE": self.mcp_identifier_uri,
            "LAB_ENTRA_MCP_SP_ID": self.mcp_sp_object_id,
            "LAB_ENTRA_MCP_ROLE_ID": MCP_ROLE_ID,
            "LAB_ENTRA_A2A_APP_ID": self.a2a_app_id,
            "LAB_ENTRA_A2A_AUDIENCE": self.a2a_identifier_uri,
            "LAB_ENTRA_A2A_SP_ID": self.a2a_sp_object_id,
            "LAB_ENTRA_A2A_ROLE_ID": A2A_ROLE_ID,
            "LAB_ENTRA_CLIENT_APP_ID": self.client_app_id,
            "LAB_ENTRA_CLIENT_SP_ID": self.client_sp_object_id,
        }


def _resolve_cli(name: str) -> str:
    resolved = shutil.which(name) or shutil.which(f"{name}.cmd") or shutil.which(f"{name}.exe")
    if not resolved:
        raise RuntimeError(f"Required CLI '{name}' was not found on PATH.")
    return resolved


def run_cli_json(cmd: list[str]) -> Any:
    exe = _resolve_cli(cmd[0])
    proc = subprocess.run(
        [exe, *cmd[1:]],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {proc.stderr.strip()}")
    stdout = proc.stdout.strip()
    return json.loads(stdout) if stdout else None


def run_cli_text(cmd: list[str], *, input_text: str | None = None) -> str:
    exe = _resolve_cli(cmd[0])
    proc = subprocess.run(
        [exe, *cmd[1:]],
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def ensure_resource_group(name: str, location: str, subscription_id: str) -> None:
    run_cli_json(
        [
            "az",
            "group",
            "create",
            "--name",
            name,
            "--location",
            location,
            "--subscription",
            subscription_id,
            "--tags",
            "SecurityControl=Ignore",
            "project=apim-assess",
            "environment=validation-lab",
            "managedBy=bicep",
            "-o",
            "json",
        ]
    )


def deploy_bootstrap_bicep(
    *,
    subscription_id: str,
    bootstrap_rg: str,
    location: str,
    github_repo: str,
    github_env: str,
    template_path: Path,
) -> dict[str, str]:
    deployment = run_cli_json(
        [
            "az",
            "deployment",
            "group",
            "create",
            "--subscription",
            subscription_id,
            "--resource-group",
            bootstrap_rg,
            "--name",
            "apv-lab-bootstrap",
            "--template-file",
            str(template_path),
            "--parameters",
            f"location={location}",
            f"githubRepository={github_repo}",
            f"githubEnvironment={github_env}",
            "-o",
            "json",
        ]
    )
    outputs = deployment.get("properties", {}).get("outputs", {})
    return {key: str(val.get("value", "")) for key, val in outputs.items()}


def ensure_role_assignment(
    *,
    principal_id: str,
    role: str,
    scope: str,
    principal_type: str = "ServicePrincipal",
) -> None:
    existing = run_cli_json(
        [
            "az",
            "role",
            "assignment",
            "list",
            "--assignee-object-id",
            principal_id,
            "--role",
            role,
            "--scope",
            scope,
            "-o",
            "json",
        ]
    )
    if isinstance(existing, list) and existing:
        return
    run_cli_json(
        [
            "az",
            "role",
            "assignment",
            "create",
            "--assignee-object-id",
            principal_id,
            "--assignee-principal-type",
            principal_type,
            "--role",
            role,
            "--scope",
            scope,
            "-o",
            "json",
        ]
    )


def ensure_api_app_registration(
    *,
    display_name: str,
    role_id: str,
    role_value: str,
    role_description: str,
) -> tuple[str, str, str]:
    apps = run_cli_json(
        [
            "az",
            "ad",
            "app",
            "list",
            "--display-name",
            display_name,
            "-o",
            "json",
        ]
    )
    app_roles = [
        {
            "allowedMemberTypes": ["Application", "User"],
            "description": role_description,
            "displayName": role_value,
            "id": role_id,
            "isEnabled": True,
            "value": role_value,
        }
    ]
    roles_json = json.dumps(app_roles)
    if isinstance(apps, list) and apps:
        app = apps[0]
        app_id = str(app["appId"])
        run_cli_text(
            [
                "az",
                "ad",
                "app",
                "update",
                "--id",
                app_id,
                "--app-roles",
                roles_json,
            ]
        )
    else:
        app = run_cli_json(
            [
                "az",
                "ad",
                "app",
                "create",
                "--display-name",
                display_name,
                "--sign-in-audience",
                "AzureADMyOrg",
                "--app-roles",
                roles_json,
                "-o",
                "json",
            ]
        )
        app_id = str(app["appId"])

    identifier_uri = f"api://{app_id}"
    run_cli_text(
        [
            "az",
            "ad",
            "app",
            "update",
            "--id",
            app_id,
            "--identifier-uris",
            identifier_uri,
        ]
    )
    sp_object_id = ensure_service_principal(app_id)
    return app_id, sp_object_id, identifier_uri


def ensure_client_app_registration(display_name: str) -> tuple[str, str]:
    apps = run_cli_json(
        [
            "az",
            "ad",
            "app",
            "list",
            "--display-name",
            display_name,
            "-o",
            "json",
        ]
    )
    if isinstance(apps, list) and apps:
        app_id = str(apps[0]["appId"])
    else:
        app = run_cli_json(
            [
                "az",
                "ad",
                "app",
                "create",
                "--display-name",
                display_name,
                "--sign-in-audience",
                "AzureADMyOrg",
                "-o",
                "json",
            ]
        )
        app_id = str(app["appId"])
    sp_object_id = ensure_service_principal(app_id)
    return app_id, sp_object_id


def ensure_service_principal(app_id: str) -> str:
    sps = run_cli_json(
        [
            "az",
            "ad",
            "sp",
            "list",
            "--filter",
            f"appId eq '{app_id}'",
            "-o",
            "json",
        ]
    )
    if isinstance(sps, list) and sps:
        return str(sps[0]["id"])
    sp = run_cli_json(["az", "ad", "sp", "create", "--id", app_id, "-o", "json"])
    return str(sp["id"])


def ensure_app_role_assignment(
    *,
    principal_sp_id: str,
    resource_sp_id: str,
    app_role_id: str,
) -> None:
    existing = run_cli_json(
        [
            "az",
            "rest",
            "--method",
            "GET",
            "--url",
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_sp_id}/appRoleAssignments",
            "-o",
            "json",
        ]
    )
    items = existing.get("value", []) if isinstance(existing, dict) else []
    for item in items:
        if (
            str(item.get("resourceId", "")).casefold() == resource_sp_id.casefold()
            and str(item.get("appRoleId", "")).casefold() == app_role_id.casefold()
        ):
            return
    body = json.dumps(
        {
            "principalId": principal_sp_id,
            "resourceId": resource_sp_id,
            "appRoleId": app_role_id,
        }
    )
    run_cli_json(
        [
            "az",
            "rest",
            "--method",
            "POST",
            "--url",
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_sp_id}/appRoleAssignments",
            "--headers",
            "Content-Type=application/json",
            "--body",
            body,
            "-o",
            "json",
        ]
    )


def sync_github_environment_variables(
    *,
    repo: str,
    environment: str,
    variables: dict[str, str],
) -> None:
    run_cli_text(
        [
            "gh",
            "api",
            "--method",
            "PUT",
            f"repos/{repo}/environments/{environment}",
        ]
    )
    for key, value in sorted(variables.items()):
        run_cli_text(
            [
                "gh",
                "variable",
                "set",
                key,
                "--repo",
                repo,
                "--env",
                environment,
                "--body",
                value,
            ]
        )


def resolve_account_context(
    subscription_id: str | None = None,
    tenant_id: str | None = None,
) -> tuple[str, str]:
    sub = (subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip()
    ten = (tenant_id or os.environ.get("AZURE_TENANT_ID") or "").strip()
    if not sub or not ten:
        account = run_cli_json(["az", "account", "show", "-o", "json"])
        if isinstance(account, dict):
            sub = sub or str(account.get("id") or "")
            ten = ten or str(account.get("tenantId") or "")
    if not sub or not ten:
        raise RuntimeError(
            "Subscription ID and Tenant ID are required (pass --subscription-id/--tenant-id "
            "or authenticate via `az login`)."
        )
    return sub, ten


def bootstrap_lab(
    *,
    subscription_id: str | None = None,
    tenant_id: str | None = None,
    location: str = DEFAULT_LOCATION,
    bootstrap_rg: str = DEFAULT_BOOTSTRAP_RG,
    lab_rg: str = DEFAULT_LAB_RG,
    repo: str = DEFAULT_REPO,
    github_env: str = DEFAULT_GH_ENV,
    sync_github: bool = True,
) -> BootstrapResult:
    resolved_sub, resolved_tenant = resolve_account_context(subscription_id, tenant_id)
    ensure_resource_group(bootstrap_rg, location, resolved_sub)
    ensure_resource_group(lab_rg, location, resolved_sub)

    template_path = Path("infra/lab/bootstrap.bicep")
    outputs = deploy_bootstrap_bicep(
        subscription_id=resolved_sub,
        bootstrap_rg=bootstrap_rg,
        location=location,
        github_repo=repo,
        github_env=github_env,
        template_path=template_path,
    )

    deploy_principal_id = outputs["deployIdentityPrincipalId"]
    assess_principal_id = outputs["assessIdentityPrincipalId"]

    bootstrap_scope = f"/subscriptions/{resolved_sub}/resourceGroups/{bootstrap_rg}"
    lab_scope = f"/subscriptions/{resolved_sub}/resourceGroups/{lab_rg}"

    # Least-privilege RBAC for deploy identity
    ensure_role_assignment(principal_id=deploy_principal_id, role="Reader", scope=bootstrap_scope)
    ensure_role_assignment(principal_id=deploy_principal_id, role="Contributor", scope=lab_scope)
    ensure_role_assignment(
        principal_id=deploy_principal_id,
        role="Role Based Access Control Administrator",
        scope=lab_scope,
    )

    # Least-privilege RBAC for read-only assess identity
    ensure_role_assignment(principal_id=assess_principal_id, role="Reader", scope=bootstrap_scope)
    ensure_role_assignment(principal_id=assess_principal_id, role="Reader", scope=lab_scope)
    ensure_role_assignment(
        principal_id=assess_principal_id,
        role="API Management Service Reader Role",
        scope=lab_scope,
    )
    ensure_role_assignment(
        principal_id=assess_principal_id,
        role="Monitoring Reader",
        scope=lab_scope,
    )
    ensure_role_assignment(
        principal_id=assess_principal_id,
        role="Log Analytics Reader",
        scope=lab_scope,
    )
    ensure_role_assignment(
        principal_id=assess_principal_id,
        role="Security Reader",
        scope=lab_scope,
    )

    # Entra App Registrations & App Role Assignments
    mcp_app_id, mcp_sp_id, mcp_uri = ensure_api_app_registration(
        display_name=MCP_APP_DISPLAY_NAME,
        role_id=MCP_ROLE_ID,
        role_value=MCP_ROLE_VALUE,
        role_description="Invoke MCP tools exposed by the validation lab.",
    )
    a2a_app_id, a2a_sp_id, a2a_uri = ensure_api_app_registration(
        display_name=A2A_APP_DISPLAY_NAME,
        role_id=A2A_ROLE_ID,
        role_value=A2A_ROLE_VALUE,
        role_description="Invoke A2A agent endpoints exposed by the validation lab.",
    )
    client_app_id, client_sp_id = ensure_client_app_registration(CLIENT_APP_DISPLAY_NAME)

    for caller_sp_id in (client_sp_id, deploy_principal_id, assess_principal_id):
        ensure_app_role_assignment(
            principal_sp_id=caller_sp_id,
            resource_sp_id=mcp_sp_id,
            app_role_id=MCP_ROLE_ID,
        )
        ensure_app_role_assignment(
            principal_sp_id=caller_sp_id,
            resource_sp_id=a2a_sp_id,
            app_role_id=A2A_ROLE_ID,
        )

    result = BootstrapResult(
        subscription_id=resolved_sub,
        tenant_id=resolved_tenant,
        location=location,
        bootstrap_resource_group=bootstrap_rg,
        lab_resource_group=lab_rg,
        deploy_client_id=outputs["deployIdentityClientId"],
        deploy_principal_id=deploy_principal_id,
        assess_client_id=outputs["assessIdentityClientId"],
        assess_principal_id=assess_principal_id,
        mcp_app_id=mcp_app_id,
        mcp_sp_object_id=mcp_sp_id,
        mcp_identifier_uri=mcp_uri,
        a2a_app_id=a2a_app_id,
        a2a_sp_object_id=a2a_sp_id,
        a2a_identifier_uri=a2a_uri,
        client_app_id=client_app_id,
        client_sp_object_id=client_sp_id,
    )

    if sync_github:
        sync_github_environment_variables(
            repo=repo,
            environment=github_env,
            variables=result.github_variables(),
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap Azure OIDC identities, Entra apps, and GitHub environment variables."
    )
    parser.add_argument("--subscription-id", default=os.environ.get("AZURE_SUBSCRIPTION_ID"))
    parser.add_argument("--tenant-id", default=os.environ.get("AZURE_TENANT_ID"))
    parser.add_argument("--location", default=DEFAULT_LOCATION)
    parser.add_argument("--bootstrap-rg", default=DEFAULT_BOOTSTRAP_RG)
    parser.add_argument("--lab-rg", default=DEFAULT_LAB_RG)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--github-env", default=DEFAULT_GH_ENV)
    parser.add_argument("--no-github-sync", action="store_true")
    parser.add_argument("--output-json", type=Path, default=DEFAULT_BOOTSTRAP_META_FILE)
    args = parser.parse_args()

    result = bootstrap_lab(
        subscription_id=args.subscription_id,
        tenant_id=args.tenant_id,
        location=args.location,
        bootstrap_rg=args.bootstrap_rg,
        lab_rg=args.lab_rg,
        repo=args.repo,
        github_env=args.github_env,
        sync_github=not args.no_github_sync,
    )
    summary = {
        "bootstrap_resource_group": result.bootstrap_resource_group,
        "lab_resource_group": result.lab_resource_group,
        "location": result.location,
        "mcp_audience": result.mcp_identifier_uri,
        "a2a_audience": result.a2a_identifier_uri,
        "github_environment": args.github_env,
    }
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(
            json.dumps(result.github_variables(), indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
