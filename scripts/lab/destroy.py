"""Scoped teardown and soft-delete tombstone purge script for the validation lab.

Safely deletes ONLY the disposable lab resource group (`rg-apv-lab-wus3-001`)
and purges ONLY the lab's soft-deleted resources (`apim-apv-*`, `ais-apv-lab-*`,
`kv-apv-lab-*`) in `westus3`. Never touches the persistent bootstrap resource
group (`rg-apv-bootstrap-wus3-001`) or unrelated subscription resources.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any

PROTECTED_RESOURCE_GROUPS = {"rg-apv-bootstrap-wus3-001", "rg-apv-ops-wus3-001"}
ALLOWED_APIM_PREFIX = "apim-apv-"
ALLOWED_FOUNDRY_PREFIX = "ais-apv-lab-"
ALLOWED_KV_PREFIX = "kv-apv-lab-"


def _az_executable() -> str:
    exe = shutil.which("az") or shutil.which("az.cmd")
    if not exe:
        raise RuntimeError("Azure CLI ('az') was not found on PATH.")
    return exe


def run_az(args: list[str], *, check: bool = True) -> Any:
    cmd = [_az_executable(), *args, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
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


def validate_destroy_scope(resource_group: str) -> None:
    if resource_group in PROTECTED_RESOURCE_GROUPS:
        raise ValueError(
            f"Refusing to delete protected bootstrap resource group '{resource_group}'."
        )
    if not resource_group.startswith("rg-apv-lab-"):
        raise ValueError(
            f"Refusing to delete resource group '{resource_group}' "
            "outside the 'rg-apv-lab-*' prefix."
        )


def delete_lab_resource_group(
    *,
    subscription_id: str,
    resource_group: str,
    no_wait: bool = False,
) -> bool:
    validate_destroy_scope(resource_group)
    exists = run_az(
        [
            "group",
            "exists",
            "--subscription",
            subscription_id,
            "--name",
            resource_group,
        ]
    )
    if not exists:
        print(f"[lab-destroy] Resource group '{resource_group}' does not exist; skipping delete.")
        return False

    print(f"[lab-destroy] Deleting disposable lab resource group '{resource_group}'...")
    cmd = [
        "group",
        "delete",
        "--subscription",
        subscription_id,
        "--name",
        resource_group,
        "--yes",
    ]
    if no_wait:
        cmd.append("--no-wait")
    run_az(cmd)
    return True


def purge_soft_deleted_apim(subscription_id: str, location: str) -> list[str]:
    deleted = run_az(
        ["apim", "deletedservice", "list", "--subscription", subscription_id],
        check=False,
    )
    purged: list[str] = []
    if not isinstance(deleted, list):
        return purged

    for item in deleted:
        name = str(item.get("name") or "")
        item_loc = str(item.get("location") or "").lower().replace(" ", "")
        if name.startswith(ALLOWED_APIM_PREFIX) and item_loc == location.lower():
            print(f"[lab-destroy] Purging soft-deleted APIM instance '{name}' in '{location}'...")
            run_az(
                [
                    "apim",
                    "deletedservice",
                    "purge",
                    "--subscription",
                    subscription_id,
                    "--service-name",
                    name,
                    "--location",
                    location,
                ],
                check=False,
            )
            purged.append(name)
    return purged


def purge_soft_deleted_foundry(
    subscription_id: str,
    resource_group: str,
    location: str,
) -> list[str]:
    deleted = run_az(
        [
            "cognitiveservices",
            "account",
            "list-deleted",
            "--subscription",
            subscription_id,
        ],
        check=False,
    )
    purged: list[str] = []
    if not isinstance(deleted, list):
        return purged

    for item in deleted:
        name = str(item.get("name") or "")
        item_loc = str(item.get("location") or "").lower().replace(" ", "")
        if name.startswith(ALLOWED_FOUNDRY_PREFIX) and item_loc == location.lower():
            print(f"[lab-destroy] Purging soft-deleted Foundry account '{name}' in '{location}'...")
            run_az(
                [
                    "cognitiveservices",
                    "account",
                    "purge",
                    "--subscription",
                    subscription_id,
                    "--resource-group",
                    resource_group,
                    "--location",
                    location,
                    "--name",
                    name,
                ],
                check=False,
            )
            purged.append(name)
    return purged


def purge_soft_deleted_key_vaults(subscription_id: str, location: str) -> list[str]:
    deleted = run_az(
        ["keyvault", "list-deleted", "--subscription", subscription_id],
        check=False,
    )
    purged: list[str] = []
    if not isinstance(deleted, list):
        return purged

    for item in deleted:
        name = str(item.get("name") or "")
        props = item.get("properties", {}) if isinstance(item.get("properties"), dict) else {}
        item_loc = str(props.get("location") or item.get("location") or "").lower().replace(" ", "")
        if name.startswith(ALLOWED_KV_PREFIX) and (not item_loc or item_loc == location.lower()):
            print(f"[lab-destroy] Purging soft-deleted Key Vault '{name}' in '{location}'...")
            run_az(
                [
                    "keyvault",
                    "purge",
                    "--subscription",
                    subscription_id,
                    "--name",
                    name,
                    "--location",
                    location,
                ],
                check=False,
            )
            purged.append(name)
    return purged


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Tear down the disposable apim-assess validation lab and purge soft-deleted tombstones."
        )
    )
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
    )
    parser.add_argument(
        "--resource-group",
        default=os.environ.get("AZURE_LAB_RESOURCE_GROUP", "rg-apv-lab-wus3-001"),
    )
    parser.add_argument(
        "--location",
        default=os.environ.get("AZURE_LOCATION", "westus3"),
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for resource group deletion before purging existing tombstones.",
    )
    parser.add_argument(
        "--purge-only",
        action="store_true",
        help="Skip resource group deletion and only purge matching soft-deleted tombstones.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    validate_destroy_scope(args.resource_group)

    subscription_id = args.subscription_id
    if not subscription_id:
        account = run_az(["account", "show"])
        subscription_id = str(account.get("id") or "")
    if not subscription_id:
        raise RuntimeError("AZURE_SUBSCRIPTION_ID is required.")

    deleted_rg = False
    if not args.purge_only:
        deleted_rg = delete_lab_resource_group(
            subscription_id=subscription_id,
            resource_group=args.resource_group,
            no_wait=args.no_wait,
        )

    purged_apim = purge_soft_deleted_apim(subscription_id, args.location)
    purged_foundry = purge_soft_deleted_foundry(subscription_id, args.resource_group, args.location)
    purged_kv = purge_soft_deleted_key_vaults(subscription_id, args.location)

    summary = {
        "resourceGroup": args.resource_group,
        "deletedResourceGroup": deleted_rg,
        "purgedApim": purged_apim,
        "purgedFoundry": purged_foundry,
        "purgedKeyVaults": purged_kv,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
