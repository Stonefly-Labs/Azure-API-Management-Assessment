from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree as ET

from apim_assess.collector.sanitizer import DYNAMIC, REFERENCE, SECTIONS, sanitize_policy
from apim_assess.models.policy import EffectivePolicy, Inventory, PolicyDocument, PolicyNode
from apim_assess.models.snapshot import Instance

MAX_EFFECTIVE_NODES = 20000


@dataclass
class _ExpansionBudget:
    remaining: int = MAX_EFFECTIVE_NODES


def _node(element: ET.Element, source: str, scope: str = "", section: str = "") -> PolicyNode:
    return PolicyNode(
        tag=element.tag,
        attributes=dict(element.attrib),
        text=element.text,
        source=source,
        scope=scope,
        section=section,
        children=[_node(child, source, scope, section) for child in element],
    )


def _unknown(source: str) -> PolicyNode:
    return PolicyNode(tag="unresolved-policy", source=source)


def _parse(document: PolicyDocument, *, fragment: bool = False) -> ET.Element | None:
    if document.status != "available" or document.xml is None:
        return None
    # Saved artifacts are untrusted too; use the same hardened parser at the offline boundary.
    checked = sanitize_policy(
        document.source, document.xml, fragment=fragment, already_sanitized=True
    )
    if checked.status != "available":
        return None
    root = ET.fromstring(checked.xml or "")
    if not fragment and any(child.tag not in SECTIONS for child in root):
        return None
    return root


def _expand(
    nodes: list[PolicyNode],
    inventory: Inventory,
    workspace: str | None,
    budget: _ExpansionBudget,
) -> list[PolicyNode]:
    result: list[PolicyNode] = []
    prefix = workspace + "/" if workspace else ""
    for node in nodes:
        if budget.remaining <= 0:
            return [*result, _unknown(node.source)]
        budget.remaining -= 1
        if node.tag == "include-fragment":
            identifier = node.attributes.get("fragment-id", "")
            document = inventory.fragments.get(prefix + "policyFragments/" + identifier)
            root = _parse(document, fragment=True) if document else None
            if root is None or document is None or identifier in {DYNAMIC, REFERENCE}:
                result.append(_unknown(node.source))
            else:
                count = sum(1 for _ in root.iter()) - 1
                if count > budget.remaining:
                    result.append(_unknown(node.source))
                    budget.remaining = 0
                else:
                    budget.remaining -= count
                    result.extend(
                        _node(child, document.source, node.scope, node.section) for child in root
                    )
        else:
            result.append(
                node.model_copy(
                    update={"children": _expand(node.children, inventory, workspace, budget)}
                )
            )
    return result


def resolve(instance: Instance, *, include_graphql: bool = False) -> list[EffectivePolicy]:
    inventory = instance.inventory
    if inventory is None or instance.core_status != "available":
        return []
    apis = [item for item in inventory.resources if item.kind == "api"]
    operations = [item for item in inventory.resources if item.kind == "operation"]
    product_metadata = {
        item.path: item.metadata for item in inventory.resources if item.kind == "product"
    }
    result: list[EffectivePolicy] = []
    for api in apis:
        products = sorted(
            product
            for product, members in inventory.product_apis.items()
            if any(
                api.path.casefold().split(";rev=", 1)[0] == member.casefold().split(";rev=", 1)[0]
                for member in members
            )
        )
        targets = [
            item.path
            for item in operations
            if item.path.casefold().startswith(api.path.casefold() + "/operations/")
        ]
        if not targets:
            targets = [api.path]
        open_products = [
            product
            for product in products
            if product in product_metadata
            and product_metadata[product].subscription_required is False
        ]
        contexts: list[str | None] = [None, *products]
        if api.metadata.subscription_required is False:
            contexts = [
                product
                for product in products
                if product not in product_metadata
                or product_metadata[product].subscription_required is not True
            ]
            if not open_products:
                contexts.insert(0, None)
        for product in contexts:
            for target in targets:
                required = api.metadata.subscription_required
                if product:
                    metadata = product_metadata.get(product)
                    if metadata is None or metadata.subscription_required is None:
                        required = None
                    elif metadata.subscription_required is False:
                        required = False
                view = EffectivePolicy(
                    resource_id=instance.resource_id,
                    api_path=api.path,
                    operation_path=target if target != api.path else None,
                    workspace=api.workspace,
                    product_path=product,
                    subscription_required=required,
                    service_url_kind=api.metadata.service_url_kind,
                    http_gateway_only=(
                        api.metadata.api_type is None
                        and api.metadata.protocols is not None
                        and bool(api.metadata.protocols)
                        and all(
                            protocol in {"http", "https"} for protocol in api.metadata.protocols
                        )
                    ),
                    sections={section: [] for section in SECTIONS},
                )
                scopes = ["", *([api.workspace] if api.workspace else [])]
                budget = _ExpansionBudget()
                if product:
                    scopes.append(product)
                scopes.append(api.path)
                if target != api.path:
                    scopes.append(target)
                for scope in scopes:
                    document = inventory.policies.get(scope)
                    if document is not None and document.status == "absent":
                        continue
                    root = _parse(document) if document else None
                    if root is None or document is None:
                        view.sections = {
                            section: [_unknown(document.source if document else scope)]
                            for section in SECTIONS
                        }
                        view.issues.append(f"Policy unavailable: {scope or 'global'}")
                        continue
                    for section in SECTIONS:
                        sections = root.findall(section)
                        if len(sections) != 1:
                            if scope and view.sections[section]:
                                view.sections[section] = [_unknown(document.source)]
                                view.issues.append(f"Section unavailable: {scope}/{section}")
                            elif len(sections) > 1:
                                view.sections[section] = [_unknown(document.source)]
                            continue
                        children = list(sections[0])
                        bases = [child for child in children if child.tag == "base"]
                        if len(bases) > 1 or any(
                            descendant.tag == "base"
                            for child in children
                            if child.tag != "base"
                            for descendant in child.iter()
                        ):
                            view.sections[section] = [_unknown(document.source)]
                            view.issues.append(f"Invalid base placement: {scope}/{section}")
                            continue
                        if scope and not bases:
                            view.missing_base.append(f"{scope}/{section}")
                        inherited = view.sections[section]
                        merged: list[PolicyNode] = []
                        for child in children:
                            if child.tag == "base":
                                merged.extend(inherited)
                            else:
                                merged.extend(
                                    _expand(
                                        [_node(child, document.source, scope, section)],
                                        inventory,
                                        api.workspace
                                        if api.workspace
                                        and (
                                            scope == api.workspace
                                            or scope.startswith(api.workspace + "/")
                                        )
                                        else None,
                                        budget,
                                    )
                                )
                        view.sections[section] = merged
                supported = {"http", "soap"} | ({"graphql"} if include_graphql else set())
                if api.metadata.api_type not in supported and not view.http_gateway_only:
                    view.issues.append(
                        "Protocol metadata unavailable"
                        if api.metadata.api_type is None
                        else "Protocol outside HTTP policy coverage"
                    )
                    view.sections = {section: [_unknown(api.path)] for section in SECTIONS}
                if len(open_products) > 1:
                    view.issues.append("Multiple open product contexts; selection is unresolved")
                    view.sections = {section: [_unknown(api.path)] for section in SECTIONS}
                operation_coverage = inventory.collections.get(api.path + "/operations")
                if operation_coverage is None or operation_coverage.status != "complete":
                    view.issues.append("Operation inventory incomplete")
                    view.sections = {section: [_unknown(api.path)] for section in SECTIONS}
                if any(
                    node.tag == "unresolved-policy"
                    for nodes in view.sections.values()
                    for node in walk(nodes)
                ):
                    view.issues.append("Effective policy contains unresolved content")
                result.append(view)
    return result


def walk(nodes: list[PolicyNode]) -> list[PolicyNode]:
    result = []
    for node in nodes:
        result.append(node)
        result.extend(walk(node.children))
    return result


def inventory_complete(inventory: Inventory | None) -> bool:
    if inventory is None:
        return False
    required = {"apis", "products", "workspaces"}
    for item in inventory.resources:
        if item.kind == "api":
            required.add(item.path + "/operations")
        elif item.kind == "product":
            required.add(item.path + "/apis")
        elif item.kind == "workspace":
            required.update({item.path + "/apis", item.path + "/products"})
    return all(
        key in inventory.collections and inventory.collections[key].status == "complete"
        for key in required
    )
