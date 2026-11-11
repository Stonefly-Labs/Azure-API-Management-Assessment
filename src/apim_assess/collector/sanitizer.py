from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlsplit
from xml.etree import ElementTree as ET

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from apim_assess.models.policy import PolicyDocument

REDACTED = "<REDACTED_SECRET>"
DYNAMIC = "__EXPRESSION__"
REFERENCE = "__NAMED_VALUE__"
LITERAL_URL = "__LITERAL_URL__"
LITERAL_ORIGIN = "__LITERAL_ORIGIN__"
COGNITIVE_AUDIENCE = "__COGNITIVE_AUDIENCE__"
MAX_XML_BYTES = 512 * 1024
SECTIONS = ("inbound", "backend", "outbound", "on-error")
TAGS = {
    "policies",
    "fragment",
    *SECTIONS,
    "base",
    "include-fragment",
    "choose",
    "when",
    "otherwise",
    "validate-jwt",
    "validate-azure-ad-token",
    "validate-client-certificate",
    "openid-config",
    "issuer-signing-keys",
    "decryption-keys",
    "key",
    "audiences",
    "audience",
    "issuers",
    "issuer",
    "required-claims",
    "claim",
    "value",
    "identities",
    "identity",
    "client-application-ids",
    "application-id",
    "backend-application-ids",
    "rate-limit",
    "rate-limit-by-key",
    "limit-concurrency",
    "cors",
    "allowed-origins",
    "origin",
    "allowed-methods",
    "method",
    "allowed-headers",
    "header",
    "expose-headers",
    "set-backend-service",
    "forward-request",
    "return-response",
    "set-header",
    "set-body",
    "set-variable",
    "set-status",
    "set-url",
    "send-request",
    "send-one-way-request",
    "retry",
    "authentication-managed-identity",
    "authentication-basic",
    "authentication-certificate",
    "set-query-parameter",
    "rewrite-uri",
    "cache-lookup",
    "cache-store",
    "ip-filter",
    "address",
    "address-range",
    "check-header",
    "quota",
    "quota-by-key",
    "log-to-eventhub",
    "trace",
    "message",
    "metadata",
    "set-method",
    "find-and-replace",
    "validate-content",
    "validate-parameters",
    "validate-headers",
    "json-to-xml",
    "xml-to-json",
    "llm-token-limit",
    "azure-openai-token-limit",
    "llm-emit-token-metric",
    "azure-openai-emit-token-metric",
    "dimension",
    "validate-graphql-request",
    "authorize",
    "rule",
}
BOOL_ATTRIBUTES = {
    "allow-credentials",
    "terminate-unmatched-request",
    "ignore-error",
    "validate-trust",
    "validate-revocation",
    "validate-not-before",
    "validate-not-after",
    "require-signed-tokens",
    "require-expiration-time",
    "validate-connectivity",
    "estimate-prompt-tokens",
    "ignore-case",
}
NUMBER_ATTRIBUTES = {
    "calls",
    "renewal-period",
    "max-count",
    "increment-count",
    "code",
    "count",
    "interval",
    "timeout",
    "timeout-ms",
    "max-size",
    "duration",
    "tokens-per-minute",
    "token-quota",
    "max-depth",
    "failed-check-httpcode",
}
ENUM_ATTRIBUTES = {
    "exists-action": {"delete", "override", "append", "skip"},
    "size-exceeded-action": {"prevent", "detect", "ignore"},
    "caching-type": {"internal", "external", "prefer-external"},
    "token-quota-period": {"Hourly", "Daily", "Weekly", "Monthly", "Yearly"},
}
IMPLEMENTATION_HEADERS = {"x-powered-by", "x-aspnet-version", "server"}
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "ocp-apim-subscription-key",
    "x-api-key",
    "api-key",
    "x-functions-key",
    "x-goog-api-key",
    "anthropic-api-key",
}
SENSITIVE_QUERY_PARAMS = {
    "key",
    "api-key",
    "api_key",
    "x-api-key",
    "code",
    "sig",
    "token",
    "access_token",
    "client_secret",
    "password",
    "secret",
}
SENSITIVE_VARIABLE_NAME = re.compile(
    r"(?:secret|password|passwd|pwd|api[-_]?key|access[-_]?key|connection[-_]?string)",
    re.IGNORECASE,
)
NAMED_VALUE_TOKEN = re.compile(r"\{\{\s*([^{}\s]+?)\s*\}\}")
LITERAL_URL_PATTERN = re.compile(r"(?i)https?://(?![\s\"')}]*\{\{)[a-z0-9.-]+")
CONTEXT_LOOKUP_PATTERN = re.compile(
    r'context\.[A-Za-z0-9_.<>]+\s*(?:\[\s*"[^"]*"\s*\]|\(\s*"[^"]*"(?:\s*,\s*"[^"]*"\s*)?\))'
)
QUOTED_STRING_PATTERN = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
SECRET_PATTERN = re.compile(
    r"(?i)((?<![A-Za-z0-9_-])bearer\s+(?!\{\{)[^\s\"'<>]+|"
    r"(?<![A-Za-z0-9_-])basic\s+(?!\{\{)(?![A-Za-z0-9_-]+=[\"\'])[A-Za-z0-9+/=]{8,}|"
    r"(?:password|pwd|api[-_]?key|accountkey|sharedaccesskey|sharedaccesssignature|"
    r"instrumentationkey|client[-_]?secret|access[-_]?token)\s*[=:]\s*(?!\{\{)[^\s\"'<>]+|"
    r"[?&](?:sig|api[-_]?key|x-api-key|code|client_secret|access_token)=(?!\{\{)[^&\s\"'<>]+|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|"
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b)"
)


def has_literal_url(value: str) -> bool:
    return bool(LITERAL_URL_PATTERN.search(value))


def _is_hardcoded_secret_value(raw: str) -> bool:
    stripped = raw.strip()
    if not stripped or stripped in {
        REDACTED,
        DYNAMIC,
        REFERENCE,
        LITERAL_URL,
        LITERAL_ORIGIN,
        COGNITIVE_AUDIENCE,
    }:
        return False
    without_nv = NAMED_VALUE_TOKEN.sub("", stripped).strip()
    if not without_nv or without_nv.casefold() in {
        "bearer",
        "basic",
        "digest",
        "token",
        "apikey",
        "api-key",
    }:
        return False
    if stripped.startswith(("@(", "@{")):
        if SECRET_PATTERN.search(without_nv):
            return True
        cleaned = CONTEXT_LOOKUP_PATTERN.sub("", without_nv)
        literals = [m.group(1).strip() for m in QUOTED_STRING_PATTERN.finditer(cleaned)]
        return any(
            lit
            and lit.casefold()
            not in {"bearer", "basic", "digest", "token", "apikey", "api-key", ":"}
            for lit in literals
        )
    return True


def _scan_policy(
    root: ET.Element, xml: str, *, fragment: bool
) -> tuple[list[str], list[str], list[str]]:
    secret_locations: list[str] = []
    hardcoded_urls: list[str] = []
    named_values: set[str] = set()

    def visit(node: ET.Element, section: str, parent_tag: str | None) -> None:
        current_section = (
            "fragment" if fragment else node.tag if node.tag in SECTIONS else section or "policies"
        )
        for raw_attr in node.attrib.values():
            for match in NAMED_VALUE_TOKEN.finditer(raw_attr):
                named_values.add(reference_id(match.group(1).casefold()))
        if node.text:
            for match in NAMED_VALUE_TOKEN.finditer(node.text):
                named_values.add(reference_id(match.group(1).casefold()))

        if node.tag == "set-backend-service" and has_literal_url(node.attrib.get("base-url", "")):
            hardcoded_urls.append(f"{current_section}/set-backend-service@base-url")
        elif node.tag == "set-url" and has_literal_url((node.text or "").strip()):
            prefix = (
                f"{current_section}/{parent_tag}"
                if parent_tag in {"send-request", "send-one-way-request"}
                else current_section
            )
            hardcoded_urls.append(f"{prefix}/set-url")
        elif node.tag == "rewrite-uri" and has_literal_url(node.attrib.get("template", "")):
            hardcoded_urls.append(f"{current_section}/rewrite-uri@template")

        handled_value_children = False
        if node.tag == "authentication-basic" and _is_hardcoded_secret_value(
            node.attrib.get("password", "")
        ):
            secret_locations.append(f"{current_section}/authentication-basic@password")
        elif (
            node.tag == "set-header"
            and node.attrib.get("exists-action", "").lower() != "delete"
            and node.attrib.get("name", "").strip().lower() in SENSITIVE_HEADERS
        ):
            hdr = node.attrib.get("name", "").strip().lower()
            if any(
                child.tag == "value" and _is_hardcoded_secret_value(child.text or "")
                for child in node
            ):
                secret_locations.append(f"{current_section}/set-header[name={hdr}]")
                handled_value_children = True
        elif (
            node.tag == "set-query-parameter"
            and node.attrib.get("exists-action", "").lower() != "delete"
            and node.attrib.get("name", "").strip().lower() in SENSITIVE_QUERY_PARAMS
        ):
            param = node.attrib.get("name", "").strip().lower()
            if any(
                child.tag == "value" and _is_hardcoded_secret_value(child.text or "")
                for child in node
            ):
                secret_locations.append(f"{current_section}/set-query-parameter[name={param}]")
                handled_value_children = True
        handled_value_attr = False
        if (
            node.tag == "set-variable"
            and SENSITIVE_VARIABLE_NAME.search(node.attrib.get("name", ""))
            and _is_hardcoded_secret_value(node.attrib.get("value", ""))
        ):
            var_name = node.attrib.get("name", "").strip().lower()
            secret_locations.append(f"{current_section}/set-variable[name={var_name}]")
            handled_value_attr = True
        elif (
            node.tag == "key"
            and parent_tag in {"issuer-signing-keys", "decryption-keys"}
            and not node.attrib.get("certificate-id")
            and _is_hardcoded_secret_value(node.text or "")
        ):
            secret_locations.append(f"{current_section}/validate-jwt/{parent_tag}/key")

        for key, raw_attr in node.attrib.items():
            if (node.tag == "authentication-basic" and key == "password") or (
                handled_value_attr and key == "value"
            ):
                continue
            cleaned_attr = NAMED_VALUE_TOKEN.sub("", raw_attr)
            if key in {"base-url", "url", "template"} and url_api_key(cleaned_attr) is True:
                secret_locations.append(f"{current_section}/{node.tag}@{key}")
            elif cleaned_attr.strip() and SECRET_PATTERN.search(raw_attr):
                secret_locations.append(f"{current_section}/{node.tag}@{key}")

        raw_text = (node.text or "").strip()
        if raw_text and not (
            node.tag == "key" and parent_tag in {"issuer-signing-keys", "decryption-keys"}
        ):
            cleaned_text = NAMED_VALUE_TOKEN.sub("", raw_text)
            if node.tag == "set-url" and url_api_key(cleaned_text) is True:
                secret_locations.append(f"{current_section}/set-url")
            elif cleaned_text.strip() and SECRET_PATTERN.search(raw_text):
                if not (
                    node.tag == "value" and parent_tag in {"set-header", "set-query-parameter"}
                ):
                    loc = (
                        f"{current_section}/{parent_tag}/value"
                        if node.tag == "value" and parent_tag
                        else f"{current_section}/{node.tag}"
                    )
                    secret_locations.append(loc)

        for child in node:
            if handled_value_children and child.tag == "value":
                for match in NAMED_VALUE_TOKEN.finditer(child.text or ""):
                    named_values.add(reference_id(match.group(1).casefold()))
                continue
            visit(child, current_section, node.tag)

    visit(root, "fragment" if fragment else "", None)
    if not secret_locations and SECRET_PATTERN.search(xml):
        secret_locations.append("xml/comment-or-text")
    return (
        list(dict.fromkeys(secret_locations)),
        list(dict.fromkeys(hardcoded_urls)),
        sorted(named_values),
    )


def reference_id(value: str) -> str:
    return "ref_" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def value_kind(value: object) -> str:
    if value is None:
        return "unknown"
    if not isinstance(value, str):
        raise ValueError("Invalid URL metadata")
    if not value:
        return "none"
    if "@(" in value or "@{" in value or "{{" in value:
        return "dynamic"
    return "literal"


def ai_backend_kind(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    if value_kind(value) != "literal":
        return "unknown"
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").casefold()
    except ValueError:
        return "unknown"
    if parsed.scheme not in {"https", "http"} or not hostname:
        return "unknown"
    if hostname.endswith(".openai.azure.com") or (
        hostname.endswith((".cognitiveservices.azure.com", ".services.ai.azure.com"))
        and "/openai" in parsed.path.casefold()
    ):
        return "azure_openai"
    if hostname in {"api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"} or (
        hostname.endswith(".services.ai.azure.com")
        or hostname == "aiplatform.googleapis.com"
        or hostname.endswith(".aiplatform.googleapis.com")
    ):
        return "llm"
    return "other"


def url_api_key(value: object) -> bool | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urlsplit(value)
        keys = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=1000)
    except ValueError:
        return None
    if (
        parsed.username
        or parsed.password
        or any(key.casefold() in {"api-key", "x-api-key", "api_key", "key"} for key, _ in keys)
    ):
        return True
    return False if value_kind(value) == "literal" and parsed.hostname else None


def sanitize_policy(
    source: str, xml: str, *, fragment: bool = False, already_sanitized: bool = False
) -> PolicyDocument:
    def unavailable(code: str) -> PolicyDocument:
        return PolicyDocument(source=source, status="unavailable", error_code=code)

    if len(xml.encode("utf-8")) > MAX_XML_BYTES:
        return unavailable("XML_TOO_LARGE")
    try:
        root = fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ET.ParseError, DefusedXmlException, ValueError):
        return unavailable("INVALID_XML")
    if root.tag != ("fragment" if fragment else "policies"):
        return unavailable("INVALID_XML_ROOT")
    nodes = list(root.iter())
    if len(nodes) > 10000:
        return unavailable("XML_TOO_COMPLEX")
    if fragment and any(node.tag in {*SECTIONS, "base", "include-fragment"} for node in nodes):
        return unavailable("INVALID_FRAGMENT_STRUCTURE")
    secret_locations, hardcoded_urls, named_value_refs = (
        ([], [], []) if already_sanitized else _scan_policy(root, xml, fragment=fragment)
    )
    secret_pattern = bool(secret_locations)
    header_values: dict[int, str] = {}
    for header in root.iter("check-header"):
        if header.attrib.get("name", "").casefold() == "x-azure-fdid":
            for child in header:
                raw = (child.text or "").strip()
                if child.tag != "value":
                    continue
                if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", raw):
                    header_values[id(child)] = reference_id(raw.casefold())
                elif already_sanitized and re.fullmatch(r"ref_[a-f0-9]{64}", raw):
                    header_values[id(child)] = raw

    def scrub(node: ET.Element, depth: int) -> bool:
        if depth > 64:
            return False
        if node.tag not in TAGS:
            node.tag = "unrecognized-policy"
        attributes: dict[str, str] = {}
        for key, raw in node.attrib.items():
            if key not in {
                *BOOL_ATTRIBUTES,
                *NUMBER_ATTRIBUTES,
                *ENUM_ATTRIBUTES,
                "name",
                "fragment-id",
                "backend-id",
                "base-url",
                "url",
                "template",
                "header-name",
                "query-parameter-name",
                "token-value",
                "tenant-id",
                "counter-key",
                "key",
                "increment-condition",
                "condition",
                "certificate-id",
                "resource",
                "client-id",
                "output-token-variable-name",
                "namespace",
                "ai-backend-kind",
                "ai-api-key",
            }:
                continue
            if key == "ai-backend-kind":
                if already_sanitized and raw in {"azure_openai", "llm", "other", "unknown"}:
                    attributes[key] = raw
                continue
            if key == "ai-api-key":
                if already_sanitized and raw in {"true", "false", "unknown"}:
                    attributes[key] = raw
                continue
            if already_sanitized and (
                raw in {DYNAMIC, REFERENCE, LITERAL_URL, REDACTED, COGNITIVE_AUDIENCE}
                or re.fullmatch(r"ref_[a-f0-9]{64}", raw)
            ):
                safe = raw
            elif key in BOOL_ATTRIBUTES and raw.lower() in {"true", "false"}:
                safe = raw.lower()
            elif key in NUMBER_ATTRIBUTES and re.fullmatch(r"[0-9]{1,12}", raw):
                safe = raw
            elif key in ENUM_ATTRIBUTES and raw in ENUM_ATTRIBUTES[key]:
                safe = raw
            elif (
                key == "name"
                and node.tag in {"set-header", "check-header"}
                and raw.lower()
                in IMPLEMENTATION_HEADERS
                | {"authorization", "api-key", "x-api-key", "x-azure-fdid"}
            ):
                safe = raw.lower()
            elif key == "resource" and raw.rstrip("/") == "https://cognitiveservices.azure.com":
                safe = COGNITIVE_AUDIENCE
            elif key in {"base-url", "url", "template"} and has_literal_url(raw):
                safe = LITERAL_URL
            elif raw.startswith(("@(", "@{")):
                safe = DYNAMIC
            elif "{{" in raw:
                safe = REFERENCE
            elif key in {"fragment-id", "backend-id", "namespace"}:
                safe = reference_id(raw)
            else:
                safe = REDACTED
            attributes[key] = safe
            if key == "base-url" and not already_sanitized:
                attributes["ai-backend-kind"] = ai_backend_kind(raw)
                key_presence = url_api_key(raw)
                attributes["ai-api-key"] = (
                    "unknown" if key_presence is None else str(key_presence).lower()
                )
        node.attrib.clear()
        node.attrib.update(attributes)
        if node.text and node.text.strip():
            raw_text = node.text.strip()
            if id(node) in header_values:
                node.text = header_values[id(node)]
            elif node.tag == "set-url":
                if already_sanitized and raw_text in {DYNAMIC, REFERENCE, LITERAL_URL, REDACTED}:
                    node.text = raw_text
                elif has_literal_url(raw_text):
                    node.text = LITERAL_URL
                elif raw_text.startswith(("@(", "@{")):
                    node.text = DYNAMIC
                elif "{{" in raw_text:
                    node.text = REFERENCE
                else:
                    node.text = REDACTED
            elif node.tag == "origin":
                if raw_text == "*":
                    node.text = "*"
                elif raw_text.startswith(("@(", "@{")):
                    node.text = DYNAMIC
                elif "{{" in raw_text:
                    node.text = REFERENCE
                elif already_sanitized and raw_text in {DYNAMIC, REFERENCE, LITERAL_ORIGIN}:
                    node.text = raw_text
                else:
                    parsed = urlsplit(raw_text)
                    node.text = (
                        LITERAL_ORIGIN
                        if parsed.scheme in {"http", "https"}
                        and parsed.netloc
                        and not parsed.username
                        and not parsed.password
                        and not parsed.query
                        and not parsed.fragment
                        and parsed.path in {"", "/"}
                        else REDACTED
                    )
            else:
                node.text = REDACTED
        else:
            node.text = None
        node.tail = None
        return all(scrub(child, depth + 1) for child in node)

    try:
        if not scrub(root, 0):
            return unavailable("XML_TOO_COMPLEX")
    except ValueError:
        return unavailable("INVALID_POLICY_VALUE")
    safe_xml = ET.tostring(root, encoding="unicode")
    if len(safe_xml.encode("utf-8")) > MAX_XML_BYTES:
        return unavailable("XML_TOO_LARGE")
    return PolicyDocument(
        source=source,
        status="available",
        xml=safe_xml,
        has_inline_secret_pattern=secret_pattern,
        inline_secret_locations=secret_locations,
        hardcoded_urls=hardcoded_urls,
        named_value_refs=named_value_refs,
    )
