from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from apim_assess.models.policy import PolicyDocument

REDACTED = "<REDACTED_SECRET>"
DYNAMIC = "__EXPRESSION__"
REFERENCE = "__NAMED_VALUE__"
LITERAL_URL = "__LITERAL_URL__"
LITERAL_ORIGIN = "__LITERAL_ORIGIN__"
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
}
ENUM_ATTRIBUTES = {
    "exists-action": {"delete", "override", "append", "skip"},
    "size-exceeded-action": {"prevent", "detect", "ignore"},
    "caching-type": {"internal", "external", "prefer-external"},
}
IMPLEMENTATION_HEADERS = {"x-powered-by", "x-aspnet-version", "server"}
SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+\S+|(?:password|api[-_]?key|accountkey|sharedaccesssignature|"
    r"client[-_]?secret|access[-_]?token)\s*[=:]|[?&]sig=|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
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
    secret_pattern = bool(SECRET_PATTERN.search(xml))

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
                "header-name",
                "query-parameter-name",
                "token-value",
                "tenant-id",
                "counter-key",
                "key",
                "increment-condition",
                "condition",
                "certificate-id",
            }:
                continue
            if already_sanitized and (
                raw in {DYNAMIC, REFERENCE, LITERAL_URL, REDACTED}
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
                key == "name" and node.tag == "set-header" and raw.lower() in IMPLEMENTATION_HEADERS
            ):
                safe = raw.lower()
            elif raw.startswith(("@(", "@{")):
                safe = DYNAMIC
            elif "{{" in raw:
                safe = REFERENCE
            elif key in {"fragment-id", "backend-id"}:
                safe = reference_id(raw)
            elif key in {"base-url", "url"} and raw.startswith(("http://", "https://")):
                safe = LITERAL_URL
            else:
                safe = REDACTED
            attributes[key] = safe
        node.attrib.clear()
        node.attrib.update(attributes)
        if node.text and node.text.strip():
            raw_text = node.text.strip()
            if node.tag == "origin":
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
    )
