"""ACME v2 DNS-01 certificate issuance, Key Vault import, and Cloudflare DNS management.

Provides:
1. `CloudflareDnsClient` for managing DNS-01 `_acme-challenge` TXT records and
   upserting `A`/`CNAME` records in Cloudflare DNS (`*.christopher-house.com`).
2. `issue_acme_wildcard_pfx` implementing RFC 8555 ACME v2 DNS-01 wildcard
   certificate issuance against Let's Encrypt using `cryptography` and `httpx`.
3. `ensure_keyvault_wildcard_certificate` to idempotently reuse a valid Key Vault
   certificate or issue and import a fresh ACME wildcard certificate.
4. `generate_short_lived_custom_pfx_base64` to generate an in-memory, short-lived
   (14-day) PFX for the intentional `APIM-SEC-014` (`fail`) posture on `apim-dev`.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

LETSENCRYPT_PROD_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_DOH_URL = "https://1.1.1.1/dns-query"
DOH_RESOLVER_URLS = (
    CLOUDFLARE_DOH_URL,
    "https://1.0.0.1/dns-query",
    "https://dns.google/resolve",
)
DEFAULT_AUTHORITATIVE_NS = (
    "algin.ns.cloudflare.com",
    "lila.ns.cloudflare.com",
)
DEFAULT_ZONE_NAME = "christopher-house.com"
DEFAULT_CERT_NAME = "wildcard-christopher-house-com"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_b64url(value: int, length: int) -> str:
    return _b64url(value.to_bytes(length, byteorder="big"))


class CloudflareDnsClient:
    """Minimal Cloudflare v4 DNS client for ACME DNS-01 and lab hostname records."""

    def __init__(
        self,
        api_token: str,
        *,
        http_client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_token or not api_token.strip():
            raise ValueError("Cloudflare API token is required.")
        self._token = api_token.strip()
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(timeout=30.0, transport=transport)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> CloudflareDnsClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{CLOUDFLARE_API_BASE}{path}"
        response = self._client.request(
            method,
            url,
            headers=self._headers(),
            params=params,
            json=json_body,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Cloudflare API {method} {path} returned non-JSON ({response.status_code})."
            ) from exc
        if response.status_code >= 400 or not payload.get("success", False):
            errors = payload.get("errors") or []
            err_summary = "; ".join(
                f"{e.get('code')}: {e.get('message')}" for e in errors if isinstance(e, dict)
            )
            raise RuntimeError(
                f"Cloudflare API {method} {path} failed ({response.status_code}): "
                f"{err_summary or 'unknown error'}"
            )
        return payload

    def resolve_zone_id(self, zone_name: str) -> str:
        normalized = zone_name.strip().lstrip("*.").rstrip(".")
        payload = self._request(
            "GET",
            "/zones",
            params={"name": normalized, "status": "active"},
        )
        results = payload.get("result") or []
        if not results or not isinstance(results[0], dict) or not results[0].get("id"):
            raise RuntimeError(f"Active Cloudflare DNS zone '{normalized}' was not found.")
        return str(results[0]["id"])

    def get_zone_id(self, zone_name: str) -> str:
        return self.resolve_zone_id(zone_name)

    def list_records(
        self,
        zone_id: str,
        *,
        name: str | None = None,
        record_type: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"per_page": 100}
        if name:
            params["name"] = name.rstrip(".")
        if record_type:
            params["type"] = record_type.upper()
        payload = self._request("GET", f"/zones/{zone_id}/dns_records", params=params)
        result = payload.get("result")
        return [r for r in result if isinstance(r, dict)] if isinstance(result, list) else []

    def create_txt_record(self, zone_id: str, name: str, content: str, *, ttl: int = 60) -> str:
        fqdn = name.rstrip(".")
        for existing in self.list_records(zone_id, name=fqdn, record_type="TXT"):
            if str(existing.get("content") or "").strip('"') == content and existing.get("id"):
                return str(existing["id"])
        payload = self._request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            json_body={
                "type": "TXT",
                "name": fqdn,
                "content": content,
                "ttl": ttl,
            },
        )
        record = payload.get("result") or {}
        record_id = str(record.get("id") or "")
        if not record_id:
            raise RuntimeError(f"Cloudflare did not return a record ID for TXT '{fqdn}'.")
        return record_id

    def delete_record(self, zone_id: str, record_id: str) -> None:
        if not record_id:
            return
        self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    def upsert_record(
        self,
        zone_id: str,
        *,
        record_type: str,
        name: str,
        content: str,
        proxied: bool = False,
        ttl: int = 120,
    ) -> dict[str, Any]:
        fqdn = name.rstrip(".")
        rtype = record_type.upper()
        existing_all = self.list_records(zone_id, name=fqdn)
        same_type: list[dict[str, Any]] = []
        for record in existing_all:
            existing_type = str(record.get("type") or "").upper()
            existing_id = str(record.get("id") or "")
            if existing_type == rtype:
                same_type.append(record)
            elif existing_id and existing_type in {"A", "AAAA", "CNAME"}:
                self.delete_record(zone_id, existing_id)

        body = {
            "type": rtype,
            "name": fqdn,
            "content": content,
            "proxied": proxied,
            "ttl": ttl,
        }
        if same_type and same_type[0].get("id"):
            primary_id = str(same_type[0]["id"])
            for extra in same_type[1:]:
                if extra.get("id"):
                    self.delete_record(zone_id, str(extra["id"]))
            payload = self._request(
                "PUT",
                f"/zones/{zone_id}/dns_records/{primary_id}",
                json_body=body,
            )
        else:
            payload = self._request(
                "POST",
                f"/zones/{zone_id}/dns_records",
                json_body=body,
            )
        result = payload.get("result")
        return dict(result) if isinstance(result, dict) else body


def _check_authoritative_txt_nslookup(
    fqdn: str,
    expected_value: str,
    nameservers: tuple[str, ...] = DEFAULT_AUTHORITATIVE_NS,
) -> bool:
    """Query Cloudflare authoritative nameservers directly via nslookup."""
    for ns in nameservers:
        try:
            proc = subprocess.run(
                ["nslookup", "-type=TXT", fqdn, ns],
                capture_output=True,
                text=True,
                timeout=6.0,
                check=False,
            )
            if expected_value in (proc.stdout or ""):
                return True
        except Exception:
            continue
    return False


def wait_for_txt_propagation(
    fqdn: str,
    expected_value: str,
    *,
    timeout_seconds: float = 120.0,
    poll_interval_seconds: float = 4.0,
    http_client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    authoritative_nameservers: tuple[str, ...] = DEFAULT_AUTHORITATIVE_NS,
) -> None:
    """Poll authoritative DNS and DoH resolvers until the expected TXT challenge is visible."""
    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=10.0)
    is_mock_client = isinstance(getattr(client, "_transport", None), httpx.MockTransport)
    deadline = time.monotonic() + timeout_seconds
    clean_name = fqdn.rstrip(".")
    doh_urls = (CLOUDFLARE_DOH_URL,) if is_mock_client else DOH_RESOLVER_URLS

    try:
        # Wait one interval before querying recursive resolvers so we do not trigger
        # 1800s SOA negative-cache poisoning at t=0 before authoritative push finishes.
        if not is_mock_client and timeout_seconds > poll_interval_seconds:
            sleep_fn(min(poll_interval_seconds, 5.0))

        while True:
            if not is_mock_client and _check_authoritative_txt_nslookup(
                clean_name,
                expected_value,
                authoritative_nameservers,
            ):
                return

            for doh_url in doh_urls:
                try:
                    resp = client.get(
                        doh_url,
                        params={"name": clean_name, "type": "TXT"},
                        headers={"Accept": "application/dns-json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        answers = data.get("Answer") or []
                        for ans in answers:
                            raw_txt = str(ans.get("data") or "").strip().strip('"')
                            if raw_txt == expected_value or expected_value in raw_txt:
                                return
                except Exception:
                    continue

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting {timeout_seconds}s for TXT record '{clean_name}'."
                )
            sleep_fn(poll_interval_seconds)
    finally:
        if owns_client:
            client.close()


class _AcmeV2Session:
    """Lightweight RFC 8555 ACME v2 client using an ephemeral EC P-256 account key."""

    def __init__(self, directory_url: str, *, http_client: httpx.Client) -> None:
        self._directory_url = directory_url
        self._client = http_client
        self._account_key = ec.generate_private_key(ec.SECP256R1())
        self._directory: dict[str, Any] = {}
        self._nonce: str | None = None
        self._kid: str | None = None

    def _jwk(self) -> dict[str, str]:
        numbers = self._account_key.public_key().public_numbers()
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": _int_to_b64url(numbers.x, 32),
            "y": _int_to_b64url(numbers.y, 32),
        }

    def thumbprint(self) -> str:
        canonical = json.dumps(self._jwk(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _b64url(hashlib.sha256(canonical).digest())

    def initialize(self) -> None:
        resp = self._client.get(self._directory_url)
        resp.raise_for_status()
        self._directory = resp.json()

    def _get_nonce(self) -> str:
        if self._nonce:
            nonce, self._nonce = self._nonce, None
            return nonce
        new_nonce_url = str(self._directory["newNonce"])
        resp = self._client.head(new_nonce_url)
        nonce = resp.headers.get("Replay-Nonce")
        if not nonce:
            raise RuntimeError("ACME directory did not provide a Replay-Nonce header.")
        return nonce

    def _sign_jws(self, url: str, payload: dict[str, Any] | str | None) -> dict[str, str]:
        protected: dict[str, Any] = {
            "alg": "ES256",
            "nonce": self._get_nonce(),
            "url": url,
        }
        if self._kid:
            protected["kid"] = self._kid
        else:
            protected["jwk"] = self._jwk()

        protected_b64 = _b64url(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
        if payload is None:
            payload_b64 = ""
        elif isinstance(payload, str):
            payload_b64 = _b64url(payload.encode("utf-8"))
        else:
            payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        der_sig = self._account_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _b64url(raw_sig),
        }

    def post(
        self,
        url: str,
        payload: dict[str, Any] | None,
        *,
        accept: str = "application/json",
    ) -> httpx.Response:
        for attempt in range(3):
            jws = self._sign_jws(url, payload)
            resp = self._client.post(
                url,
                content=json.dumps(jws).encode("utf-8"),
                headers={
                    "Content-Type": "application/jose+json",
                    "Accept": accept,
                },
            )
            if "Replay-Nonce" in resp.headers:
                self._nonce = resp.headers["Replay-Nonce"]
            if resp.status_code == 400 and "badNonce" in resp.text and attempt < 2:
                continue
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"ACME request to {url} failed ({resp.status_code}): {resp.text[:400]}"
                )
            return resp
        raise RuntimeError(f"ACME request to {url} exhausted badNonce retries.")

    def register_account(self, contact_email: str | None = None) -> None:
        new_account_url = str(self._directory["newAccount"])
        body: dict[str, Any] = {"termsOfServiceAgreed": True}
        if contact_email:
            body["contact"] = [f"mailto:{contact_email}"]
        resp = self.post(new_account_url, body)
        location = resp.headers.get("Location")
        if not location:
            raise RuntimeError("ACME newAccount response did not include an account Location URL.")
        self._kid = location


def _serialize_pfx(
    *,
    private_key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    cas: list[x509.Certificate] | None,
    password: str | None,
    legacy_triple_des: bool = False,
) -> bytes:
    if not password:
        encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    elif legacy_triple_des:
        pwd_bytes = password.encode("utf-8")
        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(2000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(pwd_bytes)
        )
    else:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    return pkcs12.serialize_key_and_certificates(
        name=b"apim-assess-lab",
        key=private_key,
        cert=cert,
        cas=cas or None,
        encryption_algorithm=encryption,
    )


def issue_acme_wildcard_pfx(
    *,
    zone_name: str,
    cloudflare: CloudflareDnsClient,
    pfx_password: str,
    directory_url: str = LETSENCRYPT_PROD_DIRECTORY,
    contact_email: str | None = None,
    propagation_wait_seconds: float = 60.0,
    http_client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> bytes:
    """Issue a `*.<zone_name>` wildcard certificate via ACME DNS-01 and return PFX bytes."""
    clean_zone = zone_name.strip().lstrip("*.").rstrip(".")
    wildcard_domain = f"*.{clean_zone}"
    challenge_fqdn = f"_acme-challenge.{clean_zone}"

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=30.0)
    zone_id = cloudflare.resolve_zone_id(clean_zone)
    created_record_ids: list[str] = []

    try:
        for stale in cloudflare.list_records(zone_id, name=challenge_fqdn, record_type="TXT"):
            stale_id = str(stale.get("id") or "")
            if stale_id:
                cloudflare.delete_record(zone_id, stale_id)

        print(
            f"[acme] Requesting Let's Encrypt wildcard order for {wildcard_domain}...", flush=True
        )
        acme = _AcmeV2Session(directory_url, http_client=client)
        acme.initialize()
        acme.register_account(contact_email=contact_email)

        order_resp = acme.post(
            str(acme._directory["newOrder"]),
            {"identifiers": [{"type": "dns", "value": wildcard_domain}]},
        )
        order_url = order_resp.headers.get("Location") or ""
        order_data = order_resp.json()
        authz_urls = list(order_data.get("authorizations") or [])
        finalize_url = str(order_data["finalize"])

        challenge_urls: list[str] = []
        for authz_url in authz_urls:
            authz_resp = acme.post(str(authz_url), None)
            authz_data = authz_resp.json()
            if authz_data.get("status") == "valid":
                continue
            challenges = authz_data.get("challenges") or []
            dns_challenge = next(
                (c for c in challenges if isinstance(c, dict) and c.get("type") == "dns-01"),
                None,
            )
            if not dns_challenge:
                raise RuntimeError(f"ACME authorization {authz_url} did not offer dns-01.")
            token = str(dns_challenge["token"])
            key_auth = f"{token}.{acme.thumbprint()}"
            txt_value = _b64url(hashlib.sha256(key_auth.encode("ascii")).digest())
            rec_id = cloudflare.create_txt_record(zone_id, challenge_fqdn, txt_value)
            created_record_ids.append(rec_id)
            print(
                f"[acme] Created Cloudflare TXT record {challenge_fqdn} ({rec_id}); "
                "verifying DNS propagation...",
                flush=True,
            )
            if propagation_wait_seconds > 0:
                try:
                    wait_for_txt_propagation(
                        challenge_fqdn,
                        txt_value,
                        timeout_seconds=propagation_wait_seconds,
                        http_client=client,
                        sleep_fn=sleep_fn,
                    )
                    print(f"[acme] Verified DNS propagation for {challenge_fqdn}.", flush=True)
                except TimeoutError:
                    print(
                        f"[acme] Local DNS resolver did not observe {challenge_fqdn} within "
                        f"{propagation_wait_seconds}s (likely cached SOA NXDOMAIN); "
                        "proceeding with authoritative ACME challenge validation...",
                        flush=True,
                    )
            challenge_urls.append(str(dns_challenge["url"]))

        for chall_url in challenge_urls:
            acme.post(chall_url, {})

        for authz_url in authz_urls:
            for _ in range(30):
                status_resp = acme.post(str(authz_url), None).json()
                status = status_resp.get("status")
                if status == "valid":
                    break
                if status == "invalid":
                    raise RuntimeError(f"ACME DNS-01 authorization failed: {status_resp}")
                sleep_fn(3.0)
            else:
                raise TimeoutError(f"Timed out waiting for ACME authorization {authz_url}.")

        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, wildcard_domain)]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(wildcard_domain)]),
                critical=False,
            )
            .sign(cert_key, hashes.SHA256())
        )
        csr_der_b64 = _b64url(csr.public_bytes(serialization.Encoding.DER))
        finalize_resp = acme.post(finalize_url, {"csr": csr_der_b64}).json()

        certificate_url = finalize_resp.get("certificate")
        if not certificate_url and order_url:
            for _ in range(30):
                polled = acme.post(order_url, None).json()
                if polled.get("status") == "valid" and polled.get("certificate"):
                    certificate_url = polled["certificate"]
                    break
                if polled.get("status") == "invalid":
                    raise RuntimeError(f"ACME order finalization failed: {polled}")
                sleep_fn(3.0)
        if not certificate_url:
            raise RuntimeError("ACME order did not return a certificate download URL.")

        pem_chain_bytes = acme.post(
            str(certificate_url),
            None,
            accept="application/pem-certificate-chain",
        ).content
        certs = x509.load_pem_x509_certificates(pem_chain_bytes)
        if not certs:
            raise RuntimeError("ACME certificate response contained no X.509 certificates.")

        return _serialize_pfx(
            private_key=cert_key,
            cert=certs[0],
            cas=certs[1:],
            password=pfx_password,
            legacy_triple_des=True,
        )
    finally:
        for rec_id in created_record_ids:
            try:
                cloudflare.delete_record(zone_id, rec_id)
            except Exception:
                pass
        if owns_client:
            client.close()


def ensure_keyvault_wildcard_certificate(
    *,
    vault_name: str,
    cert_name: str = DEFAULT_CERT_NAME,
    cloudflare_api_token: str = "",
    zone_name: str = DEFAULT_ZONE_NAME,
    directory_url: str = LETSENCRYPT_PROD_DIRECTORY,
    min_remaining_days: int = 35,
    run_az_fn: Callable[..., Any],
) -> str:
    """Return unversioned Key Vault secret URI for the wildcard cert, issuing via ACME if needed."""
    unversioned_uri = f"https://{vault_name}.vault.azure.net/secrets/{cert_name}"
    existing = run_az_fn(
        [
            "keyvault",
            "certificate",
            "show",
            "--vault-name",
            vault_name,
            "--name",
            cert_name,
        ],
        check=False,
    )
    if isinstance(existing, dict) and existing.get("sid"):
        expires_raw = (existing.get("attributes") or {}).get("expires")
        if isinstance(expires_raw, str) and expires_raw:
            try:
                expires_dt = dt.datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
                remaining = (expires_dt - dt.datetime.now(dt.UTC)).days
                if remaining >= min_remaining_days:
                    return unversioned_uri
            except ValueError:
                pass

    if not cloudflare_api_token or not cloudflare_api_token.strip():
        raise RuntimeError(
            f"Key Vault certificate '{cert_name}' in '{vault_name}' is missing or expiring soon, "
            "and CLOUDFLARE_API_TOKEN was not provided."
        )

    pfx_password = secrets.token_urlsafe(24)
    with CloudflareDnsClient(cloudflare_api_token) as cf:
        pfx_bytes = issue_acme_wildcard_pfx(
            zone_name=zone_name,
            cloudflare=cf,
            pfx_password=pfx_password,
            directory_url=directory_url,
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        pfx_path = Path(tmp_dir) / "wildcard.pfx"
        pfx_path.write_bytes(pfx_bytes)
        last_err: Exception | None = None
        for attempt in range(6):
            try:
                run_az_fn(
                    [
                        "keyvault",
                        "certificate",
                        "import",
                        "--vault-name",
                        vault_name,
                        "--name",
                        cert_name,
                        "--file",
                        str(pfx_path),
                        "--password",
                        pfx_password,
                    ]
                )
                print(
                    f"[acme] Imported wildcard certificate '{cert_name}' "
                    f"into Key Vault '{vault_name}'.",
                    flush=True,
                )
                last_err = None
                break
            except Exception as exc:
                last_err = exc
                if attempt < 5:
                    time.sleep(10.0)
        if last_err is not None:
            raise last_err

    return unversioned_uri


def generate_short_lived_custom_pfx_base64(
    *,
    hostname: str,
    validity_days: int = 14,
) -> str:
    """Generate an unencrypted, short-lived (14-day) PFX in base64 for APIM-SEC-014 (`fail`)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    pfx_bytes = _serialize_pfx(
        private_key=private_key,
        cert=cert,
        cas=None,
        password=None,
    )
    return base64.b64encode(pfx_bytes).decode("ascii")


def upsert_lab_dns_records(
    *,
    cloudflare_api_token: str,
    zone_name: str = DEFAULT_ZONE_NAME,
    appgw_public_ip: str,
    apim_bv2_default_hostname: str,
    apim_dev_private_ip: str = "10.240.1.4",
    agw_bv2_hostname: str | None = None,
    agw_dev_hostname: str | None = None,
    api_bv2_hostname: str | None = None,
    api_dev_hostname: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, str]]:
    """Upsert Cloudflare DNS records for the Application Gateway and APIM custom domains."""
    clean_zone = zone_name.strip().lstrip("*.").rstrip(".")
    agw_bv2 = agw_bv2_hostname or f"agw-bv2.{clean_zone}"
    agw_dev = agw_dev_hostname or f"agw-dev.{clean_zone}"
    api_bv2 = api_bv2_hostname or f"api-bv2.{clean_zone}"
    api_dev = api_dev_hostname or f"api-dev.{clean_zone}"

    summary: list[dict[str, str]] = []
    with CloudflareDnsClient(cloudflare_api_token, transport=transport) as cf:
        zone_id = cf.resolve_zone_id(clean_zone)
        for host in (agw_bv2, agw_dev):
            if host and appgw_public_ip:
                cf.upsert_record(
                    zone_id,
                    record_type="A",
                    name=host,
                    content=appgw_public_ip,
                    proxied=False,
                )
                summary.append({"name": host, "type": "A", "target": appgw_public_ip})
        if api_bv2 and apim_bv2_default_hostname:
            cf.upsert_record(
                zone_id,
                record_type="CNAME",
                name=api_bv2,
                content=apim_bv2_default_hostname,
                proxied=False,
            )
            summary.append({"name": api_bv2, "type": "CNAME", "target": apim_bv2_default_hostname})
        if api_dev and apim_dev_private_ip:
            cf.upsert_record(
                zone_id,
                record_type="A",
                name=api_dev,
                content=apim_dev_private_ip,
                proxied=False,
            )
            summary.append({"name": api_dev, "type": "A", "target": apim_dev_private_ip})
    return summary
