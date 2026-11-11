import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from azure.core.credentials import AccessToken

from apim_assess.analyzer.engine import analyze
from apim_assess.collector.apim_core import collect
from apim_assess.collector.client import ARM, ArmReader, AzureReadError
from apim_assess.collector.sanitizer import reference_id
from apim_assess.config import AssessmentConfig

ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/sample/providers/Microsoft.ApiManagement/service/sample-prod"
)
SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
SECRET = "SENSITIVE_TEST_SENTINEL_NOT_A_REAL_SECRET"


class FakeCredential:
    def __init__(self):
        self.calls = 0

    async def get_token(self, *scopes, **kwargs):
        self.calls += 1
        return AccessToken("synthetic-test-token", 9999999999)

    async def close(self):
        pass


def service(identifier=ID, sku="Premium"):
    return {
        "id": identifier,
        "name": identifier.rsplit("/", 1)[-1],
        "location": "eastus",
        "sku": {"name": sku, "capacity": 2},
        "zones": ["1", "2"],
        "identity": {"type": "SystemAssigned", "principalId": SECRET},
        "tags": {"env": "prod", "private-contact": SECRET},
        "properties": {
            "additionalLocations": [],
            "virtualNetworkType": "Internal",
            "publicNetworkAccess": "Enabled",
            "privateEndpointConnections": [],
            "customProperties": {
                "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2": "True",
                "Microsoft.WindowsAzure.ApiManagement.UnexpectedSecret": SECRET,
                f"Microsoft.WindowsAzure.ApiManagement.{SECRET}": True,
                "arbitrarySecret": SECRET,
            },
            "publisherEmail": SECRET,
            "publisherName": SECRET,
            "certificates": [{"data": SECRET, "password": SECRET}],
            "namedValues": [{"value": SECRET}],
        },
    }


def exercise(handler, config):
    def route(request):
        path = request.url.path
        if path.endswith("/pricings/Api"):
            return httpx.Response(200, json={"properties": {"pricingTier": "Free"}})
        if path.endswith("/autoscalesettings"):
            return httpx.Response(200, json={"value": []})
        tail = path.partition("/service/")[2]
        if tail and "/" in tail and not path.endswith("/metrics"):
            if path.endswith(("/tenant/access", "/portalsettings/signup")):
                return httpx.Response(200, json={"properties": {"enabled": False}})
            if path.endswith("/portalconfigs/default"):
                return httpx.Response(200, json={"properties": {"signin": {"require": True}}})
            if path.endswith("/policies/policy"):
                return httpx.Response(404)
            return httpx.Response(200, json={"value": []})
        return handler(request)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
            return await collect(config, ArmReader(FakeCredential(), client))

    return asyncio.run(run())


def metric_metadata(request):
    dimension = request.url.params.get("$filter", "").split(" ")[0]
    return (
        [
            {
                "name": {"value": dimension},
                "value": {
                    "Location": "eastus",
                    "GatewayResponseCodeCategory": "2xx",
                    "ApiId": SECRET,
                }[dimension],
            }
        ]
        if dimension
        else []
    )


def metric_unit(name):
    return (
        "Count"
        if name == "Requests"
        else ("MilliSeconds" if name in {"Duration", "BackendDuration"} else "Percent")
    )


def test_collection_projects_safe_metadata_and_queries_only_gets():
    requests = []
    point_time = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer synthetic-test-token"
        if request.url.path.endswith("/metrics"):
            name = request.url.params["metricnames"]
            timespan = request.url.params["timespan"]
            assert all(instant.endswith("Z") for instant in timespan.split("/"))
            assert "+" not in timespan
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "name": {"value": name},
                            "unit": metric_unit(name),
                            "timeseries": [
                                {
                                    "metadatavalues": metric_metadata(request),
                                    "data": [
                                        {
                                            "timeStamp": point_time.isoformat(),
                                            ("total" if name == "Requests" else "average"): 30,
                                            "minimum": 0,
                                            "private_payload": SECRET,
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                },
            )
        return httpx.Response(200, json=service())

    config = AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    snapshot = exercise(handler, config)
    assert SECRET not in snapshot.model_dump_json()
    instance = snapshot.instances[0]
    assert instance.identity_type == "SystemAssigned"
    assert len(instance.custom_properties) == 1
    assert instance.environment == "prod"
    assert len(instance.metrics) == 8
    metric_requests = [request for request in requests if request.url.path.endswith("/metrics")]
    assert {request.url.params["metricnames"] for request in metric_requests} == {
        "Capacity",
        "Requests",
        "Duration",
        "BackendDuration",
    }
    assert (
        next(
            request
            for request in metric_requests
            if request.url.params["metricnames"] == "Requests"
        ).url.params["aggregation"]
        == "Total"
    )
    assert {
        warning.code for warning in snapshot.collection_warnings if warning.module == "metrics"
    } == {"PARTIAL_METRIC_DATA"}
    by_split = {
        (request.url.params["metricnames"], request.url.params.get("$filter")): request.url.params
        for request in metric_requests
    }
    assert by_split["Capacity", "Location eq '*'"]["aggregation"] == "Average,Maximum"
    assert by_split["Requests", "ApiId eq '*'"]["top"] == "5"
    assert by_split["Requests", "ApiId eq '*'"]["orderby"] == "Total desc"
    assert by_split["BackendDuration", "ApiId eq '*'"]["aggregation"] == "Average,Maximum"
    assert by_split["BackendDuration", "ApiId eq '*'"]["orderby"] == "Maximum desc"
    assert any(
        series.dimensions.get("ApiId") == reference_id(SECRET.casefold())
        for series in instance.metrics
    )
    assert snapshot.telemetry_end - snapshot.telemetry_start == timedelta(days=30)


def test_v2_does_not_query_zero_returning_classic_metric():
    names = []

    def handler(request):
        if request.url.path.endswith("/metrics"):
            names.append(request.url.params["metricnames"])
            return httpx.Response(200, json={"value": []})
        return httpx.Response(200, json=service(sku="StandardV2"))

    config = AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    snapshot = exercise(handler, config)
    assert set(names) == {
        "CpuPercent_Gateway",
        "MemoryPercent_Gateway",
        "Requests",
        "Duration",
        "BackendDuration",
    }
    assert next(
        item for item in snapshot.instances[0].metrics if item.name == "Capacity"
    ).status == ("unsupported")
    assert all(
        warning.code == "NO_METRIC_DATA"
        for warning in snapshot.collection_warnings
        if warning.module == "metrics"
    )


@pytest.mark.parametrize("sku", ["Developer", "Basic", "Standard"])
def test_classic_non_premium_capacity_never_requests_zero_returning_maximum(sku):
    queries = []

    def handler(request):
        if request.url.path.endswith("/metrics"):
            queries.append(request.url.params)
            return httpx.Response(200, json={"value": []})
        return httpx.Response(200, json=service(sku=sku))

    exercise(
        handler, AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    )
    assert (
        next(query for query in queries if query["metricnames"] == "Capacity")["aggregation"]
        == "Average"
    )
    assert not any(
        query["metricnames"] in {"CpuPercent_Gateway", "MemoryPercent_Gateway"} for query in queries
    )


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        ("denied", "HTTP_403"),
        ("no_dimension", "MISSING_METRIC_DIMENSION"),
        ("too_many", "METRIC_SERIES_LIMIT_EXCEEDED"),
        ("duplicate", "DUPLICATE_METRIC_SERIES"),
        ("wrong_unit", "INVALID_METRIC_UNIT"),
    ],
)
def test_failed_dimensional_query_does_not_discard_other_splits_or_leak_data(failure, code):
    timestamp = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)

    def handler(request):
        if not request.url.path.endswith("/metrics"):
            return httpx.Response(200, json=service())
        name = request.url.params["metricnames"]
        dimension = request.url.params.get("$filter", "").split(" ")[0]
        data = [{"timeStamp": timestamp.isoformat(), "average": 25, "maximum": 50, "total": 10}]
        series = {"metadatavalues": metric_metadata(request), "data": data}
        body = {"name": {"value": name}, "unit": metric_unit(name), "timeseries": [series]}
        if name == "Requests" and dimension == "ApiId":
            if failure == "denied":
                return httpx.Response(403, json={"error": {"message": SECRET}})
            if failure == "no_dimension":
                series["metadatavalues"] = []
            elif failure == "too_many":
                body["timeseries"] = [series] * 6
            elif failure == "duplicate":
                body["timeseries"] = [series] * 2
            elif failure == "wrong_unit":
                body["unit"] = SECRET
        return httpx.Response(200, json={"value": [body]})

    snapshot = exercise(
        handler, AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    )
    metrics = snapshot.instances[0].metrics
    assert (
        next(
            series
            for series in metrics
            if series.name == "Requests" and "ApiId" in series.dimensions
        ).status
        == "unavailable"
    )
    assert (
        next(
            series
            for series in metrics
            if series.name == "Requests" and "GatewayResponseCodeCategory" in series.dimensions
        ).status
        == "available"
    )
    assert (
        next(series for series in metrics if series.name == "BackendDuration").status == "available"
    )
    assert any(warning.code == code for warning in snapshot.collection_warnings)
    assert SECRET not in snapshot.model_dump_json()


def test_missing_maxima_remain_partial_even_with_every_hour_present():
    def handler(request):
        if not request.url.path.endswith("/metrics"):
            return httpx.Response(200, json=service())
        name = request.url.params["metricnames"]
        start = datetime.fromisoformat(request.url.params["timespan"].split("/")[0])
        points = [
            {
                "timeStamp": (start + timedelta(hours=index)).isoformat(),
                ("total" if name == "Requests" else "average"): 10,
            }
            for index in range(24)
        ]
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": {"value": name},
                        "unit": metric_unit(name),
                        "timeseries": [
                            {"metadatavalues": metric_metadata(request), "data": points}
                        ],
                    }
                ]
            },
        )

    snapshot = exercise(
        handler,
        AssessmentConfig.model_validate(
            {"targets": {"instances": [{"resource_id": ID}]}, "telemetry": {"lookback_days": 1}}
        ),
    )
    warnings = [warning for warning in snapshot.collection_warnings if warning.module == "metrics"]
    assert {warning.code for warning in warnings} == {"PARTIAL_METRIC_DATA"}
    assert all("Requests /" not in warning.message for warning in warnings)
    assert any("Capacity / Location" in warning.message for warning in warnings)
    assert any("BackendDuration / ApiId" in warning.message for warning in warnings)


def test_no_status_category_does_not_discard_other_status_splits():
    timestamp = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)

    def handler(request):
        if not request.url.path.endswith("/metrics"):
            return httpx.Response(200, json=service())
        name = request.url.params["metricnames"]
        dimension = request.url.params.get("$filter", "").split(" ")[0]
        if name != "Requests" or dimension != "GatewayResponseCodeCategory":
            return httpx.Response(200, json={"value": []})
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": {"value": name},
                        "unit": "Count",
                        "timeseries": [
                            {
                                "metadatavalues": [
                                    {"name": {"value": dimension}, "value": category}
                                ],
                                "data": [{"timeStamp": timestamp.isoformat(), "total": total}],
                            }
                            for category, total in [("4xx", 4), ("5xx", 5), ("None", 2)]
                        ],
                    }
                ]
            },
        )

    snapshot = exercise(
        handler, AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    )
    categories = {
        series.dimensions["GatewayResponseCodeCategory"]: series
        for series in snapshot.instances[0].metrics
        if "GatewayResponseCodeCategory" in series.dimensions
    }
    assert set(categories) == {"4xx", "5xx", "none"}
    assert all(series.status == "available" for series in categories.values())
    assert categories["none"].points[0].total == 2
    assert not any(
        warning.code == "INVALID_METRIC_CATEGORY" for warning in snapshot.collection_warnings
    )


def test_permission_failure_is_preserved_without_response_body():
    def handler(request):
        return httpx.Response(403, json={"error": {"message": SECRET}})

    snapshot = exercise(
        handler, AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    )
    assert snapshot.collection_warnings[0].code == "HTTP_403"
    assert SECRET not in snapshot.model_dump_json()
    assert all(result.result.outcome == "unknown" for result in analyze(snapshot).findings)


def test_duplicate_metric_samples_become_structured_warnings():
    timestamp = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)

    def handler(request):
        if not request.url.path.endswith("/metrics"):
            return httpx.Response(200, json=service())
        point = {
            "timeStamp": timestamp.isoformat(),
            "average": 30,
            "total": 30,
            "minimum": 0,
            "private_payload": SECRET,
        }
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": {"value": request.url.params["metricnames"]},
                        "unit": metric_unit(request.url.params["metricnames"]),
                        "timeseries": [
                            {"metadatavalues": metric_metadata(request), "data": [point, point]}
                        ],
                    }
                ]
            },
        )

    snapshot = exercise(
        handler, AssessmentConfig.model_validate({"targets": {"instances": [{"resource_id": ID}]}})
    )
    assert snapshot.instances[0].core_status == "available"
    assert {
        warning.code for warning in snapshot.collection_warnings if warning.module == "metrics"
    } == {"DUPLICATE_METRIC_TIMESTAMPS"}
    assert SECRET not in snapshot.model_dump_json()


def test_discovery_pagination_deduplication_and_explicit_targets():
    first_path = f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.ApiManagement/service"
    second = ID + "-second"
    discovered_paths = []

    def handler(request):
        discovered_paths.append(request.url.path)
        if request.url.path == first_path:
            if request.url.params.get("page") == "2":
                return httpx.Response(200, json={"value": [{"id": second}]})
            return httpx.Response(
                200, json={"value": [{"id": ID.upper()}], "nextLink": ARM + first_path + "?page=2"}
            )
        return httpx.Response(200, json=service(str(request.url.path)))

    config = AssessmentConfig.model_validate(
        {
            "targets": {"instances": [{"resource_id": ID}], "subscriptions": [SUBSCRIPTION]},
            "modules": {"metrics": False},
        }
    )
    snapshot = exercise(handler, config)
    assert len(snapshot.instances) == 2
    assert discovered_paths.count(first_path) == 2
    assert all(instance.core_status == "available" for instance in snapshot.instances)
    assert all(
        warning.code == "DISABLED"
        for warning in snapshot.collection_warnings
        if warning.module in {"discovery", "core", "metrics"}
    )


def test_pagination_cannot_send_tokens_to_another_host():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "value": [{"id": ID}],
                "nextLink": f"https://attacker.invalid{request.url.path}?page=2",
            },
        )

    config = AssessmentConfig.model_validate(
        {
            "targets": {"subscriptions": [SUBSCRIPTION]},
            "modules": {"metrics": False},
        }
    )
    snapshot = exercise(handler, config)
    assert snapshot.collection_warnings[0].code == "UNSAFE_URL"
    assert all(request.url.host == "management.azure.com" for request in calls)


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.invalid/subscriptions/x",
        "http://management.azure.com/subscriptions/x",
        "https://user:password@management.azure.com/subscriptions/x",
        "https://management.azure.com:8443/subscriptions/x",
    ],
)
def test_reader_rejects_unsafe_urls_before_authentication(url):
    credential = FakeCredential()

    async def run():
        async with httpx.AsyncClient() as client:
            reader = ArmReader(credential, client)
            with pytest.raises(AzureReadError, match="UNSAFE_URL"):
                await reader.get(url)

    asyncio.run(run())
    assert credential.calls == 0


def test_retries_are_bounded_and_do_not_expose_failures():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "1000"}, text=SECRET)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            reader = ArmReader(FakeCredential(), client)
            with pytest.raises(AzureReadError, match="HTTP_429"):
                await reader.get(ID)

    with patch("apim_assess.collector.client.asyncio.sleep", new_callable=AsyncMock) as sleep:
        asyncio.run(run())
    assert len(calls) == 3
    assert all(call.args[0] <= 5 for call in sleep.call_args_list)


def test_default_https_port_in_same_origin_pagination_is_supported():
    def handler(request):
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"value": [2]})
        return httpx.Response(
            200,
            json={
                "value": [1],
                "nextLink": "https://management.azure.com:443" + ID + "?page=2",
            },
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return [item async for item in ArmReader(FakeCredential(), client).pages(ID, "test")]

    assert asyncio.run(run()) == [1, 2]


def test_concurrent_reads_share_cached_token_and_refresh_before_expiry():
    authorizations = []

    def handler(request):
        authorizations.append(request.headers["authorization"])
        return httpx.Response(200, json={})

    async def run():
        credential = AsyncMock()
        credential.get_token.side_effect = [
            AccessToken("first-test-token", 1000),
            AccessToken("second-test-token", 2000),
        ]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            reader = ArmReader(credential, client)
            with patch("apim_assess.collector.client.time.time", return_value=500):
                await asyncio.gather(*(reader.get(ID) for _ in range(20)))
            assert credential.get_token.await_count == 1
            with patch("apim_assess.collector.client.time.time", return_value=870):
                await reader.get(ID)
            assert credential.get_token.await_count == 1
            with patch("apim_assess.collector.client.time.time", return_value=880):
                await reader.get(ID)
            assert credential.get_token.await_count == 2

    asyncio.run(run())
    assert authorizations[:-1] == ["Bearer first-test-token"] * 21
    assert authorizations[-1] == "Bearer second-test-token"
