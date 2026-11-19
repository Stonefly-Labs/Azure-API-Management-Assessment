import asyncio
import sys
from unittest.mock import AsyncMock

import psutil
import pytest

from apim_assess.mcp.jobs import Jobs
from apim_assess.mcp.models import Job, Work
from apim_assess.mcp.service import ServiceError, Workspace


def test_busy_cancel_close_and_restart(tmp_path):
    async def run():
        jobs = Jobs(Workspace(tmp_path))
        work = Work(operation="analyze", workspace=str(tmp_path), output="", snapshot="missing")
        started = await jobs.start(work)
        with pytest.raises(ServiceError, match="BUSY"):
            await jobs.start(work)
        cancelled = await jobs.cancel(started.job_id)
        assert cancelled.state == "cancelled"
        assert jobs.process.returncode is not None
        assert (await jobs.cancel(started.job_id)).state == "cancelled"
        await jobs.close()
        with pytest.raises(ServiceError, match="SERVER_CLOSED"):
            await jobs.start(work)
        with pytest.raises(ServiceError, match="UNKNOWN_JOB"):
            Jobs(Workspace(tmp_path)).get(started.job_id)

    asyncio.run(run())


def test_worker_failure_and_record_limit(tmp_path):
    async def run():
        jobs = Jobs(Workspace(tmp_path))
        for index in range(50):
            jobs.records[str(index)] = Job(job_id=str(index), state="completed", stage="done")
        work = Work(operation="analyze", workspace=str(tmp_path), output="", snapshot="missing")
        started = await jobs.start(work)
        await jobs.monitor
        assert jobs.get(started.job_id).state == "failed"
        assert jobs.get(started.job_id).error_code == "FILE_UNAVAILABLE"
        assert len(jobs.records) == 50
        assert "0" not in jobs.records
        await jobs.close()

    asyncio.run(run())


def test_worker_crash_is_not_success(tmp_path):
    async def run():
        jobs = Jobs(Workspace(tmp_path))
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "raise SystemExit(3)",
            stdout=asyncio.subprocess.PIPE,
        )
        job = Job(job_id="crash", stage="analyze")
        await jobs._watch(job, process)
        assert job.state == "failed"
        assert job.error_code == "WORKER_FAILED"

    asyncio.run(run())


def test_shutdown_kills_owned_worker_descendants(tmp_path):
    async def run():
        jobs = Jobs(Workspace(tmp_path))
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']); "
            "print(child.pid,flush=True); time.sleep(120)",
            stdout=asyncio.subprocess.PIPE,
        )
        child_pid = int(await process.stdout.readline())
        jobs.process = process
        jobs.records["owned"] = Job(job_id="owned", stage="analyze")
        await jobs.close()
        assert jobs.get("owned").state == "cancelled"
        assert process.returncode is not None
        if psutil.pid_exists(child_pid):
            assert psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE

    asyncio.run(run())


def test_start_failure_is_safe_and_does_not_reserve_slot(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "apim_assess.mcp.jobs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=OSError("SECRET_SENTINEL")),
    )

    async def run():
        jobs = Jobs(Workspace(tmp_path))
        with pytest.raises(ServiceError, match="WORKER_START_FAILED") as error:
            await jobs.start(Work(operation="analyze", workspace=str(tmp_path), output=""))
        assert "SENTINEL" not in str(error.value)
        assert not jobs.records
        await jobs.close()

    asyncio.run(run())


def test_shutdown_waits_for_inflight_start(tmp_path, monkeypatch):
    original = asyncio.create_subprocess_exec

    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def delayed(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original(*args, **kwargs)

        monkeypatch.setattr("apim_assess.mcp.jobs.asyncio.create_subprocess_exec", delayed)
        jobs = Jobs(Workspace(tmp_path))
        start = asyncio.create_task(
            jobs.start(
                Work(operation="analyze", workspace=str(tmp_path), output="", snapshot="missing")
            )
        )
        await entered.wait()
        shutdown = asyncio.create_task(jobs.close())
        await asyncio.sleep(0)
        release.set()
        job = await start
        await shutdown
        assert jobs.closed
        assert jobs.get(job.job_id).state == "cancelled"
        assert jobs.process.returncode is not None

    asyncio.run(run())
