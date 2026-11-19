from __future__ import annotations

import asyncio
import os
import sys
from collections import OrderedDict
from uuid import uuid4

import psutil
from pydantic import ValidationError

from apim_assess.mcp.models import Event, Job, Work
from apim_assess.mcp.service import ServiceError, Workspace


class Jobs:
    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.records: OrderedDict[str, Job] = OrderedDict()
        self.process: asyncio.subprocess.Process | None = None
        self.monitor: asyncio.Task[None] | None = None
        self.lock = asyncio.Lock()
        self.closed = False

    async def start(self, work: Work) -> Job:
        async with self.lock:
            if self.closed:
                raise ServiceError("SERVER_CLOSED")
            if any(item.state == "running" for item in self.records.values()):
                raise ServiceError("BUSY")
            while len(self.records) >= 50:
                self.records.popitem(last=False)
            identifier = uuid4().hex
            work.output = "runs/" + identifier
            self.workspace.path(work.output, directory=True)
            try:
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "apim_assess.mcp.worker",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    limit=1024 * 1024,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
            except OSError as exc:
                raise ServiceError("WORKER_START_FAILED") from exc
            self.process = process
            job = Job(job_id=identifier, stage=work.operation)
            self.records[identifier] = job
            self.monitor = asyncio.create_task(self._watch(job, process))
            assert process.stdin is not None
            process.stdin.write(work.model_dump_json().encode())
            try:
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                job.state = "failed"
                job.error_code = "WORKER_FAILED"
                await self._stop(process)
            finally:
                process.stdin.close()
            return job.model_copy(deep=True)

    async def _watch(self, job: Job, process: asyncio.subprocess.Process) -> None:
        assert process.stdout is not None
        terminal: Event | None = None
        try:
            while line := await process.stdout.readline():
                event = Event.model_validate_json(line)
                job.stage = event.stage
                job.artifacts.update(event.artifacts)
                if event.warnings:
                    job.warnings = event.warnings
                if event.stage == "done" and job.state == "running":
                    terminal = event
            await process.wait()
            if terminal is not None and job.state == "running":
                job.error_code = terminal.error_code or (
                    "WORKER_FAILED" if process.returncode else None
                )
                job.summary = terminal.summary
                job.pillar_scores = terminal.pillar_scores
                job.mcsb_assessed_score = terminal.mcsb_assessed_score
                job.state = "failed" if terminal.error_code or process.returncode else "completed"
        except (ValidationError, ValueError):
            await self._stop(process)
            job.error_code = "INVALID_WORKER_RESPONSE"
            job.state = "failed"
        finally:
            if job.state == "running":
                job.state = "failed"
                job.error_code = "WORKER_FAILED"

    def get(self, identifier: str) -> Job:
        if identifier not in self.records:
            raise ServiceError("UNKNOWN_JOB")
        return self.records[identifier].model_copy(deep=True)

    async def _stop(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)
            for child in reversed(children):
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            parent.kill()
        except psutil.NoSuchProcess:
            pass
        await process.wait()

    async def cancel(self, identifier: str) -> Job:
        async with self.lock:
            job = self.get(identifier)
            if job.state != "running":
                return job
            self.records[identifier].state = "cancelled"
            assert self.process is not None
            await self._stop(self.process)
            if self.monitor:
                await self.monitor
            return self.get(identifier)

    async def close(self) -> None:
        async with self.lock:
            self.closed = True
            identifiers = [job.job_id for job in self.records.values() if job.state == "running"]
        for identifier in identifiers:
            await self.cancel(identifier)
        if self.monitor:
            await self.monitor
