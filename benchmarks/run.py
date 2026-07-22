#!/usr/bin/env python3
"""在 Linux 上运行 Ram 可复现的端到端性能套件。

本测试工具有意只使用 Python 标准库。功能与串行用例由 curl 驱动，持久 HTTP/1.1 和
HTTP/2 负载由 h2load 驱动。服务器资源使用从 /proc 采样，因此结果描述 Ram 进程，
而不是负载生成器。

Run Ram's reproducible end-to-end performance suite on Linux.

The harness intentionally uses only the Python standard library.  curl drives
the functional/sequential cases and h2load drives persistent HTTP/1.1 and
HTTP/2 load.  Server resource use is sampled from /proc, so results describe
the Ram process rather than the load generator.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESULT_SCHEMA_VERSION = 1
MIB = 1024 * 1024


class BenchmarkError(RuntimeError):
    """前置条件、服务器操作或测量失败。 / A prerequisite, server operation, or measurement failed."""


def command_output(command: Sequence[str], *, timeout: float = 30.0) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise BenchmarkError(f"command failed: {' '.join(command)}: {error}") from error
    return completed.stdout.strip()


def parse_positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def parse_nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return parsed


def parse_size(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([KMG]i?B?|B)?", value, re.IGNORECASE)
    if match is None:
        raise argparse.ArgumentTypeError(
            "size must be a positive integer with an optional K, M, G, KiB, MiB, or GiB suffix"
        )
    number = int(match.group(1))
    suffix = (match.group(2) or "B").upper()
    multipliers = {
        "B": 1,
        "K": 1024,
        "KB": 1024,
        "KIB": 1024,
        "M": 1024**2,
        "MB": 1024**2,
        "MIB": 1024**2,
        "G": 1024**3,
        "GB": 1024**3,
        "GIB": 1024**3,
    }
    return number * multipliers[suffix]


def parse_cpu_list(value: str) -> list[int]:
    cpus: set[int] = set()
    try:
        for group in value.split(","):
            bounds = group.strip().split("-", 1)
            if len(bounds) == 1:
                cpus.add(int(bounds[0]))
            else:
                start, end = (int(item) for item in bounds)
                if end < start:
                    raise ValueError
                cpus.update(range(start, end + 1))
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid CPU list: {value!r}") from error
    if not cpus or min(cpus) < 0:
        raise argparse.ArgumentTypeError(f"invalid CPU list: {value!r}")
    return sorted(cpus)


def cpu_list_text(cpus: Sequence[int]) -> str:
    return ",".join(str(cpu) for cpu in cpus)


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        raise BenchmarkError("cannot summarize an empty sample set")
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def summarize_numbers(values: Sequence[float]) -> dict[str, float]:
    if not values:
        raise BenchmarkError("cannot summarize an empty sample set")
    return {
        "minimum": min(values),
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "maximum": max(values),
    }


def atomic_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(
            value,
            stream,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def proc_status_bytes(pid: int, field: str) -> int:
    status = Path(f"/proc/{pid}/status")
    try:
        for line in status.read_text(encoding="ascii").splitlines():
            if line.startswith(f"{field}:"):
                parts = line.split()
                return int(parts[1]) * 1024
    except (FileNotFoundError, ProcessLookupError):
        return 0
    return 0


def proc_count(path: Path) -> int:
    try:
        return sum(1 for _ in path.iterdir())
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return 0


@dataclass
class ResourceSnapshot:
    monotonic_seconds: float
    rss_bytes: int
    fd_count: int
    thread_count: int


class ProcessSampler:
    """在不为服务器加插桩的情况下采样进程。 / Sample one process without instrumenting the server."""

    def __init__(self, pid: int, interval_seconds: float = 0.02) -> None:
        self.pid = pid
        self.interval_seconds = interval_seconds
        self.samples: list[ResourceSnapshot] = []
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None

    def _snapshot(self) -> ResourceSnapshot:
        return ResourceSnapshot(
            monotonic_seconds=time.monotonic(),
            rss_bytes=proc_status_bytes(self.pid, "VmRSS"),
            fd_count=proc_count(Path(f"/proc/{self.pid}/fd")),
            thread_count=proc_count(Path(f"/proc/{self.pid}/task")),
        )

    def _run(self) -> None:
        while not self._stopped.wait(self.interval_seconds):
            self.samples.append(self._snapshot())

    def __enter__(self) -> "ProcessSampler":
        self.samples.append(self._snapshot())
        self._thread = threading.Thread(target=self._run, name="ram-benchmark-proc", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stopped.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self.samples.append(self._snapshot())

    def summary(self) -> dict[str, int]:
        if not self.samples:
            raise BenchmarkError("resource sampler produced no observations")
        initial = self.samples[0]
        rss_peak = max(sample.rss_bytes for sample in self.samples)
        return {
            "rss_initial_bytes": initial.rss_bytes,
            "rss_peak_bytes": rss_peak,
            "rss_peak_delta_bytes": max(0, rss_peak - initial.rss_bytes),
            "fd_initial": initial.fd_count,
            "fd_peak": max(sample.fd_count for sample in self.samples),
            "thread_initial": initial.thread_count,
            "thread_peak": max(sample.thread_count for sample in self.samples),
            "sample_count": len(self.samples),
        }


@dataclass(frozen=True)
class Fixture:
    root: Path
    payload: Path
    load_object: Path
    directory: Path
    tls_cert: Path
    tls_key: Path
    large_bytes: int
    load_bytes: int
    directory_entries: int
    directory_input_bytes: int
    creation_seconds: float


def write_pattern_file(path: Path, size: int) -> None:
    chunk = bytes(range(256)) * 4096
    remaining = size
    with path.open("wb", buffering=0) as stream:
        while remaining:
            block = chunk[: min(len(chunk), remaining)]
            stream.write(block)
            remaining -= len(block)
        os.fsync(stream.fileno())


def create_fixture(
    work_dir: Path,
    *,
    large_bytes: int,
    load_bytes: int,
    directory_entries: int,
    source_cert: Path,
    source_key: Path,
) -> Fixture:
    started = time.monotonic()
    root = work_dir / "served"
    secrets_dir = work_dir / "secrets"
    directory = root / "directory"
    directory.mkdir(parents=True)
    secrets_dir.mkdir(mode=0o700)

    payload = root / "payload.bin"
    load_object = root / "load.bin"
    write_pattern_file(payload, large_bytes)
    write_pattern_file(load_object, load_bytes)

    directory_input_bytes = 0
    for index in range(directory_entries):
        content = f"ram-benchmark-entry-{index:08d}\n".encode("ascii")
        (directory / f"entry-{index:08d}.txt").write_bytes(content)
        directory_input_bytes += len(content)

    tls_cert = secrets_dir / "cert.pem"
    tls_key = secrets_dir / "key.pem"
    shutil.copyfile(source_cert, tls_cert)
    shutil.copyfile(source_key, tls_key)
    tls_cert.chmod(0o600)
    tls_key.chmod(0o600)

    return Fixture(
        root=root,
        payload=payload,
        load_object=load_object,
        directory=directory,
        tls_cert=tls_cert,
        tls_key=tls_key,
        large_bytes=large_bytes,
        load_bytes=load_bytes,
        directory_entries=directory_entries,
        directory_input_bytes=directory_input_bytes,
        creation_seconds=time.monotonic() - started,
    )


class RamServer:
    def __init__(
        self,
        *,
        binary: Path,
        profile: str,
        fixture: Fixture,
        work_dir: Path,
        password: str,
        h2_streams: int,
        max_expensive_tasks: int,
        server_cpus: Sequence[int],
    ) -> None:
        self.binary = binary
        self.profile = profile
        self.fixture = fixture
        self.work_dir = work_dir
        self.password = password
        self.h2_streams = h2_streams
        self.max_expensive_tasks = max_expensive_tasks
        self.server_cpus = list(server_cpus)
        self.port = reserve_loopback_port()
        self.process: subprocess.Popen[bytes] | None = None
        self.log_path = work_dir / f"server-{profile}-h2-{h2_streams}-{self.port}.log"
        self._log_stream: Any = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    @property
    def pid(self) -> int:
        if self.process is None:
            raise BenchmarkError("server is not running")
        return self.process.pid

    @property
    def authorization(self) -> str:
        token = base64.b64encode(f"benchmark:{self.password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def command(self) -> list[str]:
        max_requests = max(256, self.h2_streams * 8)
        command = [
            str(self.binary),
            "--bind",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--auth",
            f"benchmark:{self.password}@/:rw",
            "--allow-upload",
            "--allow-search",
            "--allow-archive",
            "--allow-hash",
            "--max-connections",
            str(max_requests),
            "--max-concurrent-requests",
            str(max_requests),
            "--max-concurrent-requests-per-source",
            str(max_requests),
            "--max-concurrent-requests-per-user",
            str(max_requests),
            "--max-request-queue",
            str(max_requests),
            "--max-concurrent-uploads",
            "64",
            "--max-concurrent-uploads-per-source",
            "64",
            "--max-concurrent-uploads-per-user",
            "64",
            "--h2-max-concurrent-streams",
            str(self.h2_streams),
            "--max-expensive-tasks",
            str(self.max_expensive_tasks),
            "--max-blocking-threads",
            "32",
            "--max-walk-entries",
            str(max(20_000, self.fixture.directory_entries + 100)),
            "--max-search-results",
            str(max(10_000, self.fixture.directory_entries)),
            "--max-directory-entries",
            str(max(10_000, self.fixture.directory_entries)),
            "--max-archive-size",
            str(max(4 * MIB, self.fixture.directory_input_bytes * 2)),
            "--max-hash-size",
            str(max(4 * MIB, self.fixture.large_bytes * 2)),
            "--max-upload-size",
            str(max(4 * MIB, self.fixture.large_bytes * 2)),
            "--tls-cert",
            str(self.fixture.tls_cert),
            "--tls-key",
            str(self.fixture.tls_key),
            str(self.fixture.root),
        ]
        if self.server_cpus:
            return ["taskset", "--cpu-list", cpu_list_text(self.server_cpus), *command]
        return command

    def start(self) -> None:
        self._log_stream = self.log_path.open("wb")
        self.process = subprocess.Popen(
            self.command(),
            stdin=subprocess.DEVNULL,
            stdout=self._log_stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        health_url = f"{self.url}/__ram__/health"
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            completed = subprocess.run(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--insecure",
                    "--max-time",
                    "1",
                    "--output",
                    "/dev/null",
                    health_url,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode == 0:
                return
            time.sleep(0.05)
        log_tail = ""
        try:
            log_tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            pass
        self.stop()
        raise BenchmarkError(f"Ram failed to become ready at {health_url}\n{log_tail}")

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15.0)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5.0)
        self.process = None
        if self._log_stream is not None:
            self._log_stream.close()
            self._log_stream = None

    def __enter__(self) -> "RamServer":
        self.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.stop()


def taskset_prefix(cpus: Sequence[int]) -> list[str]:
    if not cpus:
        return []
    return ["taskset", "--cpu-list", cpu_list_text(cpus)]


def run_curl_measurement(
    server: RamServer,
    *,
    path: str,
    method: str = "GET",
    upload: Path | None = None,
    client_cpus: Sequence[int],
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    write_out = (
        "%{http_code}\\t%{size_download}\\t%{size_upload}\\t"
        "%{speed_download}\\t%{speed_upload}\\t%{time_total}\\t%{http_version}"
    )
    command = [
        *taskset_prefix(client_cpus),
        "curl",
        "--silent",
        "--show-error",
        "--insecure",
        "--http1.1",
        "--max-time",
        str(timeout_seconds),
        "--output",
        "/dev/null",
        "--header",
        f"Authorization: {server.authorization}",
        "--request",
        method,
        "--write-out",
        write_out,
    ]
    if upload is not None:
        command.extend(["--header", "Expect:", "--data-binary", f"@{upload}"])
    command.append(f"{server.url}{path}")

    started = time.monotonic()
    with ProcessSampler(server.pid) as sampler:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    wall_seconds = time.monotonic() - started
    if completed.returncode != 0:
        raise BenchmarkError(
            f"curl {method} {path} failed with exit {completed.returncode}: {completed.stderr.strip()}"
        )
    fields = completed.stdout.strip().split("\t")
    if len(fields) != 7:
        raise BenchmarkError(f"unexpected curl metrics for {method} {path}: {completed.stdout!r}")
    try:
        status = int(fields[0])
        size_download = int(float(fields[1]))
        size_upload = int(float(fields[2]))
        speed_download = float(fields[3])
        speed_upload = float(fields[4])
        elapsed_seconds = float(fields[5])
    except ValueError as error:
        raise BenchmarkError(f"invalid curl metrics: {completed.stdout!r}") from error
    if not 200 <= status < 300:
        raise BenchmarkError(f"curl {method} {path} returned HTTP {status}")
    return {
        "http_status": status,
        "http_version": fields[6],
        "elapsed_seconds": elapsed_seconds,
        "wall_seconds": wall_seconds,
        "size_download_bytes": size_download,
        "size_upload_bytes": size_upload,
        "download_bytes_per_second": speed_download,
        "upload_bytes_per_second": speed_upload,
        "resources": sampler.summary(),
    }


def summarize_curl_samples(samples: Sequence[dict[str, Any]]) -> dict[str, Any]:
    metrics = [
        "elapsed_seconds",
        "wall_seconds",
        "size_download_bytes",
        "size_upload_bytes",
        "download_bytes_per_second",
        "upload_bytes_per_second",
    ]
    summary: dict[str, Any] = {
        metric: summarize_numbers([float(sample[metric]) for sample in samples])
        for metric in metrics
    }
    for resource in ["rss_peak_bytes", "rss_peak_delta_bytes", "fd_peak", "thread_peak"]:
        summary[resource] = max(int(sample["resources"][resource]) for sample in samples)
    return summary


def run_curl_scenario(
    server: RamServer,
    *,
    path: str,
    method: str,
    upload: Path | None,
    warmups: int,
    iterations: int,
    client_cpus: Sequence[int],
) -> dict[str, Any]:
    for _ in range(warmups):
        run_curl_measurement(
            server,
            path=path,
            method=method,
            upload=upload,
            client_cpus=client_cpus,
        )
    samples = [
        run_curl_measurement(
            server,
            path=path,
            method=method,
            upload=upload,
            client_cpus=client_cpus,
        )
        for _ in range(iterations)
    ]
    return {"samples": samples, "summary": summarize_curl_samples(samples)}


def parse_duration(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s)", value)
    if match is None:
        raise BenchmarkError(f"cannot parse h2load duration {value!r}")
    multipliers = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0}
    return float(match.group(1)) * multipliers[match.group(2)]


def parse_byte_rate(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(B|KB|MB|GB)/s", value)
    if match is None:
        raise BenchmarkError(f"cannot parse h2load byte rate {value!r}")
    multipliers = {"B": 1.0, "KB": 1024.0, "MB": 1024.0**2, "GB": 1024.0**3}
    return float(match.group(1)) * multipliers[match.group(2)]


def parse_h2load_output(output: str) -> dict[str, Any]:
    finished = re.search(
        r"finished in\s+(\S+),\s+([0-9]+(?:\.[0-9]+)?)\s+req/s,\s+(\S+/s)",
        output,
    )
    requests = re.search(
        r"requests:\s+(\d+) total,\s+(\d+) started,\s+(\d+) done,\s+"
        r"(\d+) succeeded,\s+(\d+) failed",
        output,
    )
    statuses = re.search(r"status codes:\s+(\d+) 2xx,\s+(\d+) 3xx,\s+(\d+) 4xx,\s+(\d+) 5xx", output)
    request_time = re.search(
        r"time for request:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", output
    )
    if any(match is None for match in [finished, requests, statuses, request_time]):
        raise BenchmarkError(f"unrecognized h2load output:\n{output}")
    assert finished is not None and requests is not None
    assert statuses is not None and request_time is not None
    metrics = {
        "elapsed_seconds": parse_duration(finished.group(1)),
        "requests_per_second": float(finished.group(2)),
        "wire_bytes_per_second": parse_byte_rate(finished.group(3)),
        "requests_total": int(requests.group(1)),
        "requests_started": int(requests.group(2)),
        "requests_done": int(requests.group(3)),
        "requests_succeeded": int(requests.group(4)),
        "requests_failed": int(requests.group(5)),
        "status_2xx": int(statuses.group(1)),
        "status_3xx": int(statuses.group(2)),
        "status_4xx": int(statuses.group(3)),
        "status_5xx": int(statuses.group(4)),
        "request_time_min_seconds": parse_duration(request_time.group(1)),
        "request_time_max_seconds": parse_duration(request_time.group(2)),
        "request_time_mean_seconds": parse_duration(request_time.group(3)),
        "request_time_sd_seconds": parse_duration(request_time.group(4)),
    }
    if metrics["requests_failed"] != 0 or metrics["status_2xx"] != metrics["requests_total"]:
        raise BenchmarkError(f"h2load requests did not all return 2xx:\n{output}")
    return metrics


def run_h2load(
    server: RamServer,
    *,
    path: str,
    protocol: str,
    requests: int,
    clients: int,
    streams: int,
    client_cpus: Sequence[int],
    sample_resources: bool = True,
) -> dict[str, Any]:
    if protocol not in {"http1", "h2"}:
        raise BenchmarkError(f"unsupported load protocol: {protocol}")
    command = [
        *taskset_prefix(client_cpus),
        "h2load",
        "--requests",
        str(requests),
        "--clients",
        str(clients),
        "--threads",
        "1",
        "--max-concurrent-streams",
        str(streams),
        "--header",
        f"authorization: {server.authorization}",
    ]
    if protocol == "http1":
        command.append("--h1")
    else:
        # 不允许 ALPN 悄然回退 HTTP/1.1 却把样本标为 HTTP/2。
        # Do not let ALPN silently fall back to HTTP/1.1 while labeling the sample HTTP/2.
        command.append("--alpn-list=h2")
    command.append(f"{server.url}{path}")

    started = time.monotonic()
    sampler = ProcessSampler(server.pid)
    if sample_resources:
        sampler.__enter__()
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
            timeout=900,
        )
    finally:
        if sample_resources:
            sampler.__exit__()
    wall_seconds = time.monotonic() - started
    if completed.returncode != 0:
        raise BenchmarkError(f"h2load failed with exit {completed.returncode}:\n{completed.stdout}")
    metrics = parse_h2load_output(completed.stdout)
    metrics["wall_seconds"] = wall_seconds
    metrics["protocol"] = protocol
    metrics["clients"] = clients
    metrics["streams_per_client"] = streams
    metrics["offered_concurrency"] = clients * streams
    metrics["raw_output"] = completed.stdout
    if sample_resources:
        metrics["resources"] = sampler.summary()
    return metrics


def load_scenario(
    server: RamServer,
    *,
    protocol: str,
    streams: int,
    requests: int,
    clients: int,
    fixture: Fixture,
    client_cpus: Sequence[int],
) -> dict[str, Any]:
    transfer = run_h2load(
        server,
        path="/load.bin",
        protocol=protocol,
        requests=requests,
        clients=clients,
        streams=streams,
        client_cpus=client_cpus,
    )
    transfer["application_bytes_per_second"] = (
        fixture.load_bytes * transfer["requests_succeeded"] / transfer["elapsed_seconds"]
    )

    single_hash = run_h2load(
        server,
        path="/load.bin?hash",
        protocol=protocol,
        requests=3,
        clients=1,
        streams=1,
        client_cpus=client_cpus,
        sample_resources=False,
    )
    queue_requests = max(requests, clients * streams * 2)
    saturated_hash = run_h2load(
        server,
        path="/load.bin?hash",
        protocol=protocol,
        requests=queue_requests,
        clients=clients,
        streams=streams,
        client_cpus=client_cpus,
    )
    baseline_ms = single_hash["request_time_mean_seconds"] * 1000.0
    saturated_ms = saturated_hash["request_time_mean_seconds"] * 1000.0
    queue = {
        "single_request_mean_ms": baseline_ms,
        "saturated_request_mean_ms": saturated_ms,
        # 该值有意称为 proxy。Tokio 不暴露阻塞队列长度，推导虚构精确计数会误导基线；多余延迟
        # 可观察，并能在固定 runner 上捕获队列/工作线程回退。
        # Deliberately call this a proxy. Tokio exposes no blocking-queue length; a fictitious exact
        # count would mislead. Observable excess latency catches regressions on a fixed runner.
        "blocking_queue_delay_proxy_ms": max(0.0, saturated_ms - baseline_ms),
        "expensive_task_slots": server.max_expensive_tasks,
        "offered_concurrency": clients * streams,
        "offered_concurrency_above_slots": max(
            0, clients * streams - server.max_expensive_tasks
        ),
        "load": saturated_hash,
    }
    return {"transfer": transfer, "blocking_queue": queue}


def add_curl_regression_metrics(
    target: dict[str, float], profile: str, scenario: str, result: dict[str, Any]
) -> None:
    summary = result["summary"]
    prefix = f"{profile}/{scenario}"
    target[f"{prefix}/elapsed_seconds_median"] = summary["elapsed_seconds"]["median"]
    target[f"{prefix}/rss_peak_bytes"] = float(summary["rss_peak_bytes"])
    target[f"{prefix}/fd_peak"] = float(summary["fd_peak"])
    target[f"{prefix}/thread_peak"] = float(summary["thread_peak"])
    if scenario == "large_put":
        target[f"{prefix}/throughput_bytes_per_second_median"] = summary[
            "upload_bytes_per_second"
        ]["median"]
    elif scenario in {"large_get", "directory_zip"}:
        target[f"{prefix}/throughput_bytes_per_second_median"] = summary[
            "download_bytes_per_second"
        ]["median"]
    elif scenario == "large_hash":
        target[f"{prefix}/throughput_bytes_per_second_median"] = (
            result["input_bytes"] / summary["elapsed_seconds"]["median"]
        )


def add_load_regression_metrics(
    target: dict[str, float], profile: str, name: str, result: dict[str, Any]
) -> None:
    transfer = result["transfer"]
    queue = result["blocking_queue"]
    prefix = f"{profile}/{name}"
    target[f"{prefix}/requests_per_second"] = transfer["requests_per_second"]
    target[f"{prefix}/application_bytes_per_second"] = transfer[
        "application_bytes_per_second"
    ]
    target[f"{prefix}/request_time_mean_seconds"] = transfer["request_time_mean_seconds"]
    target[f"{prefix}/rss_peak_bytes"] = float(transfer["resources"]["rss_peak_bytes"])
    target[f"{prefix}/fd_peak"] = float(transfer["resources"]["fd_peak"])
    target[f"{prefix}/thread_peak"] = float(transfer["resources"]["thread_peak"])
    target[f"{prefix}/blocking_queue_delay_proxy_ms"] = queue[
        "blocking_queue_delay_proxy_ms"
    ]


def build_profile_comparison(metrics: dict[str, float]) -> dict[str, Any]:
    debug_prefix = "debug/"
    release_prefix = "release/"
    comparisons: dict[str, Any] = {}
    for key, debug_value in sorted(metrics.items()):
        if not key.startswith(debug_prefix):
            continue
        suffix = key[len(debug_prefix) :]
        release_key = f"{release_prefix}{suffix}"
        if release_key not in metrics:
            continue
        release_value = metrics[release_key]
        difference_fraction = None
        if debug_value != 0:
            difference_fraction = (release_value - debug_value) / debug_value
        comparisons[suffix] = {
            "debug": debug_value,
            "release": release_value,
            "release_minus_debug_fraction": difference_fraction,
        }
    return comparisons


def read_first_line(command: Sequence[str]) -> str:
    output = command_output(command)
    return output.splitlines()[0] if output else ""


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith(("model name", "hardware")):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def memory_total_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def cpu_governors(cpus: Sequence[int]) -> dict[str, str]:
    governors: dict[str, str] = {}
    for cpu in cpus:
        path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
        try:
            governors[str(cpu)] = path.read_text(encoding="ascii").strip()
        except OSError:
            governors[str(cpu)] = "unavailable"
    return governors


def filesystem_type(path: Path) -> str:
    return command_output(["stat", "--file-system", "--format=%T", str(path)])


def git_commit() -> str:
    try:
        return command_output(["git", "rev-parse", "HEAD"])
    except BenchmarkError:
        return "unknown"


def environment_metadata(
    *,
    runner_id: str,
    work_dir: Path,
    server_cpus: Sequence[int],
    client_cpus: Sequence[int],
    binaries: dict[str, Path],
    include_h2load: bool,
    binary_contract: str,
) -> dict[str, Any]:
    curl_version = read_first_line(["curl", "--version"])
    h2load_version = read_first_line(["h2load", "--version"]) if include_h2load else None
    all_cpus = sorted(set(server_cpus) | set(client_cpus))
    stable = {
        "runner_id": runner_id,
        "architecture": platform.machine(),
        "kernel_release": platform.release(),
        "cpu_model": cpu_model(),
        "logical_cpus": os.cpu_count(),
        "memory_total_bytes": memory_total_bytes(),
        "filesystem_type": filesystem_type(work_dir),
        "server_cpus": list(server_cpus),
        "client_cpus": list(client_cpus),
        "cpu_governors": cpu_governors(all_cpus),
        "curl": curl_version,
        "h2load": h2load_version,
        "rustc": read_first_line(["rustc", "--version"]),
        "cargo": read_first_line(["cargo", "--version"]),
        "libc": list(platform.libc_ver()),
        "binary_contract": binary_contract,
    }
    fingerprint = hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        **stable,
        "environment_fingerprint": fingerprint,
        "platform": platform.platform(),
        "load_average": list(os.getloadavg()),
        "binaries": {
            profile: {
                "path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "version": read_first_line([str(path), "--version"]),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for profile, path in sorted(binaries.items())
        },
    }


def validate_prerequisites(args: argparse.Namespace, binaries: dict[str, Path]) -> None:
    if sys.platform != "linux" or not Path("/proc/self/status").is_file():
        raise BenchmarkError("the performance harness requires Linux with a mounted /proc")
    for executable in ["curl", "taskset", "stat"]:
        if shutil.which(executable) is None:
            raise BenchmarkError(f"required executable is missing: {executable}")
    for profile, binary in binaries.items():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise BenchmarkError(f"{profile} binary is not executable: {binary}")
    curl_features = command_output(["curl", "--version"])
    if "HTTP2" not in curl_features:
        raise BenchmarkError("curl must be built with HTTP/2 support")
    if not args.skip_load:
        if shutil.which("h2load") is None:
            raise BenchmarkError("h2load is required unless --skip-load is used")
        help_text = command_output(["h2load", "--help"])
        for option in ["--h1", "--alpn-list", "--max-concurrent-streams"]:
            if option not in help_text:
                raise BenchmarkError(f"h2load does not support required option {option}")

    online = set(range(os.cpu_count() or 0))
    selected_server = set(args.server_cpus)
    selected_client = set(args.client_cpus)
    if not selected_server <= online or not selected_client <= online:
        raise BenchmarkError(
            f"selected CPUs are not online; online=0-{max(online, default=-1)}, "
            f"server={args.server_cpus}, client={args.client_cpus}"
        )
    if selected_server & selected_client:
        raise BenchmarkError("server and client CPU sets must not overlap")
    if args.strict_environment:
        if args.runner_id == "local":
            raise BenchmarkError("--strict-environment requires an explicit stable --runner-id")
        if not selected_server or not selected_client:
            raise BenchmarkError("strict runs require non-empty, disjoint server/client CPU sets")
        if args.binary_contract == "unspecified":
            raise BenchmarkError("strict runs require an explicit --binary-contract")
        if set(binaries) != {"debug", "release"}:
            raise BenchmarkError(
                "strict runs require exactly debug and release binary profiles"
            )
        governors = cpu_governors(sorted(selected_server | selected_client))
        invalid = {cpu: governor for cpu, governor in governors.items() if governor != "performance"}
        if invalid:
            raise BenchmarkError(
                "strict runs require the performance CPU governor on every selected CPU: "
                f"{invalid}"
            )


def parse_binaries(values: Sequence[str]) -> dict[str, Path]:
    binaries: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise BenchmarkError(f"--binary must be PROFILE=PATH, got {value!r}")
        profile, raw_path = value.split("=", 1)
        if not profile or not re.fullmatch(r"[a-z0-9_-]+", profile):
            raise BenchmarkError(f"invalid profile name: {profile!r}")
        if profile in binaries:
            raise BenchmarkError(f"duplicate binary profile: {profile}")
        binaries[profile] = Path(raw_path).resolve()
    if not binaries:
        raise BenchmarkError("at least one --binary PROFILE=PATH is required")
    return binaries


def run_suite(args: argparse.Namespace) -> dict[str, Any]:
    binaries = parse_binaries(args.binary)
    validate_prerequisites(args, binaries)

    owned_temporary = args.work_dir is None
    work_dir = (
        Path(tempfile.mkdtemp(prefix="ram-performance-"))
        if owned_temporary
        else Path(args.work_dir).resolve()
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        environment = environment_metadata(
            runner_id=args.runner_id,
            work_dir=work_dir,
            server_cpus=args.server_cpus,
            client_cpus=args.client_cpus,
            binaries=binaries,
            include_h2load=not args.skip_load,
            binary_contract=args.binary_contract,
        )
        fixture = create_fixture(
            work_dir,
            large_bytes=args.large_file_bytes,
            load_bytes=args.load_object_bytes,
            directory_entries=args.directory_entries,
            source_cert=Path(args.tls_cert).resolve(),
            source_key=Path(args.tls_key).resolve(),
        )
        password = secrets.token_urlsafe(24)
        profiles: dict[str, Any] = {}
        regression_metrics: dict[str, float] = {}

        for profile, binary in sorted(binaries.items()):
            profile_results: dict[str, Any] = {"endpoint_scenarios": {}, "load_scenarios": {}}
            endpoint_stream_limit = max(args.h2_streams)
            with RamServer(
                binary=binary,
                profile=profile,
                fixture=fixture,
                work_dir=work_dir,
                password=password,
                h2_streams=endpoint_stream_limit,
                max_expensive_tasks=args.max_expensive_tasks,
                server_cpus=args.server_cpus,
            ) as server:
                endpoint_specs = {
                    "large_get": ("/payload.bin", "GET", None),
                    "large_put": (f"/uploaded-{profile}.bin", "PUT", fixture.payload),
                    "directory_list": ("/directory/?json", "GET", None),
                    "directory_search": ("/directory/?q=ram-no-match&json", "GET", None),
                    "directory_zip": ("/directory/?zip", "GET", None),
                    "large_hash": ("/payload.bin?hash", "GET", None),
                }
                for scenario, (path, method, upload) in endpoint_specs.items():
                    measured = run_curl_scenario(
                        server,
                        path=path,
                        method=method,
                        upload=upload,
                        warmups=args.warmups,
                        iterations=args.iterations,
                        client_cpus=args.client_cpus,
                    )
                    if scenario == "large_hash":
                        measured["input_bytes"] = fixture.large_bytes
                    if scenario == "directory_zip":
                        measured["input_bytes"] = fixture.directory_input_bytes
                    profile_results["endpoint_scenarios"][scenario] = measured
                    add_curl_regression_metrics(regression_metrics, profile, scenario, measured)

                if not args.skip_load:
                    http1 = load_scenario(
                        server,
                        protocol="http1",
                        streams=1,
                        requests=args.load_requests,
                        clients=args.http1_clients,
                        fixture=fixture,
                        client_cpus=args.client_cpus,
                    )
                    profile_results["load_scenarios"]["http1"] = http1
                    add_load_regression_metrics(regression_metrics, profile, "load_http1", http1)

            if not args.skip_load:
                for streams in args.h2_streams:
                    with RamServer(
                        binary=binary,
                        profile=profile,
                        fixture=fixture,
                        work_dir=work_dir,
                        password=password,
                        h2_streams=streams,
                        max_expensive_tasks=args.max_expensive_tasks,
                        server_cpus=args.server_cpus,
                    ) as server:
                        h2_result = load_scenario(
                            server,
                            protocol="h2",
                            streams=streams,
                            requests=args.load_requests,
                            clients=args.h2_clients,
                            fixture=fixture,
                            client_cpus=args.client_cpus,
                        )
                    name = f"h2_streams_{streams}"
                    profile_results["load_scenarios"][name] = h2_result
                    add_load_regression_metrics(
                        regression_metrics, profile, f"load_{name}", h2_result
                    )
            profiles[profile] = profile_results

        result = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "kind": "ram-performance-result",
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_commit": git_commit(),
            "preset": args.preset,
            "runner_id": args.runner_id,
            "environment": environment,
            "configuration": {
                "strict_environment": args.strict_environment,
                "binary_contract": args.binary_contract,
                "large_file_bytes": fixture.large_bytes,
                "load_object_bytes": fixture.load_bytes,
                "directory_entries": fixture.directory_entries,
                "directory_input_bytes": fixture.directory_input_bytes,
                "iterations": args.iterations,
                "warmups": args.warmups,
                "load_requests": args.load_requests,
                "http1_clients": args.http1_clients,
                "h2_clients": args.h2_clients,
                "h2_stream_limits": args.h2_streams,
                "max_expensive_tasks": args.max_expensive_tasks,
                "max_blocking_threads": 32,
                "request_admission_floor": 256,
                "fixture_creation_seconds": fixture.creation_seconds,
                "cache_model": "warm after explicit scenario warmups; no host-wide cache mutation",
                "blocking_queue_metric": (
                    "observable excess mean hash latency under fixed offered concurrency; "
                    "not an internal Tokio queue length"
                ),
            },
            "profiles": profiles,
            "regression_metrics": dict(sorted(regression_metrics.items())),
            "profile_comparison": build_profile_comparison(regression_metrics),
        }
        return result
    finally:
        if owned_temporary and not args.keep_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)


def self_test() -> None:
    sample = """
finished in 1.25s, 80.00 req/s, 12.50MB/s
requests: 100 total, 100 started, 100 done, 100 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 100 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 16.00MB (16777216) total, 10.00KB (10240) headers, 15.99MB (16766976) data
                     min         max         mean         sd        +/- sd
time for request:  1.00ms     50.00ms     12.00ms      3.00ms    90.00%
"""
    parsed = parse_h2load_output(sample)
    assert parsed["requests_succeeded"] == 100
    assert parsed["wire_bytes_per_second"] == 12.5 * MIB
    assert parsed["request_time_mean_seconds"] == 0.012
    assert parse_size("1MiB") == MIB
    assert parse_cpu_list("1-3,5") == [1, 2, 3, 5]
    assert percentile([1.0, 2.0, 3.0], 0.95) == 3.0
    print("benchmark harness self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        action="append",
        default=[],
        metavar="PROFILE=PATH",
        help="Ram binary to measure; repeat for debug/release",
    )
    parser.add_argument("--output", type=Path, help="machine-readable JSON result path")
    parser.add_argument("--work-dir", type=Path, help="dedicated local-filesystem work directory")
    parser.add_argument("--keep-work-dir", action="store_true")
    parser.add_argument("--preset", choices=["full", "smoke"], default="full")
    parser.add_argument("--large-file-bytes", type=parse_size)
    parser.add_argument("--load-object-bytes", type=parse_size)
    parser.add_argument("--directory-entries", type=parse_positive_int)
    parser.add_argument("--iterations", type=parse_positive_int)
    parser.add_argument("--warmups", type=parse_nonnegative_int)
    parser.add_argument("--load-requests", type=parse_positive_int)
    parser.add_argument("--http1-clients", type=parse_positive_int)
    parser.add_argument("--h2-clients", type=parse_positive_int)
    parser.add_argument(
        "--h2-streams",
        type=lambda value: [parse_positive_int(item) for item in value.split(",")],
    )
    parser.add_argument("--max-expensive-tasks", type=parse_positive_int, default=2)
    parser.add_argument("--skip-load", action="store_true", help="skip h2load HTTP/1/H2 scenarios")
    parser.add_argument("--runner-id", default="local")
    parser.add_argument(
        "--binary-contract",
        default="unspecified",
        help="reviewed build command/features shared by every supplied profile",
    )
    parser.add_argument("--server-cpus", type=parse_cpu_list, default=[])
    parser.add_argument("--client-cpus", type=parse_cpu_list, default=[])
    parser.add_argument("--strict-environment", action="store_true")
    parser.add_argument("--tls-cert", type=Path, default=REPOSITORY_ROOT / "tests/data/cert.pem")
    parser.add_argument("--tls-key", type=Path, default=REPOSITORY_ROOT / "tests/data/key_pkcs8.pem")
    parser.add_argument("--self-test", action="store_true")
    return parser


def apply_preset(args: argparse.Namespace) -> None:
    defaults = {
        "full": {
            "large_file_bytes": 256 * MIB,
            "load_object_bytes": MIB,
            "directory_entries": 10_000,
            "iterations": 3,
            "warmups": 1,
            "load_requests": 128,
            "http1_clients": 8,
            "h2_clients": 4,
            "h2_streams": [1, 8, 32],
        },
        "smoke": {
            "large_file_bytes": MIB,
            "load_object_bytes": 64 * 1024,
            "directory_entries": 64,
            "iterations": 1,
            "warmups": 0,
            "load_requests": 8,
            "http1_clients": 2,
            "h2_clients": 2,
            "h2_streams": [1],
        },
    }[args.preset]
    for name, value in defaults.items():
        if getattr(args, name) is None:
            setattr(args, name, value)
    args.h2_streams = sorted(set(args.h2_streams))


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.binary or args.output is None:
        parser.error("--binary and --output are required unless --self-test is used")
    apply_preset(args)
    try:
        result = run_suite(args)
        atomic_json_write(args.output.resolve(), result)
    except BenchmarkError as error:
        print(f"performance benchmark failed: {error}", file=sys.stderr)
        return 2
    print(f"performance result written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
