"""Network failures must be reported and skipped, never raised or hung."""
import os
import socket
import subprocess
import sys
import threading
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import git_dumper


class ExplodingWorker(git_dumper.Worker):
    def init(self, record_path):
        self.record_path = record_path

    def do_task(self, task, record_path):
        with open(record_path, "a", encoding="utf-8") as handle:
            handle.write("%s\n" % task)
            handle.flush()
        if task == "bad":
            raise RuntimeError("boom")
        if task == "exit":
            sys.exit(3)
        if task == "parent":
            return ["child"]
        return []


class HangWorker(git_dumper.Worker):
    def init(self):
        return None

    def do_task(self, task):
        time.sleep(120)
        return []


def _serve(handler):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(64)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    return port, stop, sock


def _stop(stop, sock):
    stop.set()
    try:
        sock.close()
    except OSError:
        pass


def _http_response(conn, status, body, extra_headers=b"", stall_after=None):
    try:
        conn.settimeout(2)
        try:
            conn.recv(65536)
        except socket.timeout:
            pass
        head = (
            "HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n"
            % (status, len(body), extra_headers.decode() if isinstance(extra_headers, bytes) else extra_headers)
        ).encode()
        conn.sendall(head + body[:stall_after] if stall_after is not None else head + body)
        if stall_after is not None:
            time.sleep(30)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def test_error_messages_name_the_failure():
    assert "read timeout" in git_dumper.format_network_error(
        requests.exceptions.ReadTimeout("Read timed out")
    )
    assert "connect timeout" in git_dumper.format_network_error(
        requests.exceptions.ConnectTimeout("connect timeout")
    )
    assert "SSL error" in git_dumper.format_network_error(
        requests.exceptions.SSLError("WRONG_VERSION_NUMBER")
    )
    assert "DNS lookup failed" in git_dumper.format_network_error(
        socket.gaierror("Name or service not known")
    )
    assert "connection refused" in git_dumper.format_network_error(
        ConnectionRefusedError(111, "Connection refused")
    )


def test_partial_download_is_removed(tmp_path):
    class Response(object):
        def iter_content(self, chunk_size):
            yield b"hello"
            raise requests.exceptions.ReadTimeout("Read timed out")

        def close(self):
            return None

    target = tmp_path / "object"
    assert git_dumper.write_response_to_file(Response(), str(target)) is False
    assert not target.exists()
    assert not (tmp_path / "object.part").exists()


def test_unexpected_git_object_does_not_exit():
    assert git_dumper.get_referenced_sha1(object()) == []


def test_sanitize_missing_file_does_not_raise(tmp_path):
    git_dumper.sanitize_file(str(tmp_path / "missing"))


def test_worker_exceptions_do_not_stop_the_pool(tmp_path):
    record = tmp_path / "seen.txt"
    git_dumper.process_tasks(
        ["bad", "exit", "parent"],
        ExplodingWorker,
        2,
        args=(str(record),),
        timeout=1,
        retry=0,
    )
    seen = set(record.read_text(encoding="utf-8").split())
    assert seen == {"bad", "exit", "parent", "child"}


def test_stuck_worker_is_abandoned():
    started = time.monotonic()
    git_dumper.process_tasks(["hang"], HangWorker, 2, args=(), timeout=1, retry=0)
    elapsed = time.monotonic() - started
    budget = git_dumper.network_budget(1, 0)
    assert elapsed < budget + 20
    assert elapsed > 2


def test_refused_and_ssl_targets_return_instead_of_raising(tmp_path):
    port, stop, sock = _serve(lambda conn: _http_response(conn, "200 OK", b"hello\n"))
    refused_dir = tmp_path / "refused"
    ssl_dir = tmp_path / "ssl"
    refused_dir.mkdir()
    ssl_dir.mkdir()
    try:
        refused = git_dumper.fetch_git(
            "http://127.0.0.1:1/.git",
            str(refused_dir),
            2, 1, 1, {"User-Agent": "test"},
        )
        started = time.monotonic()
        ssl_code = git_dumper.fetch_git(
            "https://127.0.0.1:%d/.git" % port,
            str(ssl_dir),
            2, 1, 1, {"User-Agent": "test"},
        )
        elapsed = time.monotonic() - started
    finally:
        _stop(stop, sock)

    assert refused == 1
    assert ssl_code == 1
    assert elapsed < 20


def test_read_timeout_on_one_file_does_not_hang(tmp_path):
    def handler(conn):
        _http_response(conn, "200 OK", b"x" * 100000, stall_after=50)

    port, stop, sock = _serve(handler)
    try:
        started = time.monotonic()
        git_dumper.process_tasks(
            [".git/config"],
            git_dumper.DownloadWorker,
            2,
            args=(
                "http://127.0.0.1:%d" % port,
                str(tmp_path),
                1,
                1,
                {"User-Agent": "test"},
                None,
                None,
                "GET",
                False,
            ),
            timeout=1,
            retry=1,
        )
        elapsed = time.monotonic() - started
    finally:
        _stop(stop, sock)

    assert elapsed < 20
    assert not (tmp_path / ".git" / "config").exists()
    assert not list(tmp_path.rglob("*.part"))


def test_hanging_server_fails_the_target(tmp_path):
    def handler(conn):
        try:
            time.sleep(30)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    port, stop, sock = _serve(handler)
    directory = tmp_path / "out"
    directory.mkdir()
    try:
        started = time.monotonic()
        code = git_dumper.fetch_git(
            "http://127.0.0.1:%d/.git" % port,
            str(directory),
            2, 1, 1, {"User-Agent": "test"},
        )
        elapsed = time.monotonic() - started
    finally:
        _stop(stop, sock)

    assert code == 1
    assert elapsed < 20


def test_reachable_head_continues_when_other_files_are_missing(tmp_path):
    def handler(conn):
        try:
            conn.settimeout(2)
            try:
                data = conn.recv(65536)
            except socket.timeout:
                data = b""
            request = data.decode("latin1", "replace")
            path = request.split(" ", 2)[1] if " " in request else ""
            if path.rstrip("/") == "/.git/HEAD":
                body = b"ref: refs/heads/main\n"
                status = "200 OK"
            else:
                body = b"missing"
                status = "404 Not Found"
            raw = (
                "HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                % (status, len(body))
            ).encode() + body
            conn.sendall(raw)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    port, stop, sock = _serve(handler)
    directory = tmp_path / "repo"
    directory.mkdir()
    cwd = os.getcwd()
    try:
        code = git_dumper.fetch_git(
            "http://127.0.0.1:%d/.git" % port,
            str(directory),
            4, 1, 1, {"User-Agent": "test"},
        )
    finally:
        _stop(stop, sock)
    assert code == 0
    assert os.getcwd() == cwd
    assert (directory / ".git" / "HEAD").is_file()


def test_repeated_timeouts_skip_the_rest_of_the_phase(tmp_path, capfd):
    """A dead host must not time out every queued file."""
    state = {"n": 0}
    lock = threading.Lock()

    def handler(conn):
        with lock:
            state["n"] += 1
        try:
            time.sleep(30)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    port, stop, sock = _serve(handler)
    files = [".git/objects/%02x/obj" % i for i in range(30)]
    try:
        started = time.monotonic()
        git_dumper.process_tasks(
            files,
            git_dumper.DownloadWorker,
            2,
            args=(
                "http://127.0.0.1:%d" % port,
                str(tmp_path),
                1,
                1,
                {"User-Agent": "test"},
                None,
                None,
                "GET",
                False,
            ),
            timeout=1,
            retry=1,
        )
        elapsed = time.monotonic() - started
    finally:
        _stop(stop, sock)

    _out, err = capfd.readouterr()
    # 30 files / 2 workers is several times longer than eight failures.
    assert elapsed < 22
    assert "Too many network failures" in err
    assert state["n"] < 40


def test_missing_files_do_not_trip_the_network_breaker(tmp_path, capfd):
    """A live host that answers 404 must be walked, not abandoned."""
    state = {"n": 0}
    lock = threading.Lock()

    def handler(conn):
        with lock:
            state["n"] += 1
        _http_response(conn, "404 Not Found", b"missing")

    port, stop, sock = _serve(handler)
    files = [".git/objects/%02x/obj" % i for i in range(12)]
    try:
        git_dumper.process_tasks(
            files,
            git_dumper.DownloadWorker,
            2,
            args=(
                "http://127.0.0.1:%d" % port,
                str(tmp_path),
                1,
                1,
                {"User-Agent": "test"},
                None,
                None,
                "GET",
                False,
            ),
            timeout=1,
            retry=1,
        )
    finally:
        _stop(stop, sock)

    _out, err = capfd.readouterr()
    assert "Too many network failures" not in err
    assert state["n"] >= len(files)


def test_batch_cli_prints_summary_without_traceback(tmp_path):
    urls = tmp_path / "urls.txt"
    urls.write_text(
        "\n".join([
            "http://127.0.0.1:1/.git",
            "https://127.0.0.1:1/.git",
            "not-a-url",
            "",
        ]),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    proc = subprocess.run(
        [
            sys.executable,
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "git_dumper.py"),
            "-l", str(urls),
            str(out),
            "-t", "1",
            "-r", "1",
            "-j", "2",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    combined = proc.stdout + proc.stderr
    assert "Traceback" not in combined
    assert "BATCH SUMMARY" in proc.stdout
    assert proc.returncode == 1
