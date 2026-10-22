#!/usr/bin/env python3
import argparse
import binascii
import errno
import glob
import http.client
import multiprocessing
import os
import os.path
import queue
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import urllib3
import bs4
import dulwich.index
import dulwich.objects
import dulwich.object_format
import dulwich.pack
import requests
import socks
from requests_pkcs12 import Pkcs12Adapter


# Largest HTML directory listing kept in memory. Bigger bodies are skipped.
_MAX_TEXT_BODY = 8 * 1024 * 1024


def printf(fmt, *args, file=sys.stdout):
    """Write one log line. Logging failures must not abort a long run."""
    try:
        if args:
            fmt = fmt % args
    except Exception:
        try:
            fmt = "%s %s\n" % (fmt, " ".join(str(arg) for arg in args))
        except Exception:
            fmt = str(fmt)
    try:
        file.write(fmt)
        file.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass


def _short(text, limit=180):
    text = " ".join(str(text).split())
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _exception_chain(exc):
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)


def _classify_error(exc):
    """Return a short category name for an exception, or None."""
    if exc is None:
        return None

    number = getattr(exc, "errno", None)
    if isinstance(number, int):
        kind = {
            errno.ETIMEDOUT: "timeout",
            errno.ECONNRESET: "connection reset",
            errno.ECONNABORTED: "connection reset",
            errno.ECONNREFUSED: "connection refused",
            errno.EPIPE: "connection reset",
            errno.ENETUNREACH: "network unreachable",
            errno.EHOSTUNREACH: "host unreachable",
            errno.ENETDOWN: "network unreachable",
            errno.EHOSTDOWN: "host unreachable",
        }.get(number)
        if kind:
            return kind

    text = str(exc).lower()
    type_name = type(exc).__name__.lower()

    if (
        isinstance(exc, (requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError))
        or "read timed out" in text
    ):
        return "read timeout"
    if (
        isinstance(exc, (requests.exceptions.ConnectTimeout, urllib3.exceptions.ConnectTimeoutError))
        or "connect timeout" in text
    ):
        return "connect timeout"
    if isinstance(exc, (requests.exceptions.Timeout, socket.timeout, TimeoutError)) or "timed out" in text:
        return "timeout"
    if isinstance(exc, (requests.exceptions.SSLError, ssl.SSLError)) or "ssl" in type_name or "ssl" in text or "tls" in text:
        return "SSL error"
    if (
        isinstance(exc, socket.gaierror)
        or "name or service not known" in text
        or "name resolution" in text
        or "getaddrinfo" in text
        or "nodename nor servname" in text
        or "temporary failure in name resolution" in text
    ):
        return "DNS lookup failed"
    if isinstance(exc, requests.exceptions.ProxyError) or "proxy" in type_name:
        return "proxy error"
    if isinstance(exc, requests.exceptions.TooManyRedirects) or "too many redirect" in text:
        return "too many redirects"
    if isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema)):
        return "invalid URL"
    if "connection refused" in text:
        return "connection refused"
    if "connection reset" in text or "connection aborted" in text or "broken pipe" in text:
        return "connection reset"
    if (
        isinstance(exc, (http.client.HTTPException, urllib3.exceptions.ProtocolError))
        or "incompleteread" in text
        or "chunked" in text
        or "connection broken" in text
        or "remote end closed" in text
        or "remotedisconnected" in text
    ):
        return "connection closed early"
    if (
        isinstance(exc, (requests.exceptions.RetryError, urllib3.exceptions.MaxRetryError))
        or "max retries exceeded" in text
    ):
        return "retry limit reached"
    if isinstance(exc, requests.exceptions.RequestException):
        return "request failed"
    return None


def format_network_error(exc):
    """One-line description of a failure. Safe to print during a long batch."""
    if exc is None:
        return "unknown error"

    kinds = []
    for item in _exception_chain(exc):
        kind = _classify_error(item)
        if kind and kind not in kinds:
            kinds.append(kind)

    priority = (
        "read timeout",
        "connect timeout",
        "timeout",
        "SSL error",
        "DNS lookup failed",
        "connection refused",
        "connection reset",
        "connection closed early",
        "host unreachable",
        "network unreachable",
        "proxy error",
        "too many redirects",
        "invalid URL",
        "retry limit reached",
        "request failed",
    )
    detail = _short(exc)
    for kind in priority:
        if kind in kinds:
            if not detail or detail.lower() == kind.lower():
                return kind
            return "%s: %s" % (kind, detail)
    if detail:
        return "%s: %s" % (type(exc).__name__, detail)
    return type(exc).__name__


def log_failure(prefix, exc):
    printf("%s%s\n", prefix, format_network_error(exc), file=sys.stderr)
    if os.environ.get("GIT_DUMPER_DEBUG"):
        try:
            traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
        except Exception:
            pass


def network_budget(timeout, retry):
    """Seconds one HTTP call may take, including connect, read, and retries.

    Socket timeouts do not cover every hang (a stuck DNS lookup is the usual
    case). Callers use this same bound as a hard deadline and abandon the call.
    """
    try:
        timeout = max(float(timeout), 0.1)
    except (TypeError, ValueError):
        timeout = 3.0
    try:
        retry = max(int(retry), 0)
    except (TypeError, ValueError):
        retry = 0

    attempts = retry + 1
    backoff = 0.0
    for attempt in range(retry):
        backoff += min(2.0, 0.2 * (2 ** attempt))
    # Each attempt can spend a full connect timeout and a full read timeout.
    return timeout * 2.0 * attempts + backoff + 5.0


def silence_tls_warnings():
    try:
        urllib3.disable_warnings()
    except Exception:
        pass


def build_retry(retry, method="GET"):
    """Bounded retries. Status codes and Retry-After cannot stall the run."""
    try:
        retry = max(int(retry), 0)
    except (TypeError, ValueError):
        retry = 0

    allowed = {"DELETE", "GET", "HEAD", "OPTIONS", "PUT", "TRACE"}
    if method:
        allowed.add(str(method).upper())

    return urllib3.util.retry.Retry(
        total=retry,
        connect=retry,
        read=retry,
        redirect=0,
        status=0,
        backoff_factor=0.2,
        backoff_max=2,
        raise_on_redirect=False,
        raise_on_status=False,
        respect_retry_after_header=False,
        allowed_methods=frozenset(allowed),
    )


def open_session(http_headers, retry, method="GET", client_cert_p12=None, client_cert_p12_password=None, mount_url=None):
    """Return a Session whose connects, reads, and retries are all bounded."""
    silence_tls_warnings()
    session = requests.Session()
    session.verify = False
    session.max_redirects = 5
    session.headers = http_headers
    retry_conf = build_retry(retry, method)

    if client_cert_p12:
        adapter = Pkcs12Adapter(
            pkcs12_filename=client_cert_p12,
            pkcs12_password=client_cert_p12_password,
            max_retries=retry_conf,
        )
        session.mount(mount_url or "https://", adapter)
    else:
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_conf,
            pool_connections=2,
            pool_maxsize=2,
            pool_block=False,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


def close_session_quietly(session):
    if session is None:
        return

    def _close():
        try:
            session.close()
        except Exception:
            pass

    thread = threading.Thread(target=_close, daemon=True)
    thread.start()
    thread.join(2.0)


def close_quietly(response):
    if response is None:
        return

    def _close():
        try:
            response.close()
        except Exception:
            pass

    closer = getattr(response, "close", None)
    if closer is None:
        return
    thread = threading.Thread(target=_close, daemon=True)
    thread.start()
    thread.join(2.0)


def remove_quietly(path):
    if not path:
        return
    try:
        os.remove(path)
    except OSError:
        pass


def close_queue(q):
    if q is None:
        return
    try:
        q.close()
    except Exception:
        pass
    try:
        q.cancel_join_thread()
    except Exception:
        pass


def terminate_process(proc):
    if proc is None:
        return
    try:
        alive = proc.is_alive()
    except Exception:
        return
    if not alive:
        try:
            proc.join(timeout=0.2)
        except Exception:
            pass
        return
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.join(timeout=2)
    except Exception:
        pass
    try:
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=1)
    except Exception:
        pass


def ensure_mp_start_method():
    """Start workers without inheriting this process's SSL locks.

    Forking after requests/urllib3 have been used can deadlock a child inside
    the TLS stack. forkserver and spawn start from a clean interpreter.
    """
    try:
        current = multiprocessing.get_start_method(allow_none=True)
    except Exception:
        current = None
    if current in ("forkserver", "spawn"):
        return
    for method in ("forkserver", "spawn"):
        try:
            multiprocessing.set_start_method(method, force=False)
            return
        except (RuntimeError, ValueError):
            continue


class CaseInsensitiveHeaders(object):
    def __init__(self, items):
        self._items = []
        for key, value in items or []:
            self._items.append((str(key), str(value)))

    def __contains__(self, key):
        wanted = str(key).lower()
        return any(name.lower() == wanted for name, _value in self._items)

    def __getitem__(self, key):
        wanted = str(key).lower()
        for name, value in self._items:
            if name.lower() == wanted:
                return value
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def items(self):
        return list(self._items)


class DetachedResponse(object):
    """Response data copied out of a short-lived helper process."""

    def __init__(self, status, headers, body):
        self.status_code = status
        self.headers = CaseInsensitiveHeaders(headers)
        self.content = body or b""
        try:
            self.text = self.content.decode("utf-8", "replace")
        except Exception:
            self.text = ""

    def close(self):
        return None

    def iter_content(self, chunk_size=65536):
        step = chunk_size or 65536
        body = self.content
        for index in range(0, len(body), step):
            yield body[index:index + step]


def _bounded_http_request(result_queue, body_path, method, url, timeout, retry, headers, read_body, max_body, allow_redirects, client_cert_p12, client_cert_p12_password, mount_url):
    """Run one HTTP request in a process the parent is allowed to kill."""
    session = None
    try:
        session = open_session(
            headers,
            retry,
            method=method,
            client_cert_p12=client_cert_p12,
            client_cert_p12_password=client_cert_p12_password,
            mount_url=mount_url,
        )
        response = session.request(
            method,
            url,
            allow_redirects=allow_redirects,
            stream=True,
            timeout=(timeout, timeout),
        )
        truncated = False
        if read_body:
            written = 0
            with open(body_path, "wb") as handle:
                for chunk in response.iter_content(65536):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > max_body:
                        truncated = True
                        break
                    handle.write(chunk)
        header_items = []
        try:
            pairs = response.headers.items()
        except Exception:
            pairs = []
        for index, (key, value) in enumerate(pairs):
            if index >= 100:
                break
            header_items.append((str(key)[:200], str(value)[:4096]))
        try:
            status = int(response.status_code)
        except Exception:
            status = 0
        result_queue.put({
            "ok": True,
            "status": status,
            "headers": header_items,
            "truncated": truncated,
        })
        close_quietly(response)
    except BaseException as exc:
        try:
            result_queue.put({"ok": False, "error": format_network_error(exc)})
        except Exception:
            pass
    finally:
        close_session_quietly(session)


class HttpClient(object):
    """HTTP calls for the parent process.

    Each call runs in a helper process. If the helper is still going after
    network_budget(), it is killed. A stuck resolver cannot wedge the batch.
    """

    def __init__(self, http_headers, retry, timeout, method="GET", client_cert_p12=None, client_cert_p12_password=None, mount_url=None):
        self.http_headers = http_headers
        self.retry = retry
        self.timeout = timeout
        self.method = method
        self.client_cert_p12 = client_cert_p12
        self.client_cert_p12_password = client_cert_p12_password
        self.mount_url = mount_url

    def close(self):
        return None

    def request(self, method, url, stream=False, allow_redirects=False):
        ensure_mp_start_method()
        result_queue = multiprocessing.Queue()
        body_fd, body_path = tempfile.mkstemp(prefix="git-dumper-")
        os.close(body_fd)
        proc = multiprocessing.Process(
            target=_bounded_http_request,
            name="git-dumper-http",
            args=(
                result_queue,
                body_path,
                method,
                url,
                self.timeout,
                self.retry,
                self.http_headers,
                not stream,
                _MAX_TEXT_BODY,
                allow_redirects,
                self.client_cert_p12,
                self.client_cert_p12_password,
                self.mount_url or url,
            ),
        )
        proc.daemon = True
        try:
            try:
                proc.start()
            except Exception as exc:
                printf("[-] %s %s failed: %s\n", method, url, format_network_error(exc), file=sys.stderr)
                return None

            try:
                proc.join(network_budget(self.timeout, self.retry))
            except KeyboardInterrupt:
                terminate_process(proc)
                raise

            timed_out = False
            try:
                timed_out = proc.is_alive()
            except Exception:
                timed_out = False
            if timed_out:
                terminate_process(proc)

            try:
                # Give the child's queue feeder a moment to flush after exit.
                meta = result_queue.get(timeout=1)
            except (queue.Empty, EOFError, OSError):
                meta = None

            if not meta:
                reason = "stalled request abandoned" if timed_out else "no response"
                printf("[-] %s %s failed: %s\n", method, url, reason, file=sys.stderr)
                return None
            if not meta.get("ok"):
                printf(
                    "[-] %s %s failed: %s\n",
                    method,
                    url,
                    meta.get("error") or "request failed",
                    file=sys.stderr,
                )
                return None
            if meta.get("truncated"):
                printf("[-] %s %s failed: response too large\n", method, url, file=sys.stderr)
                return None

            body = b""
            if not stream:
                try:
                    with open(body_path, "rb") as handle:
                        body = handle.read()
                except OSError as exc:
                    printf("[-] %s %s failed: %s\n", method, url, format_network_error(exc), file=sys.stderr)
                    return None
            return DetachedResponse(meta.get("status", 0), meta.get("headers"), body)
        finally:
            terminate_process(proc)
            remove_quietly(body_path)
            close_queue(result_queue)


def content_length(response):
    if response is None:
        return None
    try:
        if response.status_code != 200:
            return None
        if "Content-Length" not in response.headers:
            return None
        return int(response.headers["Content-Length"])
    except (TypeError, ValueError, KeyError, AttributeError):
        return None


def response_text(response):
    if response is None:
        return ""
    try:
        return response.text or ""
    except Exception:
        try:
            return response.content.decode("utf-8", "replace")
        except Exception:
            return ""


def read_text_file(path):
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        printf("[-] Reading %s failed: %s\n", path, format_network_error(exc), file=sys.stderr)
        return ""


def write_response_to_file(response, abspath, touch=None):
    """Stream a response to disk. A partial file is never left behind."""
    if response is None:
        return False

    tmp_path = abspath + ".part"
    try:
        create_intermediate_dirs(abspath)
        with open(tmp_path, "wb") as handle:
            for chunk in response.iter_content(65536):
                if touch is not None:
                    touch()
                if chunk:
                    handle.write(chunk)
        os.replace(tmp_path, abspath)
        return True
    except KeyboardInterrupt:
        remove_quietly(tmp_path)
        raise
    except BaseException as exc:
        remove_quietly(tmp_path)
        printf("[-] Saving %s failed: %s\n", abspath, format_network_error(exc), file=sys.stderr)
        return False
    finally:
        close_quietly(response)


def read_response_bytes(response, touch=None, limit=_MAX_TEXT_BODY):
    if response is None:
        return None

    chunks = []
    total = 0
    try:
        for chunk in response.iter_content(65536):
            if touch is not None:
                touch()
            if not chunk:
                continue
            total += len(chunk)
            if total > limit:
                printf("[-] Response exceeded %d bytes; skipping\n", limit, file=sys.stderr)
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        printf("[-] Reading response failed: %s\n", format_network_error(exc), file=sys.stderr)
        return None
    finally:
        close_quietly(response)


def is_html(response):
    """ Return True if the response is a HTML webpage """
    try:
        return (
            "Content-Type" in response.headers
            and "text/html" in response.headers["Content-Type"]
        )
    except Exception:
        return False


def is_safe_path(path):
    """ Prevent directory traversal attacks """
    if path.startswith("/"):
        return False

    safe_path = os.path.expanduser("~")
    return (
        os.path.commonpath(
            (os.path.realpath(os.path.join(safe_path, path)), safe_path)
        )
        == safe_path
    )


def get_indexed_files_from_text(text):
    """ Return all the files in a directory index webpage """
    try:
        html = bs4.BeautifulSoup(text or "", "html.parser")
    except Exception as exc:
        printf("[-] Unable to parse directory listing: %s\n", format_network_error(exc), file=sys.stderr)
        return []

    files = []
    try:
        links = html.find_all("a")
    except Exception as exc:
        printf("[-] Unable to parse directory listing: %s\n", format_network_error(exc), file=sys.stderr)
        return []

    for link in links:
        try:
            href = link.get("href")
        except Exception:
            continue
        url = urllib.parse.urlparse(href or "")

        if (
            url.path
            and is_safe_path(url.path)
            and not url.scheme
            and not url.netloc
        ):
            files.append(url.path)

    return files


def get_indexed_files(response):
    """ Return all the files in the directory index webpage """
    return get_indexed_files_from_text(response_text(response))


def verify_response(response, any_status=False):
    if not any_status and response.status_code != 200:
        return (
            False,
            "[-] %s/%s responded with status code {code}\n".format(
                code=response.status_code
            ),
        )
    elif (
        "Content-Length" in response.headers
        and response.headers["Content-Length"] == 0
    ):
        return False, "[-] %s/%s responded with a zero-length body\n"
    elif (
        "Content-Type" in response.headers
        and "text/html" in response.headers["Content-Type"]
    ):
        return False, "[-] %s/%s responded with HTML\n"
    else:
        return True, True


def create_intermediate_dirs(path):
    """ Create intermediate directories, if necessary """

    dirname, basename = os.path.split(path)

    if dirname and not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except FileExistsError:
            pass  # race condition


def get_referenced_sha1(obj_file):
    """ Return all the referenced SHA1 in the given object file """
    objs = []

    if isinstance(obj_file, dulwich.objects.Commit):
        objs.append(obj_file.tree.decode())

        for parent in obj_file.parents:
            objs.append(parent.decode())
    elif isinstance(obj_file, dulwich.objects.Tree):
        for item in obj_file.iteritems():
            objs.append(item.sha.decode())
    elif isinstance(obj_file, dulwich.objects.Blob):
        pass
    elif isinstance(obj_file, dulwich.objects.Tag):
        pass
    else:
        printf("error: unexpected object type: %r\n", obj_file, file=sys.stderr)

    return objs


class _WorkerSlot(object):
    def __init__(self, proc, heartbeat, current_id, started):
        self.proc = proc
        self.heartbeat = heartbeat
        self.current_id = current_id
        self.started = started


class Worker(multiprocessing.Process):
    """ Worker for process_tasks """

    def __init__(self, pending_tasks, tasks_done, args, heartbeat, current_id, failures=None):
        super().__init__()
        self.daemon = True
        self.pending_tasks = pending_tasks
        self.tasks_done = tasks_done
        self.args = args
        self.heartbeat = heartbeat
        self.current_id = current_id
        self.failures = failures

    def touch(self):
        try:
            self.heartbeat.value = time.monotonic()
        except Exception:
            pass

    def note_network_failure(self):
        counter = self.failures
        if counter is None:
            return
        try:
            with counter.get_lock():
                counter.value += 1
        except Exception:
            pass

    def note_network_success(self):
        counter = self.failures
        if counter is None:
            return
        try:
            with counter.get_lock():
                if counter.value:
                    counter.value = 0
        except Exception:
            pass

    def run(self):
        try:
            self.touch()
            try:
                self.init(*self.args)
            except KeyboardInterrupt:
                return
            except BaseException as exc:
                log_failure("[-] Worker failed to start: ", exc)
                return

            while True:
                self.current_id.value = 0
                self.touch()
                try:
                    item = self.pending_tasks.get(timeout=1)
                except queue.Empty:
                    continue
                except (EOFError, OSError, KeyboardInterrupt):
                    return

                if item is None:
                    return

                task_id = None
                task = None
                try:
                    task_id, task = item
                    task_id = int(task_id)
                    self.touch()
                    self.current_id.value = task_id
                    result = self.do_task(task, *self.args)
                except KeyboardInterrupt:
                    return
                except BaseException as exc:
                    label = task if task is not None else item
                    log_failure("[-] " + str(label) + " failed: ", exc)
                    result = []

                if task_id is None:
                    continue
                if not isinstance(result, list):
                    result = []

                self.touch()
                try:
                    self.tasks_done.put((task_id, result))
                except (EOFError, OSError, KeyboardInterrupt):
                    return
                self.current_id.value = 0
        finally:
            close_session_quietly(getattr(self, "session", None))

    def init(self, *args):
        raise NotImplementedError

    def do_task(self, task, *args):
        raise NotImplementedError


def _shutdown_workers(slots, pending_tasks):
    alive = []
    for slot in slots:
        if slot is None:
            continue
        try:
            if slot.proc.is_alive():
                alive.append(slot)
        except Exception:
            continue
    for _slot in alive:
        try:
            pending_tasks.put(None, timeout=1)
        except Exception:
            break
    deadline = time.monotonic() + 2
    for slot in alive:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            slot.proc.join(timeout=remaining)
        except Exception:
            pass
    for slot in slots:
        if slot is not None:
            terminate_process(slot.proc)


def process_tasks(initial_tasks, worker, jobs, args=(), tasks_done=None, timeout=None, retry=None):
    """ Process tasks in parallel.

    A worker that stops reporting progress is killed. The task it was on is
    skipped so one stuck connection cannot block the rest of the run.
    """

    if not initial_tasks:
        return

    ensure_mp_start_method()
    try:
        jobs = max(int(jobs), 1)
    except (TypeError, ValueError):
        jobs = 1

    # Download jobs pass (url, directory, retry, timeout, ...) so the watchdog
    # uses the same limits as the HTTP calls unless the caller overrides them.
    if retry is None:
        try:
            retry = int(args[2])
        except Exception:
            retry = 3
    if timeout is None:
        try:
            timeout = int(args[3])
        except Exception:
            timeout = 3

    budget = network_budget(timeout, retry)
    startup_grace = max(budget, 15.0)
    tasks_seen = set(tasks_done) if tasks_done else set()
    queued = [task for task in initial_tasks if task is not None and task not in tasks_seen]
    if not queued:
        return

    pending_tasks = multiprocessing.Queue()
    done_queue = multiprocessing.Queue()
    failures = multiprocessing.Value("i", 0)
    # Two full waves of parallel transport failures means this host is not
    # answering. Skip the rest of the phase instead of timing out file by file.
    failure_limit = max(jobs * 2, 8)
    outstanding = {}
    next_id = 0
    replacements = 0
    max_replacements = jobs
    slots = []
    idle_since = None

    def submit(task):
        nonlocal next_id
        if task is None or task in tasks_seen:
            return
        next_id += 1
        task_id = next_id
        outstanding[task_id] = task
        tasks_seen.add(task)
        try:
            pending_tasks.put((task_id, task), timeout=30)
        except Exception as exc:
            outstanding.pop(task_id, None)
            log_failure("[-] Could not queue " + str(task) + ": ", exc)

    def start_slot():
        heartbeat = multiprocessing.Value("d", 0.0)
        current_id = multiprocessing.Value("q", 0)
        proc = worker(pending_tasks, done_queue, args, heartbeat, current_id, failures)
        proc.daemon = True
        proc.start()
        return _WorkerSlot(proc, heartbeat, current_id, time.monotonic())

    def replace_slot():
        nonlocal replacements
        if replacements >= max_replacements:
            return None
        try:
            return start_slot()
        except Exception as exc:
            log_failure("[-] Unable to start worker: ", exc)
            return None

    try:
        for _ in range(jobs):
            try:
                slots.append(start_slot())
            except Exception as exc:
                replacements += 1
                log_failure("[-] Unable to start worker: ", exc)
                slots.append(None)

        for task in queued:
            submit(task)

        if not outstanding:
            return

        while outstanding:
            item = None
            try:
                item = done_queue.get(timeout=0.5)
            except queue.Empty:
                item = None
            except (EOFError, OSError) as exc:
                log_failure("[-] Worker queue failed: ", exc)
                break

            if item is not None:
                idle_since = None
                if isinstance(item, tuple) and len(item) == 2:
                    task_id, result = item
                    if task_id in outstanding:
                        outstanding.pop(task_id, None)
                        if not isinstance(result, list):
                            result = []
                        for child in result:
                            submit(child)

            now = time.monotonic()
            busy = False
            starting = False

            for index, slot in enumerate(list(slots)):
                if slot is None:
                    continue
                try:
                    alive = slot.proc.is_alive()
                except Exception:
                    alive = False
                try:
                    busy_id = int(slot.current_id.value or 0)
                except Exception:
                    busy_id = 0
                try:
                    last = float(slot.heartbeat.value or 0)
                except Exception:
                    last = 0.0

                if alive and last <= 0 and (now - slot.started) <= startup_grace:
                    starting = True
                    continue

                age = (now - slot.started) if last <= 0 else (now - last)
                stuck = alive and age > budget
                if stuck or not alive:
                    if busy_id and busy_id in outstanding:
                        task_name = outstanding.pop(busy_id, None)
                        reason = "stalled" if stuck else "worker exited"
                        printf(
                            "[-] Giving up on %s (%s)\n",
                            task_name if task_name is not None else busy_id,
                            reason,
                            file=sys.stderr,
                        )
                    if stuck or not alive:
                        if alive:
                            terminate_process(slot.proc)
                        replacements += 1
                        slots[index] = replace_slot()
                    continue

                if busy_id:
                    busy = True

            if replacements >= max_replacements and outstanding:
                printf(
                    "[-] Too many worker failures; skipping %d remaining task(s)\n",
                    len(outstanding),
                    file=sys.stderr,
                )
                outstanding.clear()
                break

            try:
                failure_count = int(failures.value)
            except Exception:
                failure_count = 0
            if failure_count >= failure_limit and outstanding:
                printf(
                    "[-] Too many network failures; skipping %d remaining task(s)\n",
                    len(outstanding),
                    file=sys.stderr,
                )
                outstanding.clear()
                break

            if busy or starting or not outstanding:
                idle_since = None
            else:
                if idle_since is None:
                    idle_since = now
                elif now - idle_since > budget:
                    printf(
                        "[-] No progress on %d task(s); skipping them\n",
                        len(outstanding),
                        file=sys.stderr,
                    )
                    outstanding.clear()
                    break
    except KeyboardInterrupt:
        raise
    finally:
        _shutdown_workers(slots, pending_tasks)
        close_queue(pending_tasks)
        close_queue(done_queue)


class DownloadWorker(Worker):
    """ Download a list of files """

    def init(self, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        self.session = open_session(
            http_headers,
            retry,
            method=method,
            client_cert_p12=client_cert_p12,
            client_cert_p12_password=client_cert_p12_password,
            mount_url=url,
        )

    def request(self, method, url, timeout, stream=False, allow_redirects=False):
        self.touch()
        try:
            response = self.session.request(
                method,
                url,
                allow_redirects=allow_redirects,
                stream=stream,
                timeout=(timeout, timeout),
            )
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            self.touch()
            self.note_network_failure()
            printf("[-] %s %s failed: %s\n", method, url, format_network_error(exc), file=sys.stderr)
            return None
        self.touch()
        return response

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
            return []

        target = "%s/%s" % (url, filepath)
        response = self.request(method, target, timeout, stream=True, allow_redirects=False)
        if response is None:
            return []

        try:
            printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
            valid, error_message = verify_response(response, any_status)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                self.note_network_success()
                return []

            abspath = os.path.abspath(os.path.join(directory, filepath))
            saved = write_response_to_file(response, abspath, touch=self.touch)
            response = None
            if saved:
                self.note_network_success()
            else:
                self.note_network_failure()
            return []
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            self.note_network_failure()
            printf("[-] %s/%s failed: %s\n", url, filepath, format_network_error(exc), file=sys.stderr)
            return []
        finally:
            close_quietly(response)


class RecursiveDownloadWorker(DownloadWorker):
    """ Download a directory recursively """

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
            return []

        target = "%s/%s" % (url, filepath)
        response = self.request(method, target, timeout, stream=True, allow_redirects=False)
        if response is None:
            return []

        try:
            printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)

            location = ""
            try:
                if "Location" in response.headers:
                    location = response.headers["Location"]
            except Exception:
                location = ""

            if response.status_code in (301, 302) and location.endswith(filepath + "/"):
                self.note_network_success()
                return [filepath + "/"]

            if filepath.endswith("/"):
                if not is_html(response):
                    printf("[-] %s/%s is not a directory index\n", url, filepath, file=sys.stderr)
                    self.note_network_success()
                    return []
                body = read_response_bytes(response, touch=self.touch)
                response = None
                if body is None:
                    self.note_network_failure()
                    return []
                self.note_network_success()
                text = body.decode("utf-8", "replace")
                return [filepath + name for name in get_indexed_files_from_text(text)]

            valid, error_message = verify_response(response, any_status)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                self.note_network_success()
                return []

            abspath = os.path.abspath(os.path.join(directory, filepath))
            saved = write_response_to_file(response, abspath, touch=self.touch)
            response = None
            if saved:
                self.note_network_success()
            else:
                self.note_network_failure()
            return []
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            self.note_network_failure()
            printf("[-] %s/%s failed: %s\n", url, filepath, format_network_error(exc), file=sys.stderr)
            return []
        finally:
            close_quietly(response)


class FindRefsWorker(DownloadWorker):
    """ Find refs/ """

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        target = "%s/%s" % (url, filepath)
        response = self.request(method, target, timeout, stream=True, allow_redirects=False)
        if response is None:
            return []

        try:
            printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
            valid, error_message = verify_response(response, any_status)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                self.note_network_success()
                return []

            abspath = os.path.abspath(os.path.join(directory, filepath))
            if not write_response_to_file(response, abspath, touch=self.touch):
                response = None
                self.note_network_failure()
                return []
            response = None
            self.note_network_success()

            content = read_text_file(abspath)
            tasks = []
            for ref in re.findall(r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)", content):
                ref = ref[0]
                if not ref.endswith("*") and is_safe_path(ref):
                    tasks.append(".git/%s" % ref)
                    tasks.append(".git/logs/%s" % ref)
            return tasks
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            self.note_network_failure()
            printf("[-] %s/%s failed: %s\n", url, filepath, format_network_error(exc), file=sys.stderr)
            return []
        finally:
            close_quietly(response)


class FindObjectsWorker(DownloadWorker):
    """ Find objects """

    def do_task(self, obj, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        try:
            filepath = ".git/objects/%s/%s" % (obj[:2], obj[2:])
        except Exception as exc:
            log_failure("[-] Invalid object id " + str(obj) + ": ", exc)
            return []

        abspath = os.path.abspath(os.path.join(directory, filepath))
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
        else:
            target = "%s/%s" % (url, filepath)
            response = self.request(method, target, timeout, stream=True, allow_redirects=False)
            if response is None:
                return []
            try:
                printf("[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code)
                valid, error_message = verify_response(response, any_status)
                if not valid:
                    printf(error_message, url, filepath, file=sys.stderr)
                    self.note_network_success()
                    return []
                if not write_response_to_file(response, abspath, touch=self.touch):
                    response = None
                    self.note_network_failure()
                    return []
                response = None
                self.note_network_success()
            except KeyboardInterrupt:
                raise
            except BaseException as exc:
                self.note_network_failure()
                printf("[-] %s/%s failed: %s\n", url, filepath, format_network_error(exc), file=sys.stderr)
                return []
            finally:
                close_quietly(response)

        if not os.path.isfile(abspath):
            return []

        try:
            obj_file = dulwich.objects.ShaFile.from_path(abspath)
        except Exception as exc:
            printf("[-] Unable to parse %s: %s\n", filepath, format_network_error(exc), file=sys.stderr)
            remove_quietly(abspath)
            return []
        return get_referenced_sha1(obj_file)


def sanitize_file(filepath):
    """ Comment out possibly unsafe git-config lines """
    if not os.path.isfile(filepath):
        printf("[-] Skipping sanitize, not a file: %s\n", filepath, file=sys.stderr)
        return

    unsafe = r"^\s*fsmonitor|sshcommand|askpass|editor|pager"
    try:
        with open(filepath, "r", errors="replace") as handle:
            content = handle.read()
        modified_content = re.sub(unsafe, r"# \g<0>", content, flags=re.IGNORECASE)
        if content == modified_content:
            return
        printf("Warning: '%s' file was altered\n", filepath)
        tmp_path = filepath + ".san"
        with open(tmp_path, "w") as handle:
            handle.write(modified_content)
        os.replace(tmp_path, filepath)
    except OSError as exc:
        printf("[-] Could not sanitize %s: %s\n", filepath, format_network_error(exc), file=sys.stderr)
        remove_quietly(filepath + ".san")


def sanitize_repository(directory):
    printf("[-] Sanitizing .git/config\n")
    sanitize_file(os.path.join(directory, ".git", "config"))


def _checkout_error_line(err_handle, returncode):
    err = b""
    try:
        if err_handle is not None:
            err_handle.seek(0)
            err = err_handle.read(4096)
    except Exception:
        err = b""
    text = err.decode("utf-8", "replace").strip()
    if text:
        return text.splitlines()[0]
    return "exit %d" % returncode


def run_git_checkout(directory, environment):
    """Run git checkout without letting prompts or a missing git binary abort the run."""
    printf("[-] Running git checkout .\n")
    env = dict(environment or os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.setdefault("GIT_ASKPASS", "true")
    env.setdefault("GCM_INTERACTIVE", "never")
    env.setdefault("GIT_PAGER", "cat")
    try:
        err_handle = tempfile.TemporaryFile()
    except OSError as exc:
        printf("[-] git checkout failed: %s\n", format_network_error(exc), file=sys.stderr)
        return False

    try:
        # A stderr pipe can fill and stall git. The timeout stops a checkout
        # that never returns from freezing the rest of a long batch.
        try:
            result = subprocess.run(
                ["git", "checkout", "."],
                cwd=directory,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=err_handle,
                check=False,
                timeout=180,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            printf("[-] git checkout failed: %s\n", format_network_error(exc), file=sys.stderr)
            return False

        if result.returncode != 0:
            printf(
                "[-] git checkout failed: %s\n",
                _checkout_error_line(err_handle, result.returncode),
                file=sys.stderr,
            )
            return False
        return True
    finally:
        close_quietly(err_handle)


def parse_size(size_str):
    """ Parse human-readable size string (e.g. 500M, 1.5GB, 100KB, 1048576) into bytes """
    if size_str is None:
        return None
    size_str = str(size_str).strip()
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)$", size_str)
    if not match:
        raise argparse.ArgumentTypeError(
            "Invalid size format: '%s'. Expected format like 500MB, 1.5GB, 100M, 50KB, or raw bytes."
            % size_str
        )
    value = float(match.group(1))
    unit = match.group(2).upper()

    units = {
        "": 1,
        "B": 1,
        "K": 1024,
        "KB": 1024,
        "KIB": 1024,
        "M": 1024 * 1024,
        "MB": 1024 * 1024,
        "MIB": 1024 * 1024,
        "G": 1024 * 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "GIB": 1024 * 1024 * 1024,
        "T": 1024 * 1024 * 1024 * 1024,
        "TB": 1024 * 1024 * 1024 * 1024,
        "TIB": 1024 * 1024 * 1024 * 1024,
    }

    if unit not in units:
        raise argparse.ArgumentTypeError(
            "Unknown size unit '%s'. Supported units: B, KB, MB, GB, TB." % unit
        )

    return int(value * units[unit])


def extract_domain_folder(url):
    """ Extract a safe folder name from URL based on domain / hostname """
    # Ensure scheme for proper urlparse netloc resolution
    test_url = url
    if not (test_url.startswith("http://") or test_url.startswith("https://") or test_url.startswith("file://")):
        test_url = "http://" + test_url

    parsed = urllib.parse.urlparse(test_url)
    netloc = parsed.netloc
    if not netloc:
        netloc = parsed.path.split("/")[0]

    # Remove port and sanitize characters not suitable for folder names
    domain = re.sub(r"[:/\\]+", "_", netloc)
    return domain.strip("._") or "target"


def format_size(size_bytes):
    """ Return human-readable size string with exact bytes """
    if size_bytes is None:
        return "Unknown"
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024.0 or unit == 'TB':
            if unit == 'B':
                return "%d B" % int(size)
            return "%.2f %s (%s bytes)" % (size, unit, f"{int(size_bytes):,}")
        size /= 1024.0
    return "%s bytes" % f"{int(size_bytes):,}"


def get_remote_file_size(session, url, filepath, method="HEAD", timeout=3):
    """ Query remote file size via HTTP HEAD or stream GET without downloading the full body """
    target = "%s/%s" % (url, filepath)
    for http_method, stream in (("HEAD", False), ("GET", True)):
        resp = None
        try:
            if isinstance(session, HttpClient):
                resp = session.request(http_method, target, stream=stream, allow_redirects=True)
            else:
                resp = session.request(
                    http_method,
                    target,
                    stream=stream,
                    allow_redirects=True,
                    timeout=(timeout, timeout),
                )
            size = content_length(resp)
        except Exception:
            size = None
        finally:
            close_quietly(resp)
        if size is not None:
            return size
    return None


def analyze_index_metadata(index_path):
    """ Parse .git/index and extract tracked files, uncompressed sizes, and blob shas """
    if not os.path.isfile(index_path):
        return None

    try:
        index = dulwich.index.Index(index_path)
    except Exception as e:
        printf("[-] Unable to parse .git/index: %s\n", e, file=sys.stderr)
        return None

    total_uncompressed_size = 0
    unique_blobs = set()
    blob_sizes = {}
    files_list = []
    ext_stats = {}

    for path_bytes, entry in index.iteritems():
        path_str = path_bytes.decode(errors="replace")
        total_uncompressed_size += entry.size
        sha_hex = binascii.hexlify(entry.sha).decode() if isinstance(entry.sha, bytes) else str(entry.sha)
        unique_blobs.add(sha_hex)
        blob_sizes[sha_hex] = entry.size
        files_list.append((path_str, entry.size))

        ext = os.path.splitext(path_str)[1].lower() or "[no extension]"
        if ext not in ext_stats:
            ext_stats[ext] = {"count": 0, "size": 0}
        ext_stats[ext]["count"] += 1
        ext_stats[ext]["size"] += entry.size

    files_list.sort(key=lambda x: x[1], reverse=True)
    sorted_exts = sorted(ext_stats.items(), key=lambda x: x[1]["size"], reverse=True)

    return {
        "file_count": len(index),
        "total_uncompressed_size": total_uncompressed_size,
        "unique_blobs": unique_blobs,
        "blob_sizes": blob_sizes,
        "top_files": files_list[:5],
        "extensions": sorted_exts[:5],
    }


def analyze_packs_metadata(pack_dir, session=None, base_url=None, timeout=3):
    """ Analyze pack .idx files and estimate or query .pack file sizes """
    packs_data = []
    total_packed_objs = set()
    total_pack_download_size = 0
    total_idx_size = 0

    if not os.path.isdir(pack_dir):
        return {
            "packs": [],
            "total_packed_objects": set(),
            "total_pack_download_size": 0,
            "total_idx_size": 0,
        }

    for filename in sorted(os.listdir(pack_dir)):
        if not (filename.startswith("pack-") and filename.endswith(".idx")):
            continue

        idx_path = os.path.join(pack_dir, filename)
        pack_filename = filename[:-4] + ".pack"
        pack_path = os.path.join(pack_dir, pack_filename)

        idx_size = os.path.getsize(idx_path)
        total_idx_size += idx_size

        try:
            pack_idx = dulwich.pack.load_pack_index(
                idx_path,
                object_format=dulwich.object_format.DEFAULT_OBJECT_FORMAT,
            )
            entries = list(pack_idx.iterentries())
            offsets = sorted(offset for sha, offset, crc in entries)
            pack_shas = {
                binascii.hexlify(sha).decode() if isinstance(sha, bytes) else str(sha)
                for sha, offset, crc in entries
            }
            total_packed_objs.update(pack_shas)
        except Exception as e:
            printf("[-] Skipping unparseable pack index %s: %s\n", filename, e, file=sys.stderr)
            continue

        pack_size = None
        exact_source = None

        # Check local file if exists
        if os.path.isfile(pack_path):
            pack_size = os.path.getsize(pack_path)
            exact_source = "local"
        # Query remote server if session and base_url are provided
        elif session and base_url:
            remote_size = get_remote_file_size(
                session, base_url, ".git/objects/pack/" + pack_filename, timeout=timeout
            )
            if remote_size is not None:
                pack_size = remote_size
                exact_source = "http"

        # Fallback to estimate from .idx offsets
        if pack_size is None:
            # max(offsets) points to the start of the last object.
            # Add ~250 bytes (avg last object) + 20 bytes SHA trailer.
            pack_size = (max(offsets) + 270) if offsets else 32
            exact_source = "estimated"

        total_pack_download_size += pack_size

        packs_data.append({
            "idx_file": filename,
            "pack_file": pack_filename,
            "object_count": len(entries),
            "idx_size": idx_size,
            "pack_size": pack_size,
            "exact_source": exact_source,
            "min_offset": min(offsets) if offsets else 0,
            "max_offset": max(offsets) if offsets else 0,
        })

    return {
        "packs": packs_data,
        "total_packed_objects": total_packed_objs,
        "total_pack_download_size": total_pack_download_size,
        "total_idx_size": total_idx_size,
    }


def analyze_repository_metadata(git_dir, session=None, base_url=None, timeout=3, candidate_objs=None):
    """ Perform comprehensive metadata-based size analysis on .git/index and pack .idx files """
    index_path = os.path.join(git_dir, "index")
    pack_dir = os.path.join(git_dir, "objects", "pack")

    index_stats = analyze_index_metadata(index_path)
    packs_stats = analyze_packs_metadata(pack_dir, session=session, base_url=base_url, timeout=timeout)

    # Discovered candidate objects if not passed
    if candidate_objs is None:
        candidate_objs = set()
        ref_files = [
            os.path.join(git_dir, "packed-refs"),
            os.path.join(git_dir, "info", "refs"),
            os.path.join(git_dir, "FETCH_HEAD"),
            os.path.join(git_dir, "ORIG_HEAD"),
        ]
        for dirpath, _, filenames in os.walk(os.path.join(git_dir, "refs")):
            for filename in filenames:
                ref_files.append(os.path.join(dirpath, filename))
        for dirpath, _, filenames in os.walk(os.path.join(git_dir, "logs")):
            for filename in filenames:
                ref_files.append(os.path.join(dirpath, filename))

        for filepath in ref_files:
            if not os.path.exists(filepath):
                continue
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
                for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
                    candidate_objs.add(obj[1])
            except Exception:
                pass

        if index_stats:
            candidate_objs.update(index_stats["unique_blobs"])

    packed_objs = packs_stats["total_packed_objects"]
    loose_objs = candidate_objs - packed_objs

    # Estimate loose objects download size
    blob_sizes = index_stats["blob_sizes"] if index_stats else {}
    estimated_loose_size = 0
    for sha in loose_objs:
        if sha in blob_sizes:
            # Git deflates blobs. Average code/text compresses to ~40-50%
            estimated_loose_size += int(blob_sizes[sha] * 0.45) + 32
        else:
            # Commit / tree / tag average compressed size
            estimated_loose_size += 600

    # Calculate metadata files size currently on disk
    metadata_download_size = 0
    for root, _, filenames in os.walk(git_dir):
        for fname in filenames:
            # exclude .pack files from metadata count
            if not fname.endswith(".pack"):
                fpath = os.path.join(root, fname)
                try:
                    metadata_download_size += os.path.getsize(fpath)
                except OSError:
                    pass

    total_pack_size = packs_stats["total_pack_download_size"]
    total_estimated_download = metadata_download_size + total_pack_size + estimated_loose_size

    return {
        "index": index_stats,
        "packs": packs_stats,
        "loose": {
            "candidate_count": len(candidate_objs),
            "packed_count": len(packed_objs),
            "loose_count": len(loose_objs),
            "estimated_size": estimated_loose_size,
        },
        "metadata_download_size": metadata_download_size,
        "total_pack_size": total_pack_size,
        "total_loose_size": estimated_loose_size,
        "total_estimated_download": total_estimated_download,
    }


def print_metadata_analysis_report(stats):
    """ Display a structured, detailed size estimation report """
    printf("\n" + "=" * 80 + "\n")
    printf("                  METADATA-BASED REPOSITORY SIZE ESTIMATE\n")
    printf("=" * 80 + "\n\n")

    idx = stats.get("index")
    if idx:
        printf("[+] Working Tree (.git/index):\n")
        printf("    Tracked files:       %d\n", idx["file_count"])
        printf("    Uncompressed size:   %s\n", format_size(idx["total_uncompressed_size"]))
        printf("    Unique staged blobs: %d\n", len(idx["unique_blobs"]))
        if idx["extensions"]:
            printf("    Top file types:\n")
            for ext, ext_data in idx["extensions"]:
                printf("      %-18s %4d files,  %s\n", ext + ":", ext_data["count"], format_size(ext_data["size"]))
        if idx["top_files"]:
            printf("    Largest files in index:\n")
            for path_str, fsize in idx["top_files"]:
                printf("      - %-35s %s\n", path_str[:35], format_size(fsize))
        printf("\n")
    else:
        printf("[-] Working Tree (.git/index): Not available or empty\n\n")

    packs = stats.get("packs")
    if packs and packs["packs"]:
        printf("[+] Packfile Analysis (.git/objects/pack/*.idx):\n")
        printf("    Pack files found:    %d\n", len(packs["packs"]))
        for p in packs["packs"]:
            tag = "Exact via Content-Length" if p["exact_source"] == "http" else (
                "Local file" if p["exact_source"] == "local" else "Estimated from .idx offsets"
            )
            printf("    * %s:\n", p["pack_file"])
            printf("        Objects inside pack: %d\n", p["object_count"])
            printf("        .idx file size:      %s\n", format_size(p["idx_size"]))
            printf("        .pack download size: %s (%s)\n", format_size(p["pack_size"]), tag)
        printf("    Total pack transfer: %s\n\n", format_size(packs["total_pack_download_size"]))
    else:
        printf("[-] Packfile Analysis: No pack files found\n\n")

    loose = stats.get("loose")
    if loose:
        printf("[+] Loose Objects Analysis:\n")
        printf("    Total candidate objs: %d\n", loose["candidate_count"])
        printf("    Already in packfiles: %d\n", loose["packed_count"])
        printf("    Loose objects needed: %d\n", loose["loose_count"])
        printf("    Estimated loose size: %s\n\n", format_size(loose["estimated_size"]))

    printf("=" * 80 + "\n")
    printf("                         DOWNLOAD & DISK SUMMARY\n")
    printf("=" * 80 + "\n")
    printf("    Metadata files (.git/index, refs, .idx): %s\n", format_size(stats["metadata_download_size"]))
    printf("    Pack files (.pack):                      %s\n", format_size(stats["total_pack_size"]))
    printf("    Loose objects (.git/objects/xx/*):       %s\n", format_size(stats["total_loose_size"]))
    printf("    ----------------------------------------------------------------------------\n")
    printf("    ESTIMATED NETWORK DOWNLOAD:              %s\n", format_size(stats["total_estimated_download"]))
    if idx:
        printf("    ESTIMATED WORKING TREE (ON DISK):        %s\n", format_size(idx["total_uncompressed_size"]))
    printf("=" * 80 + "\n\n")


def _report_metadata(git_dir, session, base_url, timeout, candidate_objs=None):
    try:
        stats = analyze_repository_metadata(
            git_dir,
            session=session,
            base_url=base_url,
            timeout=timeout,
            candidate_objs=candidate_objs,
        )
        print_metadata_analysis_report(stats)
        return stats
    except Exception as exc:
        log_failure("[-] Metadata analysis failed: ", exc)
        return None


def _exceeds_max_size(stats, max_size):
    """Return True when the estimated tree is larger than max_size."""
    if max_size is None:
        return False
    if not stats:
        printf("[-] Size check skipped: metadata unavailable\n")
        return False
    try:
        disk_size = stats["index"]["total_uncompressed_size"] if stats.get("index") else stats["total_estimated_download"]
    except Exception as exc:
        log_failure("[-] Size check skipped: ", exc)
        return False
    if disk_size > max_size:
        printf(
            "[-] Skipping download: estimated size on disk (%s) exceeds --max-size threshold (%s)\n",
            format_size(disk_size),
            format_size(max_size),
        )
        return True
    return False


def fetch_git(url, directory, jobs, retry, timeout, http_headers, branches=None, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False, estimate_only=False, estimate=False, max_size=None):
    """ Dump a git repository into the output directory """
    try:
        return _fetch_git_impl(
            url, directory, jobs, retry, timeout, http_headers,
            branches=branches,
            client_cert_p12=client_cert_p12,
            client_cert_p12_password=client_cert_p12_password,
            method=method,
            any_status=any_status,
            estimate_only=estimate_only,
            estimate=estimate,
            max_size=max_size,
        )
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        log_failure("[-] " + str(url) + " failed: ", exc)
        return 1


def _fetch_git_impl(url, directory, jobs, retry, timeout, http_headers, branches=None, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False, estimate_only=False, estimate=False, max_size=None):
    """ Dump a git repository into the output directory """

    assert os.path.isdir(directory), "%s is not a directory" % directory
    assert jobs >= 1, "invalid number of jobs"
    assert retry >= 1, "invalid number of retries"
    assert timeout >= 1, "invalid timeout"

    if not isinstance(url, str) or not url.strip():
        printf("error: invalid URL\n", file=sys.stderr)
        return 1

    # find base url
    url = url.strip().rstrip("/")
    if url.endswith("HEAD"):
        url = url[:-4]
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    if not (url.startswith("http://") or url.startswith("https://")):
        printf("error: URL must start with http:// or https:// (%s)\n", url, file=sys.stderr)
        return 1

    try:
        if os.listdir(directory):
            printf("Warning: Destination '%s' is not empty\n", directory)
    except OSError as exc:
        log_failure("[-] Cannot read destination: ", exc)
        return 1

    session = HttpClient(
        http_headers,
        retry,
        timeout,
        method=method,
        client_cert_p12=client_cert_p12,
        client_cert_p12_password=client_cert_p12_password,
        mount_url=url,
    )

    # check for /.git/HEAD
    printf("[-] Testing %s/.git/HEAD ", url)
    response = session.request(method, "%s/.git/HEAD" % url, allow_redirects=False)
    if response is None:
        printf("\nerror: Unable to connect to %s\n", url, file=sys.stderr)
        return 1

    printf("[%d]\n", response.status_code)

    valid, error_message = verify_response(response, any_status)
    head_text = response_text(response).strip()
    close_quietly(response)
    if not valid:
        printf(error_message, url, "/.git/HEAD", file=sys.stderr)
        return 1
    elif not re.match(r"^(ref:.*|[0-9a-f]{40}$)", head_text):
        printf(
            "error: %s/.git/HEAD is not a git HEAD file\n",
            url,
            file=sys.stderr,
        )
        return 1

    # set up environment to ensure proxy usage
    environment = os.environ.copy()
    try:
        configured_proxy = socks.getdefaultproxy()
        if configured_proxy is not None:
            proxy_types = ["http", "socks4h", "socks5h"]
            proxy_type = configured_proxy[0]
            if isinstance(proxy_type, int) and 0 <= proxy_type < len(proxy_types):
                environment["ALL_PROXY"] = "http.proxy=%s://%s:%s" % (
                    proxy_types[proxy_type],
                    configured_proxy[1],
                    configured_proxy[2],
                )
    except Exception as exc:
        log_failure("[-] Ignoring proxy environment setup: ", exc)

    # check for directory listing
    printf("[-] Testing %s/.git/ ", url)
    response = session.request(method, "%s/.git/" % url, allow_redirects=False)
    indexed = []
    if response is None:
        printf("[-] Directory listing unavailable, fetching common files\n")
    else:
        try:
            printf("[%d]\n", response.status_code)
            if (response.status_code == 200 or any_status) and is_html(response):
                indexed = get_indexed_files(response)
        except Exception as exc:
            log_failure("[-] Directory listing failed: ", exc)
            indexed = []
        finally:
            close_quietly(response)

    if "HEAD" in indexed:
        if estimate_only or estimate or max_size is not None:
            printf("[-] Downloading metadata (.git/index, pack .idx) for size estimation\n")
            meta_tasks = [".gitignore"]
            if any("index" in f for f in indexed):
                meta_tasks.append(".git/index")
            if any("info/packs" in f for f in indexed):
                meta_tasks.append(".git/objects/info/packs")
            process_tasks(
                meta_tasks,
                DownloadWorker,
                jobs,
                args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
            )
            # If info/packs exists, also download any .idx files
            info_packs_p = os.path.join(directory, ".git", "objects", "info", "packs")
            if os.path.exists(info_packs_p):
                try:
                    with open(info_packs_p, "r", errors="replace") as f:
                        pack_shas = re.findall(r"pack-([a-f0-9]{40})\.pack", f.read())
                except OSError as exc:
                    log_failure("[-] Cannot read packs list: ", exc)
                    pack_shas = []
                idx_tasks = [".git/objects/pack/pack-%s.idx" % s for s in pack_shas]
                process_tasks(
                    idx_tasks,
                    DownloadWorker,
                    jobs,
                    args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
                )

            stats = _report_metadata(
                os.path.join(directory, ".git"),
                session,
                url,
                timeout,
            )

            if estimate_only:
                if stats is None:
                    printf("[-] Estimate failed\n", file=sys.stderr)
                    return 1
                printf("[-] Estimate complete (--estimate-only was specified). Exiting without downloading repository payload.\n")
                return 0

            if _exceeds_max_size(stats, max_size):
                return 2

        printf("[-] Fetching .git recursively\n")
        process_tasks(
            [".git/", ".gitignore"],
            RecursiveDownloadWorker,
            jobs,
            args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
        )

        sanitize_repository(directory)
        run_git_checkout(directory, environment)
        return 0

    # no directory listing
    printf("[-] Fetching common files\n")
    tasks = [
        ".gitignore",
        ".git/COMMIT_EDITMSG",
        ".git/description",
        ".git/hooks/applypatch-msg.sample",
        ".git/hooks/commit-msg.sample",
        ".git/hooks/post-commit.sample",
        ".git/hooks/post-receive.sample",
        ".git/hooks/post-update.sample",
        ".git/hooks/pre-applypatch.sample",
        ".git/hooks/pre-commit.sample",
        ".git/hooks/pre-push.sample",
        ".git/hooks/pre-rebase.sample",
        ".git/hooks/pre-receive.sample",
        ".git/hooks/prepare-commit-msg.sample",
        ".git/hooks/update.sample",
        ".git/index",
        ".git/info/exclude",
        ".git/objects/info/packs",
    ]
    process_tasks(
        tasks,
        DownloadWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
    )

    # find refs
    printf("[-] Finding refs/\n")
    tasks = [
        ".git/FETCH_HEAD",
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/config",
        ".git/info/refs",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/main",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/heads/staging",
        ".git/logs/refs/heads/production",
        ".git/logs/refs/heads/development",
        ".git/logs/refs/remotes/origin/HEAD",
        ".git/logs/refs/remotes/origin/main",
        ".git/logs/refs/remotes/origin/master",
        ".git/logs/refs/remotes/origin/staging",
        ".git/logs/refs/remotes/origin/production",
        ".git/logs/refs/remotes/origin/development",
        ".git/logs/refs/stash",
        ".git/packed-refs",
        ".git/refs/heads/main",
        ".git/refs/heads/master",
        ".git/refs/heads/staging",
        ".git/refs/heads/production",
        ".git/refs/heads/development",
        ".git/refs/remotes/origin/HEAD",
        ".git/refs/remotes/origin/main",
        ".git/refs/remotes/origin/master",
        ".git/refs/remotes/origin/staging",
        ".git/refs/remotes/origin/production",
        ".git/refs/remotes/origin/development",
        ".git/refs/stash",
        ".git/refs/wip/wtree/refs/heads/main",
        ".git/refs/wip/wtree/refs/heads/master",
        ".git/refs/wip/wtree/refs/heads/staging",
        ".git/refs/wip/wtree/refs/heads/production",
        ".git/refs/wip/wtree/refs/heads/development",
        ".git/refs/wip/index/refs/heads/main",
        ".git/refs/wip/index/refs/heads/master",
        ".git/refs/wip/index/refs/heads/staging",
        ".git/refs/wip/index/refs/heads/production",
        ".git/refs/wip/index/refs/heads/development"
    ]

    # include user-specified branches
    if branches:
        for branch in branches:
            if not re.match(r'^[A-Za-z0-9\-\._]+$', branch):
                printf("Warning: ignoring invalid branch name '%s'\n", branch)
                continue
            tasks.extend(
                [
                    f".git/logs/refs/heads/{branch}",
                    f".git/refs/heads/{branch}",
                    f".git/logs/refs/remotes/origin/{branch}",
                    f".git/refs/remotes/origin/{branch}",
                    f".git/refs/wip/wtree/refs/heads/{branch}",
                    f".git/refs/wip/index/refs/heads/{branch}",
                ]
            )

    process_tasks(
        tasks,
        FindRefsWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
    )

    # find packs
    printf("[-] Finding packs\n")
    pack_shas = []

    # use .git/objects/info/packs to find packs
    info_packs_path = os.path.join(
        directory, ".git", "objects", "info", "packs"
    )
    if os.path.exists(info_packs_path):
        try:
            with open(info_packs_path, "r", errors="replace") as f:
                info_packs = f.read()
            pack_shas = re.findall(r"pack-([a-f0-9]{40})\.pack", info_packs)
        except OSError as exc:
            log_failure("[-] Cannot read packs list: ", exc)
            pack_shas = []

    # Fetch pack index files (.idx) first to inspect metadata without downloading huge .pack files
    if pack_shas:
        printf("[-] Fetching pack index files (.idx)\n")
        idx_tasks = [".git/objects/pack/pack-%s.idx" % sha1 for sha1 in pack_shas]
        process_tasks(
            idx_tasks,
            DownloadWorker,
            jobs,
            args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
        )

    # find objects
    printf("[-] Finding objects\n")
    objs = set()
    packed_objs = set()

    # .git/packed-refs, .git/info/refs, .git/refs/*, .git/logs/*
    files = [
        os.path.join(directory, ".git", "packed-refs"),
        os.path.join(directory, ".git", "info", "refs"),
        os.path.join(directory, ".git", "FETCH_HEAD"),
        os.path.join(directory, ".git", "ORIG_HEAD"),
    ]
    for dirpath, _, filenames in os.walk(
        os.path.join(directory, ".git", "refs")
    ):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    for dirpath, _, filenames in os.walk(
        os.path.join(directory, ".git", "logs")
    ):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))

    for filepath in files:
        if not os.path.exists(filepath):
            continue

        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
        except OSError as exc:
            log_failure("[-] Cannot read " + filepath + ": ", exc)
            continue

        for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
            obj = obj[1]
            objs.add(obj)

    # use .git/index to find objects
    index_path = os.path.join(directory, ".git", "index")
    if os.path.exists(index_path):
        # A corrupt/garbage index (e.g. an error page saved via --any-status)
        # must not abort the whole dump; skip it and rely on other sources.
        try:
            index = dulwich.index.Index(index_path)

            for entry in index.iterobjects():
                objs.add(entry[1].decode())
        except Exception as e:
            printf(
                "[-] Skipping unparseable .git/index: %s\n",
                e,
                file=sys.stderr,
            )

    # use pack .idx files to find packed objects
    pack_file_dir = os.path.join(directory, ".git", "objects", "pack")
    if os.path.isdir(pack_file_dir):
        try:
            idx_names = os.listdir(pack_file_dir)
        except OSError as exc:
            log_failure("[-] Cannot list pack directory: ", exc)
            idx_names = []
        for filename in idx_names:
            if filename.startswith("pack-") and filename.endswith(".idx"):
                pack_idx_path = os.path.join(pack_file_dir, filename)
                try:
                    pack_idx = dulwich.pack.load_pack_index(
                        pack_idx_path,
                        object_format=dulwich.object_format.DEFAULT_OBJECT_FORMAT,
                    )
                    for entry in pack_idx.iterentries():
                        sha = binascii.hexlify(entry[0]).decode() if isinstance(entry[0], bytes) else str(entry[0])
                        packed_objs.add(sha)
                except Exception as e:
                    printf(
                        "[-] Skipping unparseable pack index %s: %s\n",
                        filename,
                        e,
                        file=sys.stderr,
                    )

    # Run metadata-based size analysis before downloading .pack files and loose objects
    stats = _report_metadata(
        os.path.join(directory, ".git"),
        session,
        url,
        timeout,
        candidate_objs=objs,
    )

    if estimate_only:
        if stats is None:
            printf("[-] Estimate failed\n", file=sys.stderr)
            return 1
        printf("[-] Estimate complete (--estimate-only was specified). Exiting without downloading repository payload.\n")
        return 0

    if _exceeds_max_size(stats, max_size):
        return 2

    # Fetch pack files (.pack) now that size estimation is complete
    if pack_shas:
        printf("[-] Fetching pack files (.pack)\n")
        pack_tasks = [".git/objects/pack/pack-%s.pack" % sha1 for sha1 in pack_shas]
        process_tasks(
            pack_tasks,
            DownloadWorker,
            jobs,
            args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
        )

        # parse downloaded packs to find more referenced objects
        try:
            pack_names = os.listdir(pack_file_dir)
        except OSError as exc:
            log_failure("[-] Cannot list pack directory: ", exc)
            pack_names = []
        for filename in pack_names:
            if filename.startswith("pack-") and filename.endswith(".pack"):
                pack_data_path = os.path.join(pack_file_dir, filename)
                pack_idx_path = os.path.join(
                    pack_file_dir, filename[:-5] + ".idx"
                )
                if os.path.exists(pack_data_path) and os.path.exists(pack_idx_path):
                    try:
                        pack_data = dulwich.pack.PackData(
                            pack_data_path,
                            object_format=dulwich.object_format.DEFAULT_OBJECT_FORMAT,
                        )
                        pack_idx = dulwich.pack.load_pack_index(
                            pack_idx_path,
                            object_format=dulwich.object_format.DEFAULT_OBJECT_FORMAT,
                        )
                        pack = dulwich.pack.Pack.from_objects(pack_data, pack_idx)

                        for obj_file in pack.iterobjects():
                            objs |= set(get_referenced_sha1(obj_file))
                    except Exception as e:
                        printf(
                            "[-] Skipping unparseable pack %s: %s\n",
                            filename,
                            e,
                            file=sys.stderr,
                        )

    # fetch all objects
    printf("[-] Fetching objects\n")
    process_tasks(
        objs,
        FindObjectsWorker,
        jobs,
        args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
        tasks_done=packed_objs,
    )

    sanitize_repository(directory)
    run_git_checkout(directory, environment)
    return 0


def main():
    parser = argparse.ArgumentParser(
        usage="git-dumper [options] URL DIR",
        description="Dump a git repository from a website.",
    )
    parser.add_argument("url", metavar="URL", nargs="?", default=None, help="url or local repository path (not required if using -l/--url-list)")
    parser.add_argument(
        "directory",
        metavar="DIR",
        nargs="?",
        default=None,
        help="output directory (required unless using --estimate-only with a local repository)",
    )
    parser.add_argument(
        "-l",
        "--url-list",
        help="file containing a list of URLs to process (one per line)",
    )
    parser.add_argument(
        "--estimate-only",
        action="store_true",
        help="perform comprehensive metadata-based size analysis (.git/index and pack .idx files) and exit without downloading full repo",
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="display comprehensive size estimate before proceeding with download",
    )
    parser.add_argument(
        "--max-size",
        type=parse_size,
        default=None,
        help="skip downloading if estimated working tree size on disk exceeds limit (e.g. 500MB, 1.5GB, 100M)",
    )
    parser.add_argument("--proxy", help="use the specified proxy")
    parser.add_argument(
        "-X",
        "--method",
        type=str,
        default="GET",
        help="HTTP method to use for all requests (e.g. GET, POST)",
    )
    parser.add_argument(
        "--any-status",
        action="store_true",
        help="accept any HTTP status code as long as the body is non-empty "
        "and not HTML (e.g. targets that return 500 but still serve content)",
    )
    parser.add_argument("--client-cert-p12", help="client certificate in PKCS#12")
    parser.add_argument("--client-cert-p12-password", help="password for the client certificate")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=10,
        help="number of simultaneous requests",
    )
    parser.add_argument(
        "-r",
        "--retry",
        type=int,
        default=3,
        help="number of request attempts before giving up",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=3,
        help="seconds to wait for a connection or for more data before giving up on that request",
    )
    parser.add_argument(
        "-u",
        "--user-agent",
        type=str,
        default="Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
        help="user-agent to use for requests",
    )
    parser.add_argument(
        "-H",
        "--header",
        type=str,
        action="append",
        help="additional http headers, e.g `NAME=VALUE`",
    )
    parser.add_argument(
        "-b",
        "--branch",
        dest="branches",
        action="append",
        help="additional branch names to check for, e.g. `-b dev -b prod`. The default branches (`main`, `master`, `staging`, `production`, `development`) are always checked.",
    )
    args = parser.parse_args()

    # method
    args.method = args.method.upper()

    # jobs
    if args.jobs < 1:
        parser.error("invalid number of jobs, got `%d`" % args.jobs)

    # retry
    if args.retry < 1:
        parser.error("invalid number of retries, got `%d`" % args.retry)

    # timeout
    if args.timeout < 1:
        parser.error("invalid timeout, got `%d`" % args.timeout)

    # header
    http_headers = {"User-Agent": args.user_agent}
    if args.header:
        for header in args.header:
            tokens = header.split("=", maxsplit=1)
            if len(tokens) != 2:
                parser.error(
                    "http header must have the form NAME=VALUE, got `%s`"
                    % header
                )
            name, value = tokens
            http_headers[name.strip()] = value.strip()

    # proxy
    if args.proxy:
        proxy_valid = False

        for pattern, proxy_type in [
            (r"^socks5:(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
            (r"^socks4:(.*):(\d+)$", socks.PROXY_TYPE_SOCKS4),
            (r"^http://(.*):(\d+)$", socks.PROXY_TYPE_HTTP),
            (r"^(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
        ]:
            m = re.match(pattern, args.proxy)
            if m:
                socks.setdefaultproxy(proxy_type, m.group(1), int(m.group(2)))
                socket.socket = socks.socksocket
                proxy_valid = True
                break

        if not proxy_valid:
            parser.error("invalid proxy, got `%s`" % args.proxy)

    # Validate inputs based on whether -l/--url-list is used
    if args.url_list:
        if not os.path.isfile(args.url_list):
            parser.error("url list file '%s' does not exist" % args.url_list)
        if args.directory is None and args.url is not None:
            args.directory = args.url
            args.url = None
        if not args.directory:
            parser.error("DIR is required when using -l/--url-list")
    else:
        if not args.url:
            parser.error("URL is required unless using -l/--url-list")

    # Output directory handling
    temp_dir_obj = None
    if not args.directory:
        if args.estimate_only:
            temp_dir_obj = tempfile.TemporaryDirectory(prefix="git_dumper_meta_")
            args.directory = temp_dir_obj.name
        else:
            parser.error("DIR is required when downloading a repository")

    if not os.path.exists(args.directory):
        os.makedirs(args.directory)

    if not os.path.isdir(args.directory):
        parser.error("`%s` is not a directory" % args.directory)

    # client certificate
    if args.client_cert_p12:
        if not os.path.exists(args.client_cert_p12):
            parser.error(
                "client certificate `%s` does not exist" % args.client_cert_p12
            )

        if not os.path.isfile(args.client_cert_p12):
            parser.error(
                "client certificate `%s` is not a file" % args.client_cert_p12
            )

        if args.client_cert_p12_password is None:
            parser.error("client certificate password is required")

    silence_tls_warnings()

    # Batch URL list execution
    if args.url_list:
        try:
            with open(args.url_list, "r", errors="replace") as f:
                raw_lines = [line.strip() for line in f]
        except OSError as exc:
            log_failure("[-] Cannot read URL list: ", exc)
            sys.exit(1)
        urls = [u for u in raw_lines if u and not u.startswith("#")]
        if not urls:
            printf("[-] No valid URLs found in '%s'\n", args.url_list)
            sys.exit(0)

        printf("[-] Loaded %d URL(s) from '%s'\n", len(urls), args.url_list)
        printf("[-] Output base directory: %s\n", args.directory)
        succeeded = 0
        skipped = 0
        failed = 0
        interrupted = False

        try:
            for idx, target_url in enumerate(urls, 1):
                try:
                    domain = extract_domain_folder(target_url)
                    target_dir = os.path.join(args.directory, domain)

                    printf("\n" + "=" * 80 + "\n")
                    printf("[%d/%d] Target URL: %s\n", idx, len(urls), target_url)
                    printf("      Destination: %s\n", target_dir)
                    printf("=" * 80 + "\n\n")

                    os.makedirs(target_dir, exist_ok=True)
                    ret = fetch_git(
                        target_url,
                        target_dir,
                        args.jobs,
                        args.retry,
                        args.timeout,
                        http_headers,
                        args.branches,
                        args.client_cert_p12,
                        args.client_cert_p12_password,
                        args.method,
                        args.any_status,
                        args.estimate_only,
                        args.estimate,
                        args.max_size,
                    )
                    if ret == 0:
                        succeeded += 1
                    elif ret == 2:
                        skipped += 1
                    else:
                        failed += 1
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    log_failure("\n[-] Error processing " + str(target_url) + ": ", exc)
                    failed += 1
        except KeyboardInterrupt:
            interrupted = True
            printf("\n[-] Interrupted\n", file=sys.stderr)
        finally:
            printf("\n" + "=" * 80 + "\n")
            printf("                             BATCH SUMMARY\n")
            printf("=" * 80 + "\n")
            printf("    Total Targets:     %d\n", len(urls))
            printf("    Succeeded:         %d\n", succeeded)
            printf("    Skipped (--max):   %d\n", skipped)
            printf("    Failed / Inactive: %d\n", failed)
            printf("=" * 80 + "\n\n")

        sys.exit(130 if interrupted else (0 if failed == 0 else 1))

    # Single URL / local repository execution
    local_path = None
    if args.url.startswith("file://"):
        local_path = args.url[7:]
    elif os.path.exists(args.url):
        local_path = args.url

    is_local_repo = False
    local_git_dir = None
    if local_path:
        if os.path.isdir(os.path.join(local_path, ".git")):
            is_local_repo = True
            local_git_dir = os.path.join(local_path, ".git")
        elif os.path.exists(os.path.join(local_path, "HEAD")):
            is_local_repo = True
            local_git_dir = local_path

    if is_local_repo:
        printf("[-] Detected local git repository: %s\n", local_git_dir)
        try:
            stats = analyze_repository_metadata(local_git_dir)
            print_metadata_analysis_report(stats)
        except Exception as exc:
            log_failure("[-] Metadata analysis failed: ", exc)
            sys.exit(1)
        if _exceeds_max_size(stats, args.max_size):
            sys.exit(0)
        if args.estimate_only or not args.directory:
            sys.exit(0)

    # fetch everything
    ret = 1
    try:
        ret = fetch_git(
            args.url,
            args.directory,
            args.jobs,
            args.retry,
            args.timeout,
            http_headers,
            args.branches,
            args.client_cert_p12,
            args.client_cert_p12_password,
            args.method,
            args.any_status,
            args.estimate_only,
            args.estimate,
            args.max_size,
        )
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        log_failure("[-] " + str(args.url) + " failed: ", exc)
        ret = 1
    finally:
        if temp_dir_obj is not None:
            try:
                temp_dir_obj.cleanup()
            except Exception:
                pass

    sys.exit(ret if isinstance(ret, int) else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        printf("\n[-] Interrupted\n", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
    except Exception as exc:
        log_failure("[-] Fatal error: ", exc)
        sys.exit(1)
