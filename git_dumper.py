#!/usr/bin/env python3
from contextlib import closing
import argparse
import binascii
import glob
import multiprocessing
import os
import os.path
import re
import socket
import subprocess
import sys
import tempfile
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


def printf(fmt, *args, file=sys.stdout):
    if args:
        fmt = fmt % args

    file.write(fmt)
    file.flush()


def is_html(response):
    """ Return True if the response is a HTML webpage """
    return (
        "Content-Type" in response.headers
        and "text/html" in response.headers["Content-Type"]
    )


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


def get_indexed_files(response):
    """ Return all the files in the directory index webpage """
    html = bs4.BeautifulSoup(response.text, "html.parser")
    files = []

    for link in html.find_all("a"):
        url = urllib.parse.urlparse(link.get("href"))

        if (
            url.path
            and is_safe_path(url.path)
            and not url.scheme
            and not url.netloc
        ):
            files.append(url.path)

    return files


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
        printf(
            "error: unexpected object type: %r\n" % obj_file, file=sys.stderr
        )
        sys.exit(1)

    return objs


class Worker(multiprocessing.Process):
    """ Worker for process_tasks """

    def __init__(self, pending_tasks, tasks_done, args):
        super().__init__()
        self.daemon = True
        self.pending_tasks = pending_tasks
        self.tasks_done = tasks_done
        self.args = args

    def run(self):
        # initialize process
        self.init(*self.args)

        # fetch and do tasks
        while True:
            task = self.pending_tasks.get(block=True)

            if task is None:  # end signal
                return

            try:
                result = self.do_task(task, *self.args)
            except Exception:
                printf("Task %s raised exception:\n", task, file=sys.stderr)
                traceback.print_exc()
                result = []

            assert isinstance(
                result, list
            ), "do_task() should return a list of tasks"

            self.tasks_done.put(result)

    def init(self, *args):
        raise NotImplementedError

    def do_task(self, task, *args):
        raise NotImplementedError


def process_tasks(initial_tasks, worker, jobs, args=(), tasks_done=None):
    """ Process tasks in parallel """

    if not initial_tasks:
        return

    tasks_seen = set(tasks_done) if tasks_done else set()
    pending_tasks = multiprocessing.Queue()
    tasks_done = multiprocessing.Queue()
    num_pending_tasks = 0

    # add all initial tasks in the queue
    for task in initial_tasks:
        assert task is not None

        if task not in tasks_seen:
            pending_tasks.put(task)
            num_pending_tasks += 1
            tasks_seen.add(task)

    # initialize processes
    processes = [worker(pending_tasks, tasks_done, args) for _ in range(jobs)]

    # launch them all
    for p in processes:
        p.start()

    # collect task results
    while num_pending_tasks > 0:
        task_result = tasks_done.get(block=True)
        num_pending_tasks -= 1

        for task in task_result:
            assert task is not None

            if task not in tasks_seen:
                pending_tasks.put(task)
                num_pending_tasks += 1
                tasks_seen.add(task)

    # send termination signal (task=None)
    for _ in range(jobs):
        pending_tasks.put(None)

    # join all
    for p in processes:
        p.join()


class DownloadWorker(Worker):
    """ Download a list of files """

    def init(self, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = http_headers
        if client_cert_p12:
            self.session.mount(url, Pkcs12Adapter(pkcs12_filename=client_cert_p12, pkcs12_password=client_cert_p12_password))
        else:
            self.session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
            return []

        with closing(
            self.session.request(
                method,
                "%s/%s" % (url, filepath),
                allow_redirects=False,
                stream=True,
                timeout=timeout,
            )
        ) as response:
            printf(
                "[-] Fetching %s/%s [%d]\n",
                url,
                filepath,
                response.status_code,
            )

            valid, error_message = verify_response(response, any_status)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                return []

            abspath = os.path.abspath(os.path.join(directory, filepath))
            create_intermediate_dirs(abspath)

            # write file
            with open(abspath, "wb") as f:
                for chunk in response.iter_content(4096):
                    f.write(chunk)

            return []


class RecursiveDownloadWorker(DownloadWorker):
    """ Download a directory recursively """

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
            return []

        with closing(
            self.session.request(
                method,
                "%s/%s" % (url, filepath),
                allow_redirects=False,
                stream=True,
                timeout=timeout,
            )
        ) as response:
            printf(
                "[-] Fetching %s/%s [%d]\n",
                url,
                filepath,
                response.status_code,
            )

            if (
                response.status_code in (301, 302)
                and "Location" in response.headers
                and response.headers["Location"].endswith(filepath + "/")
            ):
                return [filepath + "/"]

            if filepath.endswith("/"):  # directory index
                assert is_html(response)

                return [
                    filepath + filename
                    for filename in get_indexed_files(response)
                ]
            else:  # file
                valid, error_message = verify_response(response, any_status)
                if not valid:
                    printf(error_message, url, filepath, file=sys.stderr)
                    return []

                abspath = os.path.abspath(os.path.join(directory, filepath))
                create_intermediate_dirs(abspath)

                # write file
                with open(abspath, "wb") as f:
                    for chunk in response.iter_content(4096):
                        f.write(chunk)

                return []


class FindRefsWorker(DownloadWorker):
    """ Find refs/ """

    def do_task(self, filepath, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        response = self.session.request(
            method, "%s/%s" % (url, filepath), allow_redirects=False, timeout=timeout
        )
        printf(
            "[-] Fetching %s/%s [%d]\n", url, filepath, response.status_code
        )

        valid, error_message = verify_response(response, any_status)
        if not valid:
            printf(error_message, url, filepath, file=sys.stderr)
            return []

        abspath = os.path.abspath(os.path.join(directory, filepath))
        create_intermediate_dirs(abspath)

        # write file
        with open(abspath, "w") as f:
            f.write(response.text)

        # find refs
        tasks = []

        for ref in re.findall(
            r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)", response.text
        ):
            ref = ref[0]
            if not ref.endswith("*") and is_safe_path(ref):
                tasks.append(".git/%s" % ref)
                tasks.append(".git/logs/%s" % ref)

        return tasks


class FindObjectsWorker(DownloadWorker):
    """ Find objects """

    def do_task(self, obj, url, directory, retry, timeout, http_headers, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False):
        filepath = ".git/objects/%s/%s" % (obj[:2], obj[2:])

        if os.path.isfile(os.path.join(directory, filepath)):
            printf("[-] Already downloaded %s/%s\n", url, filepath)
        else:
            response = self.session.request(
                method,
                "%s/%s" % (url, filepath),
                allow_redirects=False,
                timeout=timeout,
            )
            printf(
                "[-] Fetching %s/%s [%d]\n",
                url,
                filepath,
                response.status_code,
            )

            valid, error_message = verify_response(response, any_status)
            if not valid:
                printf(error_message, url, filepath, file=sys.stderr)
                return []

            abspath = os.path.abspath(os.path.join(directory, filepath))
            create_intermediate_dirs(abspath)

            # write file
            with open(abspath, "wb") as f:
                f.write(response.content)

        abspath = os.path.abspath(os.path.join(directory, filepath))
        # parse object file to find other objects
        obj_file = dulwich.objects.ShaFile.from_path(abspath)
        return get_referenced_sha1(obj_file)


def sanitize_file(filepath):
    """ Inplace comment out possibly unsafe lines based on regex """
    assert os.path.isfile(filepath), "%s is not a file" % filepath

    UNSAFE=r"^\s*fsmonitor|sshcommand|askpass|editor|pager"

    with open(filepath, 'r+') as f:
        content = f.read()
        modified_content = re.sub(UNSAFE, r'# \g<0>', content, flags=re.IGNORECASE)
        if content != modified_content:
            printf("Warning: '%s' file was altered\n" % filepath)
            f.seek(0)
            f.write(modified_content)


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
    try:
        resp = session.request(
            "HEAD",
            "%s/%s" % (url, filepath),
            allow_redirects=True,
            timeout=timeout,
        )
        if resp.status_code == 200 and "Content-Length" in resp.headers:
            return int(resp.headers["Content-Length"])
    except Exception:
        pass

    try:
        with closing(
            session.request(
                "GET",
                "%s/%s" % (url, filepath),
                stream=True,
                allow_redirects=True,
                timeout=timeout,
            )
        ) as resp:
            if resp.status_code == 200 and "Content-Length" in resp.headers:
                return int(resp.headers["Content-Length"])
    except Exception:
        pass

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


def fetch_git(url, directory, jobs, retry, timeout, http_headers, branches=None, client_cert_p12=None, client_cert_p12_password=None, method="GET", any_status=False, estimate_only=False, estimate=False, max_size=None):
    """ Dump a git repository into the output directory """

    assert os.path.isdir(directory), "%s is not a directory" % directory
    assert jobs >= 1, "invalid number of jobs"
    assert retry >= 1, "invalid number of retries"
    assert timeout >= 1, "invalid timeout"

    session = requests.Session()
    session.verify = False
    session.headers = http_headers
    if client_cert_p12:
        session.mount(url, Pkcs12Adapter(pkcs12_filename=client_cert_p12, pkcs12_password=client_cert_p12_password))
    else:
        session.mount(url, requests.adapters.HTTPAdapter(max_retries=retry))
    if os.listdir(directory):
        printf("Warning: Destination '%s' is not empty\n", directory)

    # find base url
    url = url.rstrip("/")
    if url.endswith("HEAD"):
        url = url[:-4]
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    # check for /.git/HEAD
    try:
        printf("[-] Testing %s/.git/HEAD ", url)
        response = session.request(
            method,
            "%s/.git/HEAD" % url,
            timeout=timeout,
            allow_redirects=False
        )
    except Exception as e:
        printf("\nerror: Unable to connect to %s. Error: %s\n", url, e)
        return 1

    printf("[%d]\n", response.status_code)

    valid, error_message = verify_response(response, any_status)
    if not valid:
        printf(error_message, url, "/.git/HEAD", file=sys.stderr)
        return 1
    elif not re.match(r"^(ref:.*|[0-9a-f]{40}$)", response.text.strip()):
        printf(
            "error: %s/.git/HEAD is not a git HEAD file\n",
            url,
            file=sys.stderr,
        )
        return 1

    # set up environment to ensure proxy usage
    environment = os.environ.copy()
    configured_proxy = socks.getdefaultproxy()
    if configured_proxy is not None:
        proxy_types = ["http", "socks4h", "socks5h"]
        environment["ALL_PROXY"] = f"http.proxy={proxy_types[configured_proxy[0]]}://{configured_proxy[1]}:{configured_proxy[2]}"

    # check for directory listing
    printf("[-] Testing %s/.git/ ", url)
    response = session.request(method, "%s/.git/" % url, allow_redirects=False)
    printf("[%d]\n", response.status_code)


    if (
        (response.status_code == 200 or any_status)
        and is_html(response)
        and "HEAD" in get_indexed_files(response)
    ):
        if estimate_only or estimate or max_size is not None:
            printf("[-] Downloading metadata (.git/index, pack .idx) for size estimation\n")
            meta_tasks = [".gitignore"]
            indexed = get_indexed_files(response)
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
                with open(info_packs_p, "r") as f:
                    pack_shas = re.findall(r"pack-([a-f0-9]{40})\.pack", f.read())
                idx_tasks = [".git/objects/pack/pack-%s.idx" % s for s in pack_shas]
                process_tasks(
                    idx_tasks,
                    DownloadWorker,
                    jobs,
                    args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
                )

            stats = analyze_repository_metadata(
                os.path.join(directory, ".git"),
                session=session,
                base_url=url,
                timeout=timeout,
            )
            print_metadata_analysis_report(stats)

            if estimate_only:
                printf("[-] Estimate complete (--estimate-only was specified). Exiting without downloading repository payload.\n")
                return 0

            if max_size is not None:
                disk_size = stats["index"]["total_uncompressed_size"] if stats.get("index") else stats["total_estimated_download"]
                if disk_size > max_size:
                    printf(
                        "[-] Skipping download: estimated size on disk (%s) exceeds --max-size threshold (%s)\n",
                        format_size(disk_size),
                        format_size(max_size),
                    )
                    return 2

        printf("[-] Fetching .git recursively\n")
        process_tasks(
            [".git/", ".gitignore"],
            RecursiveDownloadWorker,
            jobs,
            args=(url, directory, retry, timeout, http_headers, client_cert_p12, client_cert_p12_password, method, any_status),
        )

        os.chdir(directory)

        printf("[-] Sanitizing .git/config\n")
        sanitize_file(".git/config")

        printf("[-] Running git checkout .\n")
        subprocess.check_call(["git", "checkout", "."], env=environment)
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
        with open(info_packs_path, "r") as f:
            info_packs = f.read()

        pack_shas = re.findall(r"pack-([a-f0-9]{40})\.pack", info_packs)

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

        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

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
        for filename in os.listdir(pack_file_dir):
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
    stats = analyze_repository_metadata(
        os.path.join(directory, ".git"),
        session=session,
        base_url=url,
        timeout=timeout,
        candidate_objs=objs,
    )
    print_metadata_analysis_report(stats)

    if estimate_only:
        printf("[-] Estimate complete (--estimate-only was specified). Exiting without downloading repository payload.\n")
        return 0

    if max_size is not None:
        disk_size = stats["index"]["total_uncompressed_size"] if stats.get("index") else stats["total_estimated_download"]
        if disk_size > max_size:
            printf(
                "[-] Skipping download: estimated size on disk (%s) exceeds --max-size threshold (%s)\n",
                format_size(disk_size),
                format_size(max_size),
            )
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
        for filename in os.listdir(pack_file_dir):
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

    # git checkout
    printf("[-] Running git checkout .\n")
    os.chdir(directory)
    sanitize_file(".git/config")

    # ignore errors
    subprocess.call(
        ["git", "checkout", "."],
        stderr=open(os.devnull, "wb"),
        env=environment
    )

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
        help="maximum time in seconds before giving up",
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

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Batch URL list execution
    if args.url_list:
        with open(args.url_list, "r") as f:
            raw_lines = [line.strip() for line in f]
        urls = [u for u in raw_lines if u and not u.startswith("#")]
        if not urls:
            printf("[-] No valid URLs found in '%s'\n", args.url_list)
            sys.exit(0)

        printf("[-] Loaded %d URL(s) from '%s'\n", len(urls), args.url_list)
        printf("[-] Output base directory: %s\n", args.directory)
        succeeded = 0
        skipped = 0
        failed = 0

        for idx, target_url in enumerate(urls, 1):
            domain = extract_domain_folder(target_url)
            target_dir = os.path.join(args.directory, domain)

            printf("\n" + "=" * 80 + "\n")
            printf("[%d/%d] Target URL: %s\n", idx, len(urls), target_url)
            printf("      Destination: %s\n", target_dir)
            printf("=" * 80 + "\n\n")

            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            try:
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
            except Exception as e:
                printf("\n[-] Error processing %s: %s\n", target_url, e, file=sys.stderr)
                failed += 1

        printf("\n" + "=" * 80 + "\n")
        printf("                             BATCH SUMMARY\n")
        printf("=" * 80 + "\n")
        printf("    Total Targets:     %d\n", len(urls))
        printf("    Succeeded:         %d\n", succeeded)
        printf("    Skipped (--max):   %d\n", skipped)
        printf("    Failed / Inactive: %d\n", failed)
        printf("=" * 80 + "\n\n")

        sys.exit(0 if failed == 0 else 1)

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
        stats = analyze_repository_metadata(local_git_dir)
        print_metadata_analysis_report(stats)
        if args.max_size is not None:
            disk_size = stats["index"]["total_uncompressed_size"] if stats.get("index") else stats["total_estimated_download"]
            if disk_size > args.max_size:
                printf(
                    "[-] Skipping: estimated size on disk (%s) exceeds --max-size threshold (%s)\n",
                    format_size(disk_size),
                    format_size(args.max_size),
                )
                sys.exit(0)
        if args.estimate_only or not args.directory:
            sys.exit(0)

    # fetch everything
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
    finally:
        if temp_dir_obj is not None:
            temp_dir_obj.cleanup()

    sys.exit(ret)


if __name__ == "__main__":
    main()
