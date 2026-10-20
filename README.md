# git-dumper

A tool to dump a git repository from a website.

## Install

This can be installed easily with [`uv`](https://docs.astral.sh/uv/):
```bash
uv tool install git-dumper
```

Alternatively, you can install it via pip. Note that modern Python environments may require you to use a virtual environment or the --user flag to avoid conflicts:
```bash
# Using a virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install git-dumper

# OR using the --user flag
pip install --user git-dumper
```

## Usage

```
usage: git-dumper [options] URL DIR

Dump a git repository from a website.

positional arguments:
  URL                   url or local repository path
  DIR                   output directory (required unless using --estimate-only with a local repository)

optional arguments:
  -h, --help            show this help message and exit
  --estimate-only       perform comprehensive metadata-based size analysis (.git/index and pack .idx files) and exit without downloading full repo
  --estimate            display comprehensive size estimate before proceeding with download
  --proxy PROXY         use the specified proxy
  -X METHOD, --method METHOD
                        HTTP method to use for all requests (e.g. GET, POST)
  --any-status          accept any HTTP status code as long as the body is
                        non-empty and not HTML (e.g. targets that return 500
                        but still serve content)
  -j JOBS, --jobs JOBS  number of simultaneous requests
  -r RETRY, --retry RETRY
                        number of request attempts before giving up
  -t TIMEOUT, --timeout TIMEOUT
                        maximum time in seconds before giving up
  -u USER_AGENT, --user-agent USER_AGENT
                        user-agent to use for requests
  -H HEADER, --header HEADER
                        additional http headers, e.g `NAME=VALUE`
  --client-cert-p12 CLIENT_CERT_P12
                        client certificate in PKCS#12 format
  --client-cert-p12-password CLIENT_CERT_P12_PASSWORD
                        password for the client certificate
  -b BRANCH, --branch BRANCH
                        additional branch name to check for (repeatable)
```

### Example

```
git-dumper http://website.com/.git ~/website
```

### Custom arguments

Some targets don't serve the raw `.git` files in the usual way. The following
arguments help with those cases.

#### HTTP Method

Some targets only serve the raw `.git` files over a non-`GET` method. Use
`-X`/`--method` to change the HTTP method used for every request:

```
git-dumper -X POST http://website.com/.git ~/website
```

#### Ignore HTTP status

Some targets respond with a non-200 status (e.g. `500`) while still returning
the real content. Use `--any-status` to accept any status code as long as the
body is non-empty and not HTML:

```
git-dumper --any-status http://website.com/.git ~/website
```

#### Size Estimation & Metadata Analysis

Before downloading full repository objects and large packfiles, git-dumper can inspect the repository metadata (`.git/index`, pack `.idx` files, and refs) to calculate a comprehensive size breakdown (working tree size, pack files size, loose objects needed, and total network transfer size).

To only inspect the size breakdown without downloading full payloads or checking out files:
```
# Against a remote website
git-dumper --estimate-only http://website.com/.git

# Against a local repository directory
git-dumper --estimate-only /path/to/repo
```

To display the size breakdown before proceeding with a normal download:
```
git-dumper --estimate http://website.com/.git ~/website
```


### Disclaimer

**Use this software at your own risk!**

You should know that if the repository you are downloading is controlled by an attacker,
this could lead to remote code execution on your machine.

## Build from source

Simply install the dependencies with pip:
```
pip install -r requirements.txt
```

Then, simply use:
```
./git_dumper.py http://website.com/.git ~/website
```

## How does it work?

The tool will first check if directory listing is available. If it is, then it will just recursively download the .git directory (what you would do with `wget`).

If directory listing is not available, it will use several methods to find as many files as possible. Step by step, git-dumper will:
* Fetch all common files (`.gitignore`, `.git/HEAD`, `.git/index`, etc.);
* Find as many refs as possible (such as `refs/heads/master`, `refs/remotes/origin/HEAD`, etc.) by analyzing `.git/HEAD`, `.git/logs/HEAD`, `.git/config`, `.git/packed-refs` and so on;
* Find as many objects (sha1) as possible by analyzing `.git/packed-refs`, `.git/index`, `.git/refs/*` and `.git/logs/*`;
* Fetch all objects recursively, analyzing each commits to find their parents;
* Run `git checkout .` to recover the current working tree
