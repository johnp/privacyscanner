import hashlib
import os
import errno
import fcntl
import re
import tarfile

import time
from base64 import b32encode
from contextlib import suppress
from urllib.request import Request, urlopen
from os.path import abspath, realpath, dirname, join as joinpath

import psutil


FAKE_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'


class DownloadVerificationFailed(Exception):
    pass


class NumericLock:
    def __init__(self, lock_dir):
        self.lock_dir = lock_dir
        self._lock_file = None

    def __enter__(self):
        i = 0
        while True:
            try:
                f = (self.lock_dir / ('%d.lock' % i)).open('wb')
                fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._lock_file = f
                return i
            except OSError as e:
                if e.errno in (errno.EACCES, errno.EAGAIN):
                    i += 1
                    continue
                raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.lockf(self._lock_file.fileno(), fcntl.LOCK_UN)
        self._lock_file.close()
        os.unlink(self._lock_file.name)


# From stackoverflow with adaptations.
# https://stackoverflow.com/questions/10060069
# ref: https://bugs.python.org/issue21109
# process_members can be used to filter and re-map TarInfo members by, e.g.,
# stripping parts of the member.name or even just using the basename.
# TODO: use pathlib Path
def extract_tar(fileobj, target_dir, process_members=None):
    def resolved(path):
        return realpath(abspath(path))

    def badpath(path, base):
        # joinpath will ignore base if path is absolute
        return not resolved(joinpath(base, path)).startswith(base)

    def badlink(info, base):
        # Links are interpreted relative to the directory containing the link
        tip = resolved(joinpath(base, dirname(info.name)))
        return badpath(info.linkname, base=tip)

    def safemembers(members):
        base = resolved('.')

        for finfo in members:
            if badpath(finfo.name, base):
                raise TarExtractSecurityException("{} is blocked (illegal path)".format(finfo.name))
            elif finfo.issym() and badlink(finfo, base):
                raise TarExtractSecurityException("{} is blocked: Hard link to {}".format(finfo.name, finfo.linkname))
            elif finfo.islnk() and badlink(finfo, base):
                raise TarExtractSecurityException("{} is blocked: Symlink to {}".format(finfo.name, finfo.linkname))
            else:
                yield finfo

    with tarfile.open(fileobj=fileobj) as archive:
        tar_members = safemembers(archive)
        if process_members:
            tar_members = process_members(tar_members)
        archive.extractall(path=target_dir, members=tar_members)


class TarExtractSecurityException(Exception):
    pass


def download_file(url, fileobj, verify_hash=None):
    request = Request(url)
    request.add_header('User-Agent', FAKE_UA)
    response = urlopen(request)
    hasher = hashlib.sha256() if verify_hash else None
    copy_to(response, fileobj, hasher)
    fileobj.flush()
    if verify_hash and hasher.hexdigest() != verify_hash:
        msg = 'SHA256({!r}) does not match {}.'.format(url, verify_hash)
        raise DownloadVerificationFailed(msg)


def copy_to(src, dest, hasher=None):
    while True:
        data = src.read(8192)
        if not data:
            break
        dest.write(data)
        if hasher:
            hasher.update(data)


def file_is_outdated(path, max_age):
    try:
        return path.stat().st_mtime + max_age < time.time()
    except FileNotFoundError:
        return True


def set_default_options(target, defaults):
    for key, value in defaults.items():
        if key in target:
            new_target = target[key]
            if isinstance(new_target, dict):
                set_default_options(new_target, value)
        else:
            target[key] = value


def rand_str(length):
    rand_bits = os.urandom((length * 5 // 8) + 1)
    return b32encode(rand_bits).decode()[:length].lower()


def calculate_jaccard_index(a: bytes, b: bytes) -> float:
    """Calculate the jaccard similarity of a and b."""
    pattern = re.compile(rb'[ \n]')
    # remove tokens containing / to prevent wrong classifications for
    # absolute paths
    a = {token for token in pattern.split(a) if b'/' not in token}
    b = {token for token in pattern.split(b) if b'/' not in token}
    intersection = a.intersection(b)
    union = a.union(b)
    return len(intersection) / len(union)


def kill_everything(pid, timeout=3, only_children=False):
    # First, we take care of the children.
    procs = psutil.Process(pid).children()
    # Suspend first before sending SIGTERM to avoid thundering herd problems
    for p in procs:
        with suppress(psutil.NoSuchProcess):
            p.suspend()
    # Be nice. Ask them first to terminate, before we kill them.
    for p in procs:
        with suppress(psutil.NoSuchProcess):
            p.terminate()
    # This delivers the SIGTERM right after resuming, so no chance to
    # terminate by broken pipes etc. first.
    for p in procs:
        with suppress(psutil.NoSuchProcess):
            p.resume()
    gone, alive = psutil.wait_procs(procs, timeout=timeout)
    # They are still alive. Kill'em all. No mercy anymore.
    if alive:
        for p in alive:
            with suppress(psutil.NoSuchProcess):
                p.kill()
        psutil.wait_procs(alive, timeout=timeout)
    if not only_children:
        # Time for pid to go ...
        with suppress(psutil.NoSuchProcess):
            p = psutil.Process(pid)
            p.terminate()
            with suppress(psutil.TimeoutExpired):
                p.wait(timeout)
            if p.is_running():
                p.kill()
                with suppress(psutil.TimeoutExpired):
                    p.wait(timeout)
