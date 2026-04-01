#!/usr/bin/env uv run
# /// script
# dependencies = [
#     "xattr",
#     "tqdm",
# ]
# ///

import hashlib
import os
import sys
import time
from optparse import SUPPRESS_HELP, OptionParser
from pathlib import Path

import xattr
from tqdm import tqdm

# Constants
BLOCK_SIZE = 64 * 1024
PRG_NAME = "same"
SKIP_FILES = {".DS_Store", "Icon\r"}


class Same:
    def __init__(
        self,
        verbose=False,
        debug=False,
        progress_bar_count=100,
        use_xattr=False,
        store_xattr=False,
        force_xattr=False,
        check_date=False,
        enter_git=False,
    ):
        self.verbose = verbose
        self.debug = debug
        self.hashes = {}
        self.prg_name = PRG_NAME
        self._recursive = False
        self.file_count = 0
        self.progress_bar_count = progress_bar_count
        self._pbar = None
        self._current_line_count = 0

        self.use_xattr = use_xattr or store_xattr or force_xattr
        self.store_xattr = store_xattr or force_xattr
        self.force_xattr = force_xattr
        self.check_date = check_date
        self.enter_git = enter_git

    def recursive(self, recursive=False):
        self._recursive = recursive

    def add_alg(self, algorithm_name):
        alg_key = algorithm_name.upper()
        if alg_key not in self.hashes:
            self.hashes[alg_key] = {}

    def algs(self):
        return sorted(list(self.hashes.keys()))

    def _init_pbar(self):
        if self.verbose and not self._pbar:
            goal_text = self.file_count + self.progress_bar_count

            if self.debug:
                # {total_info} is a custom placeholder we fill manually to avoid commas
                fmt = "{desc:<40} |{bar:50}| {total_info}"
                ncols = 120
            else:
                fmt = "|{bar:100}| {total_info}"
                ncols = 125

            self._pbar_base_fmt = fmt
            initial_counter = f"{self.file_count}/{goal_text}"

            self._pbar = tqdm(
                initial=0,
                total=self.progress_bar_count,
                unit="file",
                leave=True,
                ncols=ncols,
                bar_format=self._pbar_base_fmt.replace("{total_info}", initial_counter),
            )

    def walk(self, start_path: Path):
        try:
            resolved_path = start_path.expanduser().resolve()
        except (OSError, RuntimeError):
            resolved_path = start_path.expanduser()

        if not resolved_path.exists():
            if self.verbose:
                tqdm.write(f"{self.prg_name}: {resolved_path} does not exist.")
            return

        if resolved_path.is_file():
            self._process_file(resolved_path)
        elif resolved_path.is_dir():
            if self._recursive:
                for root, dirs, files in os.walk(resolved_path):
                    if not self.enter_git and ".git" in dirs:
                        dirs.remove(".git")
                    for name in files:
                        self._process_file(Path(root) / name)
            else:
                for entry in resolved_path.iterdir():
                    if entry.is_file():
                        self._process_file(entry)

    def _get_xattr(self, file_path, alg, suffix="hash"):
        attr_name = f"user.{self.prg_name}-{suffix}.{alg.lower()}"
        try:
            val = xattr.getxattr(str(file_path), attr_name)
            return val.decode("utf-8")
        except (IOError, OSError):
            return None

    def _set_xattr(self, file_path, alg, value, suffix="hash"):
        attr_name = f"user.{self.prg_name}-{suffix}.{alg.lower()}"
        try:
            xattr.setxattr(str(file_path), attr_name, str(value).encode("utf-8"))
        except (IOError, OSError) as e:
            if self.debug:
                tqdm.write(f"Debug: Failed to write {suffix} xattr to {file_path}: {e}")

    def _process_file(self, file_path: Path):
        if file_path.name in SKIP_FILES:
            return

        try:
            file_stat = file_path.stat()
            if file_stat.st_size == 0:
                return
            current_mtime = file_stat.st_mtime if self.check_date else 0
        except (OSError, PermissionError):
            return

        algs_to_run = self.algs()
        if not algs_to_run:
            return

        full_path = file_path.expanduser().resolve()

        # Initialize Bar if needed
        if self.verbose and not self._pbar:
            self._init_pbar()

        if self.verbose and self.debug:
            fname = full_path.name
            display_name = (fname[:37] + "..") if len(fname) > 39 else fname
            self._pbar.set_description(display_name)

        digests = {}
        needed_algs = []

        for alg in algs_to_run:
            cached_hash = None
            is_stale = False
            if self.use_xattr and not self.force_xattr:
                cached_hash = self._get_xattr(full_path, alg, "hash")
                if self.check_date and cached_hash:
                    cached_date_str = self._get_xattr(full_path, alg, "hash-date")
                    try:
                        if (
                            not cached_date_str
                            or float(cached_date_str) < current_mtime
                        ):
                            is_stale = True
                    except ValueError:
                        is_stale = True

            if cached_hash and not is_stale:
                digests[alg] = cached_hash
            else:
                needed_algs.append(alg)

        if needed_algs:
            hashers = {alg: hashlib.new(alg.lower()) for alg in needed_algs}
            try:
                with open(full_path, "rb") as f:
                    while True:
                        chunk = f.read(BLOCK_SIZE)
                        if not chunk:
                            break
                        for hasher in hashers.values():
                            hasher.update(chunk)
                for alg, hasher in hashers.items():
                    digest = hasher.hexdigest()
                    digests[alg] = digest
                    if self.store_xattr:
                        self._set_xattr(full_path, alg, digest, "hash")
                        if self.check_date:
                            self._set_xattr(full_path, alg, current_mtime, "hash-date")
            except (PermissionError, OSError) as e:
                if self.verbose:
                    tqdm.write(f"{self.prg_name}: Error reading {full_path} - {e}")
                return

        self.file_count += 1
        for alg, digest in digests.items():
            if digest not in self.hashes[alg]:
                self.hashes[alg][digest] = []
            path_str = str(full_path)
            if path_str not in self.hashes[alg][digest]:
                self.hashes[alg][digest].append(path_str)

        # Unified Progress bar update
        if self.verbose:
            self._current_line_count += 1
            self._pbar.update(1)

            goal_text = (
                self.file_count - self._current_line_count
            ) + self.progress_bar_count
            counter_str = f"{self.file_count:>5}/{goal_text:>5}"

            # Manual format update to bypass the comma
            self._pbar.bar_format = self._pbar_base_fmt.replace(
                "{total_info}", counter_str
            )

            if self._current_line_count >= self.progress_bar_count:
                self._pbar.close()
                self._pbar = None
                self._current_line_count = 0

    def close_pbar(self):
        if self._pbar:
            self._pbar.close()


def format_duration(seconds):
    h, m, s = int(seconds // 3600), int((seconds % 3600) // 60), int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


if __name__ == "__main__":
    try:
        parser = OptionParser(usage="%prog [ --OPTIONS ] DIR ... FILE ...")
        parser.add_option(
            "-v",
            "--verbose",
            dest="verbose",
            action="store_true",
            default=False,
            help="Enable verbose output",
        )
        parser.add_option(
            "-M",
            "--mode",
            dest="modes",
            action="store",
            default="",
            help="Algorithms (e.g., SHA512,MD5)",
        )
        parser.add_option(
            "-r",
            "--recursive",
            dest="recursive",
            action="store_true",
            default=False,
            help="Recurse into directories",
        )
        parser.add_option(
            "-t",
            "--show-time",
            dest="show_time",
            action="store_true",
            default=False,
            help="Show timing info",
        )
        parser.add_option(
            "-d",
            "--duplicated",
            dest="duplicated",
            action="store_true",
            default=False,
            help="Only show duplicates",
        )
        parser.add_option(
            "-p",
            "--parsable",
            dest="parsable",
            action="store_true",
            default=False,
            help="Machine-parsable format",
        )
        parser.add_option(
            "-w",
            "--progress-bar-count",
            dest="progress_bar_count",
            type="int",
            default=100,
            help=SUPPRESS_HELP,
        )
        parser.add_option(
            "-x",
            "--xattr",
            dest="xattr",
            action="store_true",
            default=False,
            help="Read xattrs",
        )
        parser.add_option(
            "-X",
            "--store-xattr",
            dest="store_xattr",
            action="store_true",
            default=False,
            help="Read/Write xattrs",
        )
        parser.add_option(
            "-y",
            "-Y",
            "--always-recreate-xattr",
            dest="force_xattr",
            action="store_true",
            default=False,
            help="Force re-hash",
        )
        parser.add_option(
            "-D",
            "--date-xattr",
            dest="check_date",
            action="store_true",
            default=False,
            help="Check file mtime",
        )
        parser.add_option(
            "--enter-git",
            dest="enter_git",
            action="store_true",
            default=False,
            help="Recurse into .git",
        )
        parser.add_option(
            "--DEBUG",
            dest="DEBUG",
            action="store_true",
            default=False,
            help=SUPPRESS_HELP,
        )

        (Options, Args) = parser.parse_args()

        if Args:
            start_ts = time.time()
            if Options.show_time:
                start_str = time.strftime("%Y:%m:%d %H:%M:%S", time.localtime(start_ts))
                print(f"{PRG_NAME}: started at {start_str}", file=sys.stderr)

            scanner = Same(
                verbose=Options.verbose,
                debug=Options.DEBUG,
                progress_bar_count=Options.progress_bar_count,
                use_xattr=Options.xattr,
                store_xattr=Options.store_xattr,
                force_xattr=Options.force_xattr,
                check_date=Options.check_date,
                enter_git=Options.enter_git,
            )

            requested_algs = [a.strip() for a in Options.modes.split(",") if a.strip()]
            for alg in requested_algs:
                scanner.add_alg(alg)
            scanner.recursive(Options.recursive)

            for arg in Args:
                scanner.walk(Path(arg))

            scanner.close_pbar()

            for alg_name in scanner.algs():
                results = scanner.hashes[alg_name]
                if not Options.parsable and results:
                    print(f"\n{alg_name}:")
                for hash_val, file_list in results.items():
                    if Options.duplicated and len(file_list) < 2:
                        continue
                    if Options.parsable:
                        for f_name in file_list:
                            print(f"{alg_name}:{hash_val}:{f_name}")
                    else:
                        print(f"{hash_val}:")
                        for f_name in file_list:
                            print(f"    {f_name}")

            if Options.show_time:
                end_ts = time.time()
                duration = end_ts - start_ts
                sec_per_file = (
                    duration / scanner.file_count if scanner.file_count > 0 else 0.0
                )
                print(
                    f"{PRG_NAME}: ended at {time.strftime('%Y:%m:%d %H:%M:%S', time.localtime(end_ts))}",
                    file=sys.stderr,
                )
                print(
                    f"{PRG_NAME}: took {format_duration(duration)} ({sec_per_file:.3f} sec/file)",
                    file=sys.stderr,
                )
        else:
            parser.print_help()

    except KeyboardInterrupt:
        sys.stderr.write(f"\n{PRG_NAME}: cancelled!\n")
        sys.exit(1)
