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


class Same:
    def __init__(
        self,
        verbose=False,
        debug=False,
        progress_width=100,
        use_xattr=False,
        store_xattr=False,
        force_xattr=False,
        check_date=False,
    ):
        self.verbose = verbose
        self.debug = debug
        self.hashes = {}
        self.prg_name = PRG_NAME
        self._recursive = False
        self.file_count = 0
        self.progress_width = progress_width
        self._pbar = None
        self._current_line_count = 0

        self.use_xattr = use_xattr or store_xattr or force_xattr
        self.store_xattr = store_xattr or force_xattr
        self.force_xattr = force_xattr
        self.check_date = check_date

    def recursive(self, recursive=False):
        self._recursive = recursive

    def add_alg(self, algorithm_name):
        alg_key = algorithm_name.upper()
        if alg_key not in self.hashes:
            self.hashes[alg_key] = {}

    def algs(self):
        return sorted(list(self.hashes.keys()))

    def _init_pbar(self):
        """Starts a new progress bar segment with dynamic width based on debug mode."""
        if self.verbose and not self._pbar:
            segment_total = self.file_count + self.progress_width

            if self.debug:
                # Original layout: 40-char description + 50-char bar
                bar_width = 50
                fmt = "{desc:<40} |{bar:50}| {n_fmt}/{total_fmt}"
                total_ncols = 120
            else:
                # Duplicated width: No description + 100-char bar
                bar_width = 100
                fmt = "|{bar:100}| {n_fmt}/{total_fmt}"
                total_ncols = 120  # Keeping ncols consistent for terminal fit

            self._pbar = tqdm(
                initial=self.file_count,
                total=segment_total,
                unit="file",
                leave=True,
                ncols=total_ncols,
                bar_format=fmt,
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
                for root, _, files in os.walk(resolved_path):
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
        algs_to_run = self.algs()
        if not algs_to_run:
            return

        full_path = file_path.expanduser().resolve()

        # Get file modification time if date checking is enabled
        current_mtime = full_path.stat().st_mtime if self.check_date else 0

        if self.verbose:
            if not self._pbar:
                self._init_pbar()
            if self.debug:
                fname = full_path.name
                display_name = (fname[:27] + "..") if len(fname) > 30 else fname
                self._pbar.set_description(f"{display_name}")

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
                        # If date xattr is missing or older than file, it's stale
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

        if self.verbose:
            self._pbar.update(1)
            self._current_line_count += 1
            if self._current_line_count >= self.progress_width:
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
            "-v", "--verbose", dest="verbose", action="store_true", default=False
        )
        parser.add_option("-M", "--mode", dest="modes", action="store", default="")
        parser.add_option(
            "-r", "--recursive", dest="recursive", action="store_true", default=False
        )
        parser.add_option(
            "-t", "--show-time", dest="show_time", action="store_true", default=False
        )
        parser.add_option("-d", "--duplicated", action="store_true", default=False)
        parser.add_option("-p", "--parsable", action="store_true", default=False)
        parser.add_option(
            "-w", "--progress-width", dest="progress_width", type="int", default=100
        )
        parser.add_option(
            "-x", "--xattr", dest="xattr", action="store_true", default=False
        )
        parser.add_option(
            "-X",
            "--store-xattr",
            dest="store_xattr",
            action="store_true",
            default=False,
        )
        parser.add_option(
            "-y",
            "-Y",
            "--always-recreate-xattr",
            dest="force_xattr",
            action="store_true",
            default=False,
        )
        parser.add_option(
            "-D",
            "--date-xattr",
            dest="check_date",
            action="store_true",
            default=False,
            help="Check if file was modified since hash was stored",
        )
        parser.add_option(
            "--DEBUG",
            dest="DEBUG",
            action="store_true",
            help=SUPPRESS_HELP,
            default=False,
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
                progress_width=Options.progress_width,
                use_xattr=Options.xattr,
                store_xattr=Options.store_xattr,
                force_xattr=Options.force_xattr,
                check_date=Options.check_date,
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
