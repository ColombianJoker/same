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

from tqdm import tqdm

# Constants
BAD_ALGORITHM = 255
BLOCK_SIZE = 64 * 1024
PRG_NAME = "same"


class Same:
    def __init__(
        self, verbose: bool = False, debug: bool = False, progress_width: int = 100
    ):
        self.verbose = verbose
        self.hashes = {}
        self.prg_name = PRG_NAME
        self._recursive = False
        self.debug = debug
        self.file_count = 0
        self.progress_width = progress_width
        self._pbar = None
        self._current_line_count = 0

    def recursive(self, recursive: bool = False):
        self._recursive = recursive

    def add_alg(self, algorithm_name: str):
        alg_key = algorithm_name.upper()
        if alg_key not in self.hashes:
            self.hashes[alg_key] = {}

    def algs(self):
        return sorted(list(self.hashes.keys()))

    def _init_pbar(self):
        if self.verbose and not self._pbar:
            self._pbar = tqdm(
                total=self.progress_width,
                unit="file",
                leave=True,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
                ncols=80,
            )

    def walk(self, start_path: Path):
        # Resolve path to handle ~ and relative paths immediately
        try:
            start_path = start_path.expanduser().resolve()
        except (OSError, RuntimeError):
            # Fallback if resolution fails (e.g. permission on parent)
            start_path = start_path.expanduser()

        if not start_path.exists():
            if self.verbose:
                tqdm.write(f"{self.prg_name}: {start_path} does not exist.")
            return

        if start_path.is_file():
            self._process_file(start_path)
        elif start_path.is_dir():
            if self._recursive:
                for root, _, files in os.walk(start_path):
                    for name in files:
                        self._process_file(Path(root) / name)
            else:
                for entry in start_path.iterdir():
                    if entry.is_file():
                        self._process_file(entry)

    def _process_file(self, file_path: Path):
        algs_to_run = self.algs()
        if not algs_to_run:
            return

        # Ensure we are working with an absolute, resolved path for grouping
        full_path = file_path.expanduser().resolve()

        hashers = {alg: hashlib.new(alg.lower()) for alg in algs_to_run}

        try:
            with open(full_path, "rb") as f:
                while True:
                    chunk = f.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    for hasher in hashers.values():
                        hasher.update(chunk)

            self.file_count += 1
            for alg, hasher in hashers.items():
                digest = hasher.hexdigest()
                if digest not in self.hashes[alg]:
                    self.hashes[alg][digest] = []

                # Store the absolute string path
                path_str = str(full_path)
                if path_str not in self.hashes[alg][digest]:
                    self.hashes[alg][digest].append(path_str)

            if self.verbose:
                if not self._pbar:
                    self._init_pbar()
                self._pbar.update(1)
                self._current_line_count += 1
                if self._current_line_count >= self.progress_width:
                    self._pbar.close()
                    self._pbar = None
                    self._current_line_count = 0

        except (PermissionError, OSError) as e:
            if self.verbose:
                tqdm.write(f"{self.prg_name}: Error reading {full_path} - {e}")

    def close_pbar(self):
        if self._pbar:
            self._pbar.close()


def format_duration(seconds: float) -> str:
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
            "--DEBUG",
            dest="DEBUG",
            action="store_true",
            help=SUPPRESS_HELP,
            default=False,
        )

        (Options, Args) = parser.parse_args()

        if len(Args):
            start_ts = time.time()
            if Options.show_time:
                start_str = time.strftime("%Y:%m:%d %H:%M:%S", time.localtime(start_ts))
                print(f"{PRG_NAME}: started at {start_str}", file=sys.stderr)

            scanner = Same(
                verbose=Options.verbose,
                debug=Options.DEBUG,
                progress_width=Options.progress_width,
            )

            requested_algs = [a.strip() for a in Options.modes.split(",") if a.strip()]
            for alg in requested_algs:
                scanner.add_alg(alg)
            scanner.recursive(Options.recursive)

            for arg in Args:
                # Handle ~ and convert to Path object
                scanner.walk(Path(arg))

            scanner.close_pbar()

            # Output Results
            for alg_name in scanner.algs():
                results = scanner.hashes[alg_name]
                if not Options.parsable and results:
                    print(f"\n{alg_name}:")

                for hash_val, file_list in results.items():
                    if Options.duplicated and len(file_list) < 2:
                        continue
                    if Options.parsable:
                        for filename in file_list:
                            print(f"{alg_name}:{hash_val}:{filename}")
                    else:
                        print(f"{hash_val}:")
                        for filename in file_list:
                            print(f"    {filename}")

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

    except KeyboardInterrupt:
        sys.stderr.write(f"\n{PRG_NAME}: cancelled!\n")
        sys.exit(1)
