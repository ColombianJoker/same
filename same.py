#!/usr/bin/env uv run
# /// script
# dependencies = [
#     "xattr",
# ]
# ///

import hashlib
import os
import sys
import time
from optparse import SUPPRESS_HELP, OptionParser
from pathlib import Path

# Constants
BAD_ALGORITHM = 255
BLOCK_SIZE = 64 * 1024
PRG_NAME = "same"


class Same:
    """
    Class that walks a directory and calculates (and stores)
    hashes for all files found in the starting directory trees
    """

    def __init__(self, path: Path, verbose: bool = False, debug: bool = False):
        self.path = path
        self.verbose = verbose
        # Structure: { "SHA512": { "hash_value": ["file1", "file2"] } }
        self.hashes = {}
        self.prg_name = PRG_NAME
        self._recursive = False
        self.debug = debug
        if debug:
            print(f"Same( '{path}' ) created.", file=sys.stderr)

    def name(self, prg_name: str):
        """Stores the program name"""
        self.prg_name = prg_name

    def recursive(self, recursive: bool = False):
        """Sets the recursive mode"""
        self._recursive = recursive

    def add_alg(self, algorithm_name: str):
        """Adds an algorithm and prepares the nested dictionary"""
        alg_key = algorithm_name.upper()
        if alg_key not in self.hashes:
            self.hashes[alg_key] = {}
            if self.debug:
                print(f"{alg_key} added", file=sys.stderr)

    def algs(self):
        """Gets the list of algorithms selected"""
        return sorted(list(self.hashes.keys()))

    def walk(self):
        """
        Walks object, calculating hashes and storing them in the right list.
        Handles both single files and directories (optionally recursive).
        """
        if not self.path.exists():
            if self.verbose:
                print(f"{self.prg_name}: {self.path} does not exist.", file=sys.stderr)
            return

        if self.path.is_file():
            self._process_file(self.path)
        elif self.path.is_dir():
            if self._recursive:
                # Use os.walk for deep recursion
                for root, _, files in os.walk(self.path):
                    for name in files:
                        self._process_file(Path(root) / name)
            else:
                # Process only files in the immediate directory
                for entry in self.path.iterdir():
                    if entry.is_file():
                        self._process_file(entry)

    def _process_file(self, file_path: Path):
        """
        Reads a file once and updates all registered hash algorithms in parallel.
        This optimizes Disk I/O.
        """
        algs_to_run = self.algs()
        if not algs_to_run:
            return

        # Initialize hasher objects for each requested algorithm
        hashers = {}
        for alg in algs_to_run:
            try:
                hashers[alg] = hashlib.new(alg.lower())
            except ValueError:
                if self.verbose:
                    print(
                        f"{self.prg_name}: Unsupported algorithm {alg}", file=sys.stderr
                    )

        # Read file block by block, updating all hashers at once
        try:
            with open(file_path, "rb") as f:
                if self.debug:
                    print(
                        f"{self.prg_name}: processing '{file_path}'...", file=sys.stderr
                    )
                while True:
                    chunk = f.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    for hasher in hashers.values():
                        hasher.update(chunk)

            # Extract final digests and store them in the hash dictionary
            for alg, hasher in hashers.items():
                digest = hasher.hexdigest()
                if digest not in self.hashes[alg]:
                    self.hashes[alg][digest] = []
                self.hashes[alg][digest].append(str(file_path))
                if self.debug:
                    print(f"  {alg}={digest}", file=sys.stderr)

        except (PermissionError, OSError) as e:
            if self.verbose:
                print(
                    f"{self.prg_name}: Error reading {file_path} - {e}", file=sys.stderr
                )


def available_algorithms():
    """Returns available algorithms from hashlib library"""
    return hashlib.algorithms_available


def print_available(prg_name: str, verbose: bool = False):
    """Prints the list of available algorithms"""
    if verbose:
        print(f"{prg_name}: Algorithms available:")
        for alg in sorted(list(available_algorithms())):
            print(f"  {alg.upper()}")


# MAIN
if __name__ == "__main__":
    try:
        parser = OptionParser(usage="%prog [ --OPTIONS ] DIR ... FILE ...")
        parser.add_option(
            "-v",
            "--verbose",
            dest="verbose",
            action="store_true",
            help="Verbose mode",
            default=False,
        )
        parser.add_option(
            "-M",
            "--mode",
            dest="modes",
            action="store",
            help="Comma separated list of algorithms (e.g. SHA512,MD5)",
            default="",
        )
        parser.add_option(
            "-r",
            "--recursive",
            "--recurse",
            dest="recursive",
            action="store_true",
            help="Recurse into directories",
            default=False,
        )
        parser.add_option(
            "--available",
            dest="available",
            action="store_true",
            help="Lists available algorithms only",
            default=False,
        )
        parser.add_option(
            "--DEBUG",
            dest="DEBUG",
            action="store_true",
            help=SUPPRESS_HELP,
            default=False,
        )
        parser.add_option(
            "-d",
            "--duplicated",
            action="store_true",
            help="Show files with the same hash",
            default=False,
        )

        (Options, Args) = parser.parse_args()
        Options.prg_name = PRG_NAME
        Options.start_time = time.time()

        if Options.available:
            print_available(Options.prg_name, Options.verbose)
            sys.exit(0)

        if Options.verbose:
            st = time.localtime(Options.start_time)
            print(
                f"{Options.prg_name}: started at {st[0]:04d}/{st[1]:02d}/{st[2]:02d} "
                f"{st[3]:02d}:{st[4]:02d}:{st[5]:02d}",
                file=sys.stderr,
            )

        if len(Args):
            # Parse requested algorithms
            requested_algs = [a.strip() for a in Options.modes.split(",") if a.strip()]

            MasterList = []
            for arg in Args:
                s_obj = Same(Path(arg), verbose=Options.verbose, debug=Options.DEBUG)

                # Add algorithms and set recursion
                for alg in requested_algs:
                    s_obj.add_alg(alg)
                s_obj.recursive(Options.recursive)

                # Process the path
                s_obj.walk()
                MasterList.append(s_obj)

                if Options.DEBUG:
                    print(
                        f"{Options.prg_name}: Processed {arg} with {s_obj.algs()}",
                        file=sys.stderr,
                    )

    except KeyboardInterrupt:
        sys.stderr.write(f"\n{PRG_NAME}: cancelled!\n")
        sys.stderr.flush()
