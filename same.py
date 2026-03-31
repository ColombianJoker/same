#!/usr/bin/env uv run
# /// script
# dependencies = [
#     "xattr",
# ]
# ///

import hashlib  # Moved to top for consistency
import os
import string
import sys
import time
from datetime import datetime
from optparse import SUPPRESS_HELP, OptionParser
from pathlib import Path

import xattr

BAD_ALGORITHM = 255
BLOCK_SIZE = 64 * 1024


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
        self.debug = debug
        if debug:
            print(f"Same( '{path}' ) created.", file=sys.stderr)

    def add_alg(self, algorithm_name: str):
        """
        Adds an algorithm and prepares the nested dictionary for hash mapping
        """
        alg_key = algorithm_name.upper()
        if alg_key not in self.hashes:
            self.hashes[alg_key] = {}
            if self.debug:
                print(f"{alg_key} added", file=sys.stderr)

    def algs(self):
        """
        Gets the list of algorithms selected
        """
        return sorted(list(self.hashes.keys()))


def available_algorithms():
    """
    Simply returns the available algorithms from hashlib library
    """
    return hashlib.algorithms_available


def print_available(prg_name: str, verbose: bool = False):
    """
    Simply prints the list of available algorithms
    """
    if verbose:
        print(f"{prg_name}: Algorithms available:")
        for alg in sorted(list(available_algorithms())):
            print(f"  {alg.upper()}")


def calc_hash(prg_name: str, crypto: str, filename: Path) -> str:
    """
    Returns the hash of a file by the selected crypto algorithm

    Args:
        prg_name: a string used for messages only
        crypto: a (lowercase) string with the name of the desired hash algorithm
        filename: the path to a file
    """
    try:
        h = hashlib.new(crypto)
    except ValueError:
        # Fixed f-string formatting here
        sys.stderr.write(f'{prg_name}: unsupported hash crypto algorithm "{crypto}"!\n')
        sys.stderr.write(f"{prg_name}: EXITING...!\n")
        sys.stderr.flush()
        sys.exit(BAD_ALGORITHM)

    with open(filename, "rb") as a_file:
        while True:
            buff = a_file.read(BLOCK_SIZE)
            if not buff:
                break
            h.update(buff)
    return h.hexdigest()


# MAIN
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

    (Options, Args) = parser.parse_args()

    Options.prg_name = "same"
    Options.start_time = time.time()

    if Options.available:
        print_available(Options.prg_name, Options.verbose)
        sys.exit(0)

    if Options.verbose:
        start_time = time.localtime(Options.start_time)
        print(
            f"{Options.prg_name}: started at {start_time[0]:04d}/{start_time[1]:02d}/{start_time[2]:02d} {start_time[3]:02d}:{start_time[4]:02d}:{start_time[5]:02d}",
            file=sys.stderr,
        )

    if len(Args):
        # Process the --mode list
        requested_algs = []
        if Options.modes:
            requested_algs = [a.strip() for a in Options.modes.split(",") if a.strip()]

        MasterList = []
        for arg in Args:
            s_obj = Same(Path(arg), verbose=Options.verbose, debug=Options.DEBUG)

            # Add each requested algorithm to the instance
            for alg in requested_algs:
                s_obj.add_alg(alg)

            MasterList.append(s_obj)
            if Options.DEBUG:
                print(f"{Options.prg_name}: {arg}, {s_obj.algs()}", file=sys.stderr)

except KeyboardInterrupt:
    sys.stderr.write(f"\n{Options.prg_name}: cancelled!\n")
    sys.stderr.flush()
