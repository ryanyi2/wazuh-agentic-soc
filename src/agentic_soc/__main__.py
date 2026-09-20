"""Command-line entry point.

Usage:
    python -m agentic_soc --version
"""

import argparse

from agentic_soc import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentic-soc")
    parser.add_argument(
        "--version",
        action="version",
        version=f"agentic-soc {__version__}",
    )
    parser.parse_args()


if __name__ == "__main__":
    main()
