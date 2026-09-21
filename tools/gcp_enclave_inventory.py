#!/usr/bin/env python3
"""Match the GCP enclave MIG inventories against production's MIG list.

tools/gcp-enclave-migs.txt lists the gateway regions that serve. The deploy
used to require that file to equal production's MIG list exactly, which left no
supported way to CREATE a region: the rollout is what creates a MIG, and the
inventory check runs before the rollout.

tools/gcp-enclave-migs-pending.txt covers that window. It names a region that
is being bootstrapped, and the only thing it relaxes is existence:

  - every production MIG the listing filter matches must be named by one of
    the two files (an unknown MIG still fails closed);
  - every MAIN inventory MIG must exist (unchanged);
  - a PENDING MIG may be absent, because the first rollout creates it, or
    present, because that rollout got as far as creating it.

The DNS reconciler reads the pending file as well, for the region's OWN hostname
only: it holds and promotes the cold CNAME during the first rollout and then
keeps api-<region> on the attested VMs, but it never puts a pending region in
the canonical answer. The public TLS check reads the main inventory alone. So a
pending region receives no canonical traffic and no certificate-expiry probe
until the commit that moves its line into the main inventory
(docs/runbooks/README.md, "Adding a gateway region").

Both files are bare `region:mig` lines. They are data for several parsers, so
they cannot hold comments; this docstring and the runbook are their
documentation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple, Sequence

MAIN_INVENTORY = Path(__file__).with_name("gcp-enclave-migs.txt")
PENDING_INVENTORY = Path(__file__).with_name("gcp-enclave-migs-pending.txt")

# The serving region's MIG exists (enforced).
MAIN = "main"
# A region being bootstrapped whose MIG already exists.
PENDING = "pending"
# A region being bootstrapped whose MIG the rollout has yet to create.
ABSENT = "absent"

_REGION_RE = re.compile(r"[a-z]+(?:-[a-z]+)+[0-9]+")
# Production is listed with --filter='name~^quill-enclave-mig-'. An inventory
# name outside that filter could never be seen as existing: in the main file it
# would fail every deploy, and in the pending file it would read as absent for
# ever and hide a running MIG from the Stage D transition set.
_MIG_RE = re.compile(r"quill-enclave-mig-[a-z0-9]+(?:-[a-z0-9]+)*")


class InventoryError(ValueError):
    """An inventory or listing file that cannot be trusted as written."""


class Mig(NamedTuple):
    region: str
    name: str

    def __str__(self) -> str:
        return f"{self.region}:{self.name}"


class Comparison(NamedTuple):
    # Why the inventories and production disagree; empty when they agree.
    problems: tuple[str, ...]
    # Every inventory MIG, main first, with MAIN, PENDING or ABSENT.
    rows: tuple[tuple[Mig, str], ...]


def parse_migs(text: str, source: str) -> tuple[Mig, ...]:
    """Parse bare `region:mig` lines. A line that is anything else is an error.

    Skipping a blank or commented line would be friendlier and wrong: the other
    readers of these files (the DNS reconciler, the TLS check, the Stage D
    gate) do not skip, so a line this parser forgave would break them instead.
    """
    migs: list[Mig] = []
    for number, line in enumerate(text.splitlines(), start=1):
        region, separator, name = line.partition(":")
        if (
            not separator
            or not _REGION_RE.fullmatch(region)
            or not _MIG_RE.fullmatch(name)
        ):
            raise InventoryError(
                f"{source}:{number}: expected <region>:quill-enclave-mig-<suffix>, "
                f"got {line!r}"
            )
        migs.append(Mig(region, name))
    return tuple(migs)


def validate_inventories(main: Sequence[Mig], pending: Sequence[Mig]) -> None:
    """Refuse inventories that would make a later step ambiguous or vacuous."""
    if not main:
        # Every rollout loop iterates this list. Empty would not mean "no
        # regions"; it would mean each gate passes without looking at anything.
        raise InventoryError("the main inventory lists no MIG")
    regions: dict[str, Mig] = {}
    names: dict[str, Mig] = {}
    for mig in (*main, *pending):
        # The workflow keys its step outputs and its DNS names by region, and a
        # region in both files would be both "must exist" and "may be absent".
        if mig.region in regions:
            raise InventoryError(
                f"region {mig.region} is listed twice ({regions[mig.region]}, {mig})"
            )
        if mig.name in names:
            raise InventoryError(
                f"MIG {mig.name} is listed twice ({names[mig.name]}, {mig})"
            )
        regions[mig.region] = mig
        names[mig.name] = mig


def compare(
    main: Sequence[Mig],
    pending: Sequence[Mig],
    actual: Sequence[Mig],
) -> Comparison:
    """Classify each inventory MIG against production. Pure: no I/O."""
    validate_inventories(main, pending)
    production = frozenset(actual)
    known = frozenset(main) | frozenset(pending)
    problems = [
        f"production MIG {mig} is in neither inventory"
        for mig in sorted(production - known)
    ]
    problems += [
        f"main inventory MIG {mig} does not exist in production"
        for mig in main
        if mig not in production
    ]
    rows = [(mig, MAIN) for mig in main]
    rows += [(mig, PENDING if mig in production else ABSENT) for mig in pending]
    return Comparison(tuple(problems), tuple(rows))


def mig_for_region(
    main: Sequence[Mig], pending: Sequence[Mig], region: str
) -> Mig | None:
    validate_inventories(main, pending)
    for mig in (*main, *pending):
        if mig.region == region:
            return mig
    return None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        # A missing pending file is not an empty one. Promotion empties the
        # file and leaves it in place, so absence means a broken checkout.
        raise InventoryError(f"cannot read {path}: {exc.strerror}") from exc


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _joined(migs: Sequence[Mig]) -> str:
    return ", ".join(str(mig) for mig in migs) or "<none>"


def main_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--inventory", type=Path, default=MAIN_INVENTORY,
        help="main inventory (default: %(default)s)",
    )
    parser.add_argument(
        "--pending-inventory", type=Path, default=PENDING_INVENTORY,
        help="inventory of regions being bootstrapped (default: %(default)s)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, summary in (
        ("check", "exit 1 unless the inventories and production agree"),
        (
            "list-existing",
            "print region:mig:state for every MIG a rollout may read: all of "
            f"the main inventory ({MAIN}) and the pending MIGs that exist "
            f"({PENDING})",
        ),
        (
            "list-all",
            "list-existing, plus the pending MIGs that do not exist yet "
            f"({ABSENT})",
        ),
    ):
        command = commands.add_parser(name, help=summary)
        command.add_argument(
            "--actual-file", type=Path, required=True,
            help="production's MIGs as region:mig lines",
        )
    lookup = commands.add_parser(
        "mig-for-region", help="print the MIG either inventory lists for a region"
    )
    lookup.add_argument("region")
    args = parser.parse_args(argv)

    try:
        main = parse_migs(_read(args.inventory), _display(args.inventory))
        pending = parse_migs(
            _read(args.pending_inventory), _display(args.pending_inventory)
        )
        if args.command == "mig-for-region":
            mig = mig_for_region(main, pending, args.region)
            if mig is None:
                raise InventoryError(
                    f"no enclave group is listed for {args.region} in "
                    f"{_display(args.inventory)} or "
                    f"{_display(args.pending_inventory)}"
                )
            print(mig.name)
            return 0
        actual = parse_migs(_read(args.actual_file), _display(args.actual_file))
        comparison = compare(main, pending, actual)
    except InventoryError as exc:
        print(f"GCP enclave MIG inventory: {exc}", file=sys.stderr)
        return 1

    if comparison.problems:
        # The listing commands refuse as well, and print nothing: their output
        # feeds `while read` loops, and a partial list would silently narrow
        # what a rollout gate looks at.
        print(
            "configured GCP enclave MIG inventory does not match production",
            file=sys.stderr,
        )
        for problem in comparison.problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"  main inventory: {_joined(main)}", file=sys.stderr)
        print(f"  pending inventory: {_joined(pending)}", file=sys.stderr)
        print(f"  production: {_joined(sorted(set(actual)))}", file=sys.stderr)
        return 1

    if args.command == "check":
        by_state = {
            state: [mig for mig, row_state in comparison.rows if row_state == state]
            for state in (MAIN, PENDING, ABSENT)
        }
        print(
            "GCP enclave MIG inventory matches production: "
            f"main {_joined(by_state[MAIN])}; "
            f"pending and present {_joined(by_state[PENDING])}; "
            f"pending and not created yet {_joined(by_state[ABSENT])}"
        )
        return 0
    for mig, state in comparison.rows:
        if state == ABSENT and args.command == "list-existing":
            continue
        print(f"{mig}:{state}")
    return 0


if __name__ == "__main__":
    sys.exit(main_cli())
