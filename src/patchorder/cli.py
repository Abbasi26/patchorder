"""Command line. Read-only unless --write, --output, or --save-state is passed."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from patchorder import __version__
from patchorder.briefing import render
from patchorder.cache import Cache
from patchorder.csaf import load_csaf_path
from patchorder.engine import live_scan, resolve_inventory, run_demo, utc_now
from patchorder.errors import PatchorderError
from patchorder.httpclient import HttpClient
from patchorder.inventory import load_inventory
from patchorder.lockfile import default_lock_path, dump_lock, dump_state, load_lock, load_state
from patchorder.llm import chat_url, cve_texts, parse_chat_response, preview_json, request_body
from patchorder.models import LockEntry
from patchorder.resolver import format_candidates
from patchorder.sources import ENDPOINTS, CSAF_PROVIDER, LiveFetcher
from patchorder.cpe import canonical_base


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patchorder",
        description=(
            "Which public CVEs apply to the versions in your inventory, and what to patch first. "
            "Read-only unless you pass --write, --output, or --save-state."
        ),
    )
    parser.add_argument("--version", action="version", version=f"patchorder {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="briefing from bundled fixtures, no network")
    _format_args(demo)
    demo.add_argument("--llm-preview", action="store_true", help="print the CVE-text-only LLM body; do not send it")
    demo.set_defaults(func=cmd_demo)

    resolve = sub.add_parser("resolve", help="show CPE candidates and optionally pin them")
    resolve.add_argument("-i", "--inventory", required=True, type=Path)
    resolve.add_argument("-o", "--lock", type=Path, help="lock file to write (default: next to the inventory)")
    resolve.add_argument("--write", action="store_true", help="write the lock file after printing it")
    resolve.add_argument("--accept", action="append", default=[], metavar="ID=CPE", help="pin this CPE (repeatable)")
    resolve.add_argument("--non-interactive", action="store_true")
    resolve.add_argument("--offline", action="store_true")
    resolve.add_argument("--no-discover-cpes", action="store_true", help="use the local alias table only")
    resolve.add_argument("--cache-dir", type=Path, default=Path(".patchorder/cache"))
    resolve.add_argument("--refresh", action="store_true")
    resolve.set_defaults(func=cmd_resolve)

    scan = sub.add_parser("scan", help="match versions and print a briefing")
    scan.add_argument("-i", "--inventory", required=True, type=Path)
    scan.add_argument("-l", "--lock", type=Path)
    _format_args(scan)
    scan.add_argument("--state", type=Path, help="previous state file, for the new-since-last-run section")
    scan.add_argument("--save-state", type=Path, nargs="?", const=Path(".patchorder/state.json"))
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--cache-dir", type=Path, default=Path(".patchorder/cache"))
    scan.add_argument("--refresh", action="store_true")
    scan.add_argument("--pinned-only", action="store_true", help="do not query unpinned CPE guesses")
    scan.add_argument("--no-discover-cpes", action="store_true")
    scan.add_argument(
        "--max-pages",
        type=int,
        default=2,
        help="NVD pages of 2000 CVEs per product version (default 2, oldest first)",
    )
    scan.add_argument("--csaf", type=Path, action="append", default=[], help="CSAF file or directory")
    scan.add_argument("--csaf-provider", action="store_true", help="fetch CERT-Bund provider metadata (URLs only)")
    scan.add_argument("--llm", action="store_true", help="send CVE texts to an OpenAI-compatible endpoint")
    scan.add_argument("--llm-preview", action="store_true", help="print the LLM body and do not send it")
    scan.set_defaults(func=cmd_scan)

    inventory = sub.add_parser("inventory", help="check an inventory or import one from CSV (no network)")
    inv_sub = inventory.add_subparsers(dest="inventory_command", required=True)
    inv_check = inv_sub.add_parser("check", help="lint an inventory and show rows a scan cannot decide")
    inv_check.add_argument("inventory", type=Path)
    inv_check.add_argument("-l", "--lock", type=Path, help="lock file (default: next to the inventory)")
    inv_check.add_argument("--strict", action="store_true", help="exit 4 on warnings too")
    inv_check.set_defaults(func=cmd_inventory_check)
    inv_csv = inv_sub.add_parser("from-csv", help="turn a CSV export into inventory YAML (printed unless --output)")
    inv_csv.add_argument("csv", type=Path)
    inv_csv.add_argument("--name", help="inventory name (default: the CSV file name)")
    inv_csv.add_argument("--owner", default="unassigned", help="owner for rows without one")
    inv_csv.add_argument("--exposure", choices=("internet", "internal"), default="internal", help="exposure for rows without one")
    inv_csv.add_argument("--output", type=Path, help="write the YAML to this file")
    inv_csv.set_defaults(func=cmd_inventory_from_csv)

    sources = sub.add_parser("sources", help="list the public endpoints (no request)")
    sources.set_defaults(func=cmd_sources)
    return parser


def _format_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("md", "html", "json", "csv"), default="md")
    parser.add_argument("--output", type=Path, help="write the briefing to this file")
    parser.add_argument(
        "--fail-on",
        action="append",
        default=[],
        metavar="GATE",
        help="exit 4 when a finding matches: kev, new (needs --state), internet, or priority:N (repeatable)",
    )


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"wrote {output}", file=sys.stderr)


def _client(args) -> HttpClient:
    return HttpClient(Cache(args.cache_dir), offline=args.offline, refresh=args.refresh)


def _render(report, fmt: str) -> str:
    if fmt == "csv":
        from patchorder.csvout import render_csv

        return render_csv(report)
    return render(report, fmt)


def _gates(args):
    from patchorder.gate import parse_gate

    return [parse_gate(item) for item in args.fail_on]


def _apply_gates(report, gates) -> int:
    if not gates:
        return 0
    from patchorder.gate import GATE_EXIT, evaluate_gates

    tripped = evaluate_gates(report, gates)
    for line in tripped:
        print(f"gate: {line}", file=sys.stderr)
    if not tripped:
        print("gate: passed (" + ", ".join(g.label() for g in gates) + ")", file=sys.stderr)
    return GATE_EXIT if tripped else 0


def cmd_demo(args: argparse.Namespace) -> int:
    gates = _gates(args)
    if getattr(args, "llm", False):
        raise PatchorderError(
            "demo mode does not call an LLM endpoint. Use --llm-preview to print the request body."
        )
    report = run_demo()
    if args.llm_preview:
        report.llm_preview = preview_json(cve_texts(report.findings), os.environ.get("PATCHORDER_LLM_MODEL", "unset"))
    _emit(_render(report, args.format), args.output)
    print("patchorder demo: offline, fixtures recorded 2026-10-21", file=sys.stderr)
    return _apply_gates(report, gates)


def _parse_accept(items: list[str]) -> dict[str, LockEntry]:
    accepted: dict[str, LockEntry] = {}
    for item in items:
        if "=" not in item:
            raise PatchorderError(f"--accept must look like id=cpe:2.3:... ({item})")
        asset_id, cpe = item.split("=", 1)
        accepted[asset_id.strip()] = LockEntry(
            cpe=canonical_base(cpe),
            pinned=True,
            origin="user",
            note="Pinned with --accept.",
        )
    return accepted


def cmd_resolve(args: argparse.Namespace) -> int:
    inventory = load_inventory(args.inventory)
    lock_path = args.lock or default_lock_path(args.inventory)
    existing = load_lock(lock_path if lock_path.exists() else None)
    accepted = _parse_accept(args.accept)
    dictionary: dict[str, list[dict]] = {}
    discover = not args.no_discover_cpes and not args.offline
    if discover:
        fetcher = LiveFetcher(_client(args))
        for asset in inventory.assets:
            current = existing.get(asset.id)
            if (current and current.pinned) or asset.id in accepted:
                continue
            try:
                dictionary[asset.id] = fetcher.cpe_hits(asset.product)
            except PatchorderError as exc:
                print(f"warning: {exc}", file=sys.stderr)
    # Accepted pins override existing ones for this preview.
    merged = dict(existing)
    merged.update(accepted)
    resolutions = resolve_inventory(inventory, merged, dictionary)
    interactive = sys.stdin.isatty() and not args.non_interactive
    chosen: dict[str, LockEntry] = {asset_id: entry for asset_id, entry in merged.items() if entry.pinned}
    for resolution in resolutions:
        print(format_candidates(resolution))
        print()
        if resolution.confirmed:
            continue
        if not interactive:
            continue
        if not resolution.candidates:
            answer = input("CPE to pin, or Enter to skip: ").strip()
        else:
            answer = input("Number to pin, a CPE, or Enter to skip: ").strip()
        if not answer:
            continue
        if answer.isdigit():
            index = int(answer)
            if index < 1 or index > len(resolution.candidates):
                print("skipping, that number is not in the list")
                continue
            cpe = resolution.candidates[index - 1].cpe
        else:
            cpe = canonical_base(answer)
        chosen[resolution.asset.id] = LockEntry(cpe=cpe, pinned=True, origin="user", note="Pinned in resolve.")
    text = dump_lock(chosen)
    print(text)
    if not args.write:
        print("not written. Pass --write to save the lock file.", file=sys.stderr)
        return 0
    if not interactive and not args.accept and _needs_a_choice(resolutions, chosen):
        raise PatchorderError(
            "refusing to write a lock file without pins. Pass --accept id=cpe or run resolve in a terminal.",
            code=2,
        )
    if interactive:
        confirm = input(f"Write lock file to {lock_path}? [y/N] ").strip().lower()
        if confirm not in {"y", "yes"}:
            print("not written", file=sys.stderr)
            return 0
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(text, encoding="utf-8")
    print(f"wrote {lock_path}", file=sys.stderr)
    return 0


def _needs_a_choice(resolutions, chosen) -> bool:
    for resolution in resolutions:
        if resolution.asset.id not in chosen and not resolution.confirmed:
            return True
    return False


def cmd_scan(args: argparse.Namespace) -> int:
    if args.llm and args.llm_preview:
        print("--llm-preview is set, so the endpoint is not called.", file=sys.stderr)
        args.llm = False
    gates = _gates(args)
    if any(g.kind == "new" for g in gates) and not args.state:
        raise PatchorderError("--fail-on new needs --state with a previous run's state file", code=2)
    inventory = load_inventory(args.inventory)
    lock_path = args.lock
    if lock_path is None:
        sibling = default_lock_path(args.inventory)
        lock_path = sibling if sibling.exists() else None
    lock = load_lock(lock_path)
    previous = load_state(args.state) if args.state else None
    dictionary: dict[str, list[dict]] = {}
    client = _client(args)
    fetcher = LiveFetcher(client, max_pages=max(1, args.max_pages))
    if not args.no_discover_cpes and not args.offline:
        for asset in inventory.assets:
            entry = lock.get(asset.id)
            if entry and entry.pinned:
                continue
            try:
                dictionary[asset.id] = fetcher.cpe_hits(asset.product)
            except PatchorderError as exc:
                print(f"warning: {exc}", file=sys.stderr)
    resolutions = resolve_inventory(inventory, lock, dictionary)
    advisories = []
    for path in args.csaf:
        advisories.extend(load_csaf_path(path))
    extra = []
    if args.csaf_provider:
        try:
            meta = fetcher.provider_metadata()
            feeds = []
            for dist in meta.get("distributions") or []:
                for feed in (dist.get("rolie") or {}).get("feeds") or []:
                    if feed.get("tlp_label") == "WHITE" and feed.get("url"):
                        feeds.append(feed["url"])
            extra.append("CERT-Bund provider metadata feeds (TLP:WHITE): " + ", ".join(feeds))
        except PatchorderError as exc:
            extra.append(f"CERT-Bund provider metadata was not loaded: {exc}")
    try:
        report = live_scan(
            inventory,
            resolutions,
            fetcher,
            advisories,
            previous,
            pinned_only=args.pinned_only,
            extra_sources=extra,
        )
    except PatchorderError:
        raise
    _maybe_llm(args, report)
    _emit(_render(report, args.format), args.output)
    if args.save_state:
        ids = [finding.cve_id for finding in report.findings]
        args.save_state.parent.mkdir(parents=True, exist_ok=True)
        args.save_state.write_text(dump_state(ids, utc_now()), encoding="utf-8")
        print(f"wrote state {args.save_state} ({len(set(ids))} CVE ids)", file=sys.stderr)
    if args.offline and not report.findings and any("offline mode" in item for item in report.warnings):
        return 3
    return _apply_gates(report, gates)


def _maybe_llm(args, report) -> None:
    texts = cve_texts(report.findings)
    model = os.environ.get("PATCHORDER_LLM_MODEL", "")
    if args.llm_preview:
        report.llm_preview = preview_json(texts, model or "unset")
        return
    if not args.llm:
        return
    base = os.environ.get("PATCHORDER_LLM_BASE_URL", "").strip()
    if not base or not model:
        raise PatchorderError(
            "LLM hook is on, but PATCHORDER_LLM_BASE_URL and PATCHORDER_LLM_MODEL must both be set. "
            "Nothing was sent."
        )
    url = chat_url(base)
    body = json.dumps(request_body(texts, model)).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"patchorder/{__version__} (local; no telemetry)",
    }
    api_key = os.environ.get("PATCHORDER_LLM_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        report.warnings.append(f"LLM summary failed: {exc}")
        return
    report.llm_summary = parse_chat_response(payload)


def cmd_inventory_check(args: argparse.Namespace) -> int:
    from patchorder.inventorytools import check_inventory

    notes = check_inventory(args.inventory, args.lock)
    counts = {"error": 0, "warning": 0, "info": 0}
    for note in notes:
        counts[note.level] += 1
        print(f"{note.level:<7} {note.asset_id}: {note.text}")
    print(f"{args.inventory}: {counts['warning']} warning(s), {counts['info']} note(s)")
    return 4 if args.strict and counts["warning"] else 0


def cmd_inventory_from_csv(args: argparse.Namespace) -> int:
    from patchorder.inventorytools import csv_to_inventory

    try:
        text = args.csv.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise PatchorderError(f"cannot read {args.csv}: {exc}") from exc
    yaml_text = csv_to_inventory(text, args.name or args.csv.stem, args.owner, args.exposure)
    _emit(yaml_text, args.output)
    return 0


def cmd_sources(_args: argparse.Namespace) -> int:
    print("patchorder reads these public endpoints when you scan online. This command does not contact them.")
    print()
    for name, url in ENDPOINTS:
        print(f"{name}")
        print(f"  {url}")
    print()
    print("NVD_API_KEY, when set, is sent only to services.nvd.nist.gov and is not written to the cache.")
    print("The LLM hook is off unless you pass --llm. It posts CVE texts to PATCHORDER_LLM_BASE_URL.")
    print(f"CERT-Bund CSAF documents are read from --csaf. Provider metadata: {CSAF_PROVIDER}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PatchorderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
