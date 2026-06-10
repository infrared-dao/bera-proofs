#!/usr/bin/env python3
"""Probe a Berachain consensus-layer (beacon) RPC endpoint for the exact API
surface bera-proofs depends on.

bera-proofs (src/bera_proofs/api/beacon_client.py) hits three CL paths:

  GET /eth/v1/beacon/headers/head          -> health_check()
  GET /eth/v1/beacon/headers/{slot}        -> get_beacon_header() / get_historical_roots(current-8)
  GET /eth/v2/debug/beacon/states/{slot}   -> get_beacon_state()   (FULL state; the make-or-break call)

This harness exercises all three against a candidate endpoint so you can decide
whether it can replace the current CL node, WITHOUT touching bera-proofs config.
The debug beacon-state endpoint is the one providers most often fail to expose.

Usage:
  # endpoint via env (keeps the token out of shell history / process args):
  export CL_RPC_URL='https://host.example/<token>'
  ./scripts/probe_cl_endpoint.py

  # or positional / flag:
  ./scripts/probe_cl_endpoint.py https://host.example/<token>
  ./scripts/probe_cl_endpoint.py --endpoint "$CL_RPC_URL" --slots-back 8 --historical-state

  # compare two endpoints' state shape without installing anything:
  ./scripts/probe_cl_endpoint.py --dump-shape > a.shape   # endpoint A (via CL_RPC_URL)
  ./scripts/probe_cl_endpoint.py --dump-shape > b.shape   # endpoint B
  diff a.shape b.shape

Env vars checked (first set wins): CL_RPC_URL, BEACON_RPC_URL_MAINNET, BEACON_RPC_URL.
Exit code 0 iff all REQUIRED checks pass (head header, historical header, head state).
The token is never printed: only scheme://host is shown.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ENV_VARS = ("CL_RPC_URL", "BEACON_RPC_URL_MAINNET", "BEACON_RPC_URL")


def redact(url: str) -> str:
    """scheme://host  (path/token stripped) so secrets never hit the output."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}/<redacted>" if p.scheme else "<invalid-url>"


def fetch(url: str, timeout: float, max_parse_mb: float):
    """GET url. Returns dict: status, ms, bytes, ctype, json (or None), error."""
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            ms = (time.monotonic() - start) * 1000
            ctype = resp.headers.get("Content-Type", "")
            parsed, perr = None, None
            if len(body) <= max_parse_mb * 1024 * 1024:
                try:
                    parsed = json.loads(body)
                except Exception as e:  # noqa: BLE001
                    perr = f"non-JSON body ({e})"
            else:
                perr = f"body {len(body)/1e6:.1f}MB > --max-parse-mb; skipped parse"
            return dict(status=resp.status, ms=ms, bytes=len(body), ctype=ctype,
                        json=parsed, error=perr)
    except urllib.error.HTTPError as e:
        ms = (time.monotonic() - start) * 1000
        snippet = (e.read()[:160] or b"").decode("utf-8", "replace").replace("\n", " ")
        return dict(status=e.code, ms=ms, bytes=0, ctype="", json=None,
                    error=f"HTTP {e.code}: {snippet}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        ms = (time.monotonic() - start) * 1000
        return dict(status=None, ms=ms, bytes=0, ctype="", json=None, error=str(e))


def header_slot(j) -> int | None:
    try:
        return int(j["data"]["header"]["message"]["slot"])
    except Exception:  # noqa: BLE001
        return None


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024
    return f"{f:.1f}GB"


def state_fields(j):
    """(validators_len, balances_len) from a BeaconState response, else (None, None).

    These are the exact arrays bera-proofs builds the existence+balance proofs
    from, so a real full state must carry both as non-empty lists. Tolerant of
    Beacon-Kit camelCase. Note Berachain's validator set is small (~90), so the
    full state is only ~tens of KB — size alone is not a reliable signal.
    """
    if not isinstance(j, dict):
        return (None, None)
    data = j.get("data", j)
    if not isinstance(data, dict):
        return (None, None)

    def pick(name):
        for k in (name, name.title(), name.capitalize()):
            v = data.get(k)
            if isinstance(v, list):
                return len(v)
        return None

    return (pick("validators"), pick("balances"))


def flatten_shape(obj, path="$"):
    """Flatten JSON into sorted 'path: type' lines (no values) for diffing two
    endpoints' response shapes. Only structure + scalar types are emitted — never
    values — so it's secret-safe. Lists collapse to their element shape, so output
    is slot-independent (modulo genuinely-empty arrays)."""
    out = []
    if isinstance(obj, dict):
        out.append(f"{path}: object")
        for k in sorted(obj.keys()):
            out.extend(flatten_shape(obj[k], f"{path}.{k}"))
    elif isinstance(obj, list):
        out.append(f"{path}: list")
        if obj:
            out.extend(flatten_shape(obj[0], f"{path}[]"))  # element shape only
    elif obj is None:
        out.append(f"{path}: null")
    elif isinstance(obj, bool):           # bool before int (bool is an int subclass)
        out.append(f"{path}: bool")
    elif isinstance(obj, int):
        out.append(f"{path}: int")
    elif isinstance(obj, float):
        out.append(f"{path}: float")
    else:
        out.append(f"{path}: str")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe a CL/beacon endpoint for bera-proofs' API surface.")
    ap.add_argument("endpoint", nargs="?", help="CL RPC base URL (or set CL_RPC_URL / BEACON_RPC_URL_MAINNET)")
    ap.add_argument("--endpoint", dest="endpoint_flag", help="same as positional")
    ap.add_argument("--slots-back", type=int, default=8, help="historical header offset (default 8, matches get_historical_roots)")
    ap.add_argument("--slot", default="head", help="proof slot for the full-state check (default head)")
    ap.add_argument("--timeout", type=float, default=30.0, help="per-request timeout s (default 30, matches the client)")
    ap.add_argument("--historical-state", action="store_true", help="also fetch debug/state at current-slots_back (only needed if you generate proofs for past slots)")
    ap.add_argument("--max-parse-mb", type=float, default=128.0, help="skip JSON parse above this size (still reports status/bytes)")
    ap.add_argument("--dump-shape", action="store_true", help="print the sorted key/type skeleton of debug/states/{slot} (no values) for diffing two endpoints — nothing sensitive is emitted")
    args = ap.parse_args()

    endpoint = args.endpoint or args.endpoint_flag
    if not endpoint:
        for ev in ENV_VARS:
            if os.getenv(ev):
                endpoint = os.environ[ev]
                break
    if not endpoint:
        print(f"ERROR: no endpoint. Pass one or set {' / '.join(ENV_VARS)}.", file=sys.stderr)
        return 2
    base = endpoint.rstrip("/")

    if args.dump_shape:
        # Value-free skeleton of the full state -> stdout (diffable); info -> stderr.
        r = fetch(f"{base}/eth/v2/debug/beacon/states/{args.slot}", args.timeout, args.max_parse_mb)
        print(f"# debug/states/{args.slot} shape from {redact(base)} "
              f"(status={r['status']}, {human_bytes(r['bytes'])})", file=sys.stderr)
        if r["status"] != 200 or not isinstance(r["json"], (dict, list)):
            print(f"# ERROR: could not fetch/parse state: {r['error'] or r['status']}", file=sys.stderr)
            return 1
        for line in sorted(flatten_shape(r["json"])):
            print(line)
        return 0

    print(f"Target CL endpoint : {redact(base)}")
    print(f"Timeout / slots-back: {args.timeout:.0f}s / {args.slots_back}")
    print("-" * 78)

    results = []  # (name, required, ok, detail)

    # 1. headers/head — health + derive current slot
    r = fetch(f"{base}/eth/v1/beacon/headers/head", args.timeout, args.max_parse_mb)
    cur = header_slot(r["json"]) if r["status"] == 200 else None
    ok = r["status"] == 200 and cur is not None
    results.append(("headers/head", True, ok,
                    f"slot={cur}" if ok else (r["error"] or f"status={r['status']}")))

    # 2. headers/{current-slots_back} — historical header (get_historical_roots)
    if cur is not None:
        hslot = max(0, cur - args.slots_back)
        r2 = fetch(f"{base}/eth/v1/beacon/headers/{hslot}", args.timeout, args.max_parse_mb)
        ok2 = r2["status"] == 200 and header_slot(r2["json"]) is not None
        results.append((f"headers/{hslot} (head-{args.slots_back})", True, ok2,
                        f"ok, {r2['ms']:.0f}ms" if ok2 else (r2["error"] or f"status={r2['status']}")))
    else:
        results.append((f"headers/(head-{args.slots_back})", True, False, "skipped — no current slot"))

    # 3. debug/beacon/states/{slot} — the critical full-state call. PASS requires
    #    a real state: non-empty validators[] AND balances[] (what proofs need).
    r3 = fetch(f"{base}/eth/v2/debug/beacon/states/{args.slot}", args.timeout, args.max_parse_mb)
    sz, t = human_bytes(r3["bytes"]), f"{r3['ms']:.0f}ms"
    if r3["status"] != 200:
        ok3, det3 = False, r3["error"] or f"status={r3['status']}"
    elif r3["json"] is None and r3["error"] and "skipped parse" in r3["error"]:
        ok3, det3 = True, f"{sz}, {t} (too large to parse; size implies a full state)"
    else:
        nval, nbal = state_fields(r3["json"])
        if nval and nbal:
            ok3, det3 = True, f"{sz}, {t}, validators={nval} balances={nbal}"
        else:
            ok3, det3 = False, f"200 but NOT a full state ({sz}): validators={nval} balances={nbal} — stub/error body, unusable for proofs"
    results.append((f"debug/states/{args.slot}  [CRITICAL]", True, ok3, det3))

    # 4. optional historical full state
    if args.historical_state and cur is not None:
        hs = max(0, cur - args.slots_back)
        r4 = fetch(f"{base}/eth/v2/debug/beacon/states/{hs}", args.timeout, args.max_parse_mb)
        nv, nb = state_fields(r4["json"])
        ok4 = r4["status"] == 200 and ((nv and nb) or (r4["error"] and "skipped parse" in r4["error"]))
        results.append((f"debug/states/{hs} (historical)", False, ok4,
                        f"{human_bytes(r4['bytes'])}, {r4['ms']:.0f}ms, validators={nv} balances={nb}" if ok4
                        else (r4["error"] or f"status={r4['status']}, validators={nv} balances={nb}")))

    # report
    print(f"{'CHECK':<34}{'REQ':<5}{'RESULT':<7}DETAIL")
    for name, req, ok, det in results:
        print(f"{name:<34}{'yes' if req else 'opt':<5}{'PASS' if ok else 'FAIL':<7}{det}")
    print("-" * 78)

    required_fail = [n for n, req, ok, _ in results if req and not ok]
    if not required_fail:
        print("VERDICT: PASS — endpoint serves every CL path bera-proofs needs.")
        return 0
    print(f"VERDICT: FAIL — {len(required_fail)} required check(s) failed: {', '.join(required_fail)}")
    if any("debug/states" in n for n in required_fail):
        print("  ↳ The debug beacon-state endpoint is unavailable. bera-proofs CANNOT use this")
        print("    endpoint regardless of EL/header support — it needs the full state to build")
        print("    proofs. Have the provider enable the `debug` beacon API, or use a node that")
        print("    serves /eth/v2/debug/beacon/states (e.g. a full Beacon-Kit node).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
