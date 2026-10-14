"""Lookup-latency benchmark for the threat-intel store.

EVERY HASH IN THIS FILE IS FABRICATED. It is generated locally from a fixed
seed to measure index behaviour at a realistic record count. It is written to
a dedicated ``bench_intel.db`` in a temp directory, with ``synthetic=1`` and
``source="synthetic_benchmark"`` on every row, and the store it goes into must
be opened with ``allow_synthetic=True``. A production ``ThreatIntelStore``
refuses these rows outright, and ``verify_integrity`` flags any that leak in.
None of it is threat intelligence and none of it can ever produce a block.

The benchmark is skipped unless ``STAI_INTEL_BENCH=1`` so it never slows a
normal test run. Run it directly for the full report:

    python tests/test_threat_intel_benchmark.py [row_count]
"""

from __future__ import annotations

import os
import random
import statistics
import time
from pathlib import Path
from typing import Iterator

import pytest

from cyber_os.protection.store import DetectionRule, ThreatIntelStore

BENCH_SOURCE = "synthetic_benchmark"
BENCH_SEED = 20261014
RUN_BENCH = os.getenv("STAI_INTEL_BENCH") == "1"


def synthetic_digests(count: int, *, seed: int = BENCH_SEED) -> Iterator[str]:
    """Yield ``count`` fabricated sha256-shaped digests, deterministically."""
    rng = random.Random(seed)
    for _ in range(count):
        yield "%064x" % rng.getrandbits(256)


def build_benchmark_store(path: Path, rows: int) -> tuple[ThreatIntelStore, float]:
    store = ThreatIntelStore(path, allow_synthetic=True)
    start = time.perf_counter()
    counters = store.bulk_load_hashes(
        synthetic_digests(rows),
        source=BENCH_SOURCE,
        feed_version=f"SYNTHETIC-BENCHMARK-{rows}",
        synthetic=True,
    )
    elapsed = time.perf_counter() - start
    assert counters["inserted"] > 0
    return store, elapsed


def percentiles(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def at(fraction: float) -> float:
        index = min(len(ordered) - 1, int(fraction * len(ordered)))
        return ordered[index]

    return {
        "n": len(ordered),
        "p50_us": at(0.50) * 1e6,
        "p95_us": at(0.95) * 1e6,
        "p99_us": at(0.99) * 1e6,
        "mean_us": statistics.fmean(ordered) * 1e6,
        "max_us": ordered[-1] * 1e6,
    }


def measure_lookups(store: ThreatIntelStore, probes: list[str]) -> dict[str, float]:
    conn = store._get_conn()
    samples: list[float] = []
    for digest in probes:
        start = time.perf_counter()
        conn.execute(
            "SELECT indicator_id FROM intel_indicators WHERE sha256 = ?", (digest,)
        ).fetchone()
        samples.append(time.perf_counter() - start)
    return percentiles(samples)


def measure_linear_rule_scan(rules: tuple[DetectionRule, ...], probes: list[str]) -> dict[str, float]:
    """Time the comparison the scanner does today: a Python loop over a tuple.

    ``scanner.py`` matches a digest with a list comprehension over every rule
    in the signed rule set, so its cost is linear in the rule count with no
    index involved at all. This measures that same shape.
    """
    samples: list[float] = []
    for digest in probes:
        start = time.perf_counter()
        [rule for rule in rules if rule.kind == "sha256" and rule.value == digest]
        samples.append(time.perf_counter() - start)
    return percentiles(samples)


def query_plan(store: ThreatIntelStore, sql: str, params: tuple) -> str:
    return " | ".join(
        row[-1] for row in store._get_conn().execute("EXPLAIN QUERY PLAN " + sql, params)
    )


@pytest.mark.skipif(not RUN_BENCH, reason="set STAI_INTEL_BENCH=1 to run the benchmark")
def test_indexed_lookup_beats_a_table_scan(tmp_path: Path) -> None:
    rows = int(os.getenv("STAI_INTEL_BENCH_ROWS", "200000"))
    store, _ = build_benchmark_store(tmp_path / "bench_intel.db", rows)
    probes = list(synthetic_digests(500, seed=BENCH_SEED + 1))

    sql = "SELECT indicator_id FROM intel_indicators WHERE sha256 = ?"
    assert "SEARCH" in query_plan(store, sql, (probes[0],))
    indexed = measure_lookups(store, probes)

    store._get_conn().execute("DROP INDEX idx_intel_sha256")
    assert "SCAN intel_indicators" in query_plan(store, sql, (probes[0],))
    scanned = measure_lookups(store, probes)

    # The whole point of the index: a miss must not read the table.
    assert indexed["p99_us"] * 10 < scanned["p50_us"], (indexed, scanned)


@pytest.mark.skipif(not RUN_BENCH, reason="set STAI_INTEL_BENCH=1 to run the benchmark")
def test_benchmark_rows_are_never_block_eligible(tmp_path: Path) -> None:
    rows = 1000
    store, _ = build_benchmark_store(tmp_path / "bench_intel.db", rows)
    for digest in list(synthetic_digests(20)):
        assert store.block_decision("sha256", digest).block is False
    assert store.count_unique_hashes() == 0
    assert store.count_unique_hashes(include_synthetic=True) == rows


def _report(rows: int) -> None:
    import json
    import tempfile

    bench_dir = Path(tempfile.mkdtemp(prefix="stai-intel-bench-"))
    print(f"SYNTHETIC BENCHMARK -- {rows:,} fabricated rows -> {bench_dir}")
    print("These hashes are NOT threat intelligence.\n")

    store, load_seconds = build_benchmark_store(bench_dir / "bench_intel.db", rows)
    total = store._get_conn().execute("SELECT COUNT(*) FROM intel_indicators").fetchone()[0]
    size_mb = (bench_dir / "bench_intel.db").stat().st_size / 1e6
    print(f"loaded {total:,} rows in {load_seconds:.1f}s "
          f"({total / load_seconds:,.0f} rows/s), {size_mb:.0f} MB on disk")
    print(f"production-safety check: count_unique_hashes()={store.count_unique_hashes()} "
          f"(synthetic excluded), block_eligible={store.count_block_eligible_hashes()}")

    hit_probes = list(synthetic_digests(min(2000, rows)))
    miss_probes = list(synthetic_digests(2000, seed=BENCH_SEED + 1))
    sql = "SELECT indicator_id FROM intel_indicators WHERE sha256 = ?"

    print("\nAFTER (idx_intel_sha256 present)")
    print("  plan:", query_plan(store, sql, (hit_probes[0],)))
    print("  hits :", json.dumps(measure_lookups(store, hit_probes)))
    print("  misses:", json.dumps(measure_lookups(store, miss_probes)))
    print("  block_decision():", json.dumps(_measure_decisions(store, hit_probes[:500])))

    store._get_conn().execute("DROP INDEX idx_intel_sha256")
    print("\nBEFORE (no index on sha256 -- what an unindexed table costs)")
    print("  plan:", query_plan(store, sql, (hit_probes[0],)))
    scan_probes = miss_probes[:50]
    print("  misses:", json.dumps(measure_lookups(store, scan_probes)))
    store._get_conn().execute(
        "CREATE INDEX idx_intel_sha256 ON intel_indicators(sha256) WHERE sha256 IS NOT NULL"
    )

    print("\nBASELINE (scanner.py today: Python loop over the signed rule tuple)")
    for rule_count in (1, 1_000, 100_000):
        rules = tuple(
            DetectionRule(id=f"r{i}", kind="sha256", value=digest, action="block",
                          confidence="high")
            for i, digest in enumerate(synthetic_digests(rule_count, seed=BENCH_SEED + 2))
        )
        stats = measure_linear_rule_scan(rules, miss_probes[:200])
        print(f"  {rule_count:>7,} rules:", json.dumps(stats))


def _measure_decisions(store: ThreatIntelStore, probes: list[str]) -> dict[str, float]:
    samples: list[float] = []
    for digest in probes:
        start = time.perf_counter()
        store.block_decision("sha256", digest)
        samples.append(time.perf_counter() - start)
    return percentiles(samples)


if __name__ == "__main__":
    import sys

    _report(int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000)
