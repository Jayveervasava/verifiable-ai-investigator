"""correlate(events) -> [Finding]

How it works (plain words):
 1. Baseline: for every user, IPs seen on >= min_baseline_days different days are "usual".
 2. Seed events: events from an EXTERNAL IP that is not usual for that user.
 3. Seeds are chained into clusters when they share the same user, IP or AWS access key and the gap
    between them is <= window_minutes.  Events with no IP (e.g. 'sudo cat ~/.aws/credentials') join a
    cluster if the same user is active on the same host within the window.
 4. Rules (rules.py) tag events with MITRE techniques.  Behaviour that is normal alone (login, S3 GET)
    counts only if it is a seed.
 5. Confidence for events inside a cluster:
       high   = same user AND same IP seen in >= 3 different sources (windows/linux/aws)
       medium = same user AND same IP in 2 sources, or same IP in >= 3 sources
       low    = anything else
    Rule-only hits (no cluster) keep the rule's own base confidence.  A group takes the higher of the two.
 6. One Finding per (cluster, technique); one per (technique, host, user, burst) for stand-alone hits.
 Plus T1110 (brute force) when >= bruteforce_min_failures failed logins come from one external IP.
"""
from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from vai.common.models import Event, Finding

from . import common
from .common import action_name, event_dt, get_field, is_external_ip, norm_user
from .rules import CONF_ORDER, RULE_INDEX, TECH_TITLES

_RANK_TO_CONF = ["low", "medium", "high"]
_FAIL = {("windows", "logon_failed"), ("linux", "ssh_failed")}
_OK = {("windows", "logon_success"), ("linux", "ssh_accepted")}


@dataclass(eq=False)
class _R:
    ev: Event
    ts: datetime
    src: str
    host: str
    user: str
    ip: str
    name: str
    act: str
    key: str
    seed: bool = False
    root: int = -1


def _max_conf(a: str, b: str) -> str:
    return a if CONF_ORDER[a] >= CONF_ORDER[b] else b


def _prepare(events: Iterable[Event]) -> list[_R]:
    recs = []
    for e in events:
        a = e.action or ""
        recs.append(_R(e, event_dt(e), e.source, e.host or "", norm_user(e.user), e.ip or "", action_name(a), a,
                       get_field(a, "access_key")))
    recs.sort(key=lambda r: (r.ts, r.ev.id))
    return recs


def _baseline(recs: list[_R], min_days: int) -> dict[str, set[str]]:
    days: dict[tuple[str, str], set] = defaultdict(set)
    for r in recs:
        if r.user and is_external_ip(r.ip):
            days[(r.user, r.ip)].add(r.ts.date())
    usual: dict[str, set[str]] = defaultdict(set)
    for (u, ip), d in days.items():
        if len(d) >= min_days:
            usual[u].add(ip)
    return usual


class _DSU:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _cluster_conf(seeds: list[_R]) -> str:
    pair: dict[tuple[str, str], set] = defaultdict(set)
    ips: dict[str, set] = defaultdict(set)
    for r in seeds:
        if r.user:
            pair[(r.user, r.ip)].add(r.src)
        ips[r.ip].add(r.src)
    best_pair = max((len(s) for s in pair.values()), default=0)
    best_ip = max((len(s) for s in ips.values()), default=0)
    if best_pair >= 3:
        return "high"
    if best_pair == 2 or best_ip >= 3:
        return "medium"
    return "low"


def _title(tech: str, rs: list[_R], link_srcs: Optional[set] = None) -> str:
    users = sorted({r.user for r in rs if r.user})
    ips = sorted({r.ip for r in rs if r.ip})
    hosts = sorted({r.host for r in rs if r.host})
    parts = []
    if users:
        parts.append("user " + ",".join(users[:3]))
    if ips:
        parts.append("ip " + ",".join(ips[:3]))
    if hosts:
        parts.append("host " + ",".join(hosts[:3]))
    t = f"{TECH_TITLES.get(tech, tech)}: " + "; ".join(parts) if parts else TECH_TITLES.get(tech, tech)
    t += f" [{len(rs)} event{'s' if len(rs) != 1 else ''}]"
    if link_srcs and len(link_srcs) >= 2:
        t += f" - correlated across {len(link_srcs)} sources ({'+'.join(sorted(link_srcs))})"
    return t


def correlate(
    events: Iterable[Event],
    *,
    window_minutes: int = 120,
    min_baseline_days: int = 3,
    bruteforce_min_failures: int = 10,
    bruteforce_window_minutes: int = 60,
) -> list[Finding]:
    """CONTRACT: correlate(events) -> [Finding]  (sorted by first event time). Parameters are keyword-only tuning knobs."""
    window = timedelta(minutes=window_minutes)
    recs = _prepare(events)
    common.EVENT_TS = {r.ev.id: r.ts for r in recs}          # for timeline()
    usual = _baseline(recs, min_baseline_days)

    # 2. seeds
    for r in recs:
        r.seed = is_external_ip(r.ip) and (not r.user or r.ip not in usual.get(r.user, ()))
    seeds = [r for r in recs if r.seed]

    # 3. cluster seeds
    idx = {id(r): i for i, r in enumerate(seeds)}
    dsu = _DSU(len(seeds))
    last: dict[tuple[str, str], tuple[datetime, int]] = {}
    for i, r in enumerate(seeds):
        for k in (("u", r.user), ("i", r.ip), ("k", r.key)):
            if not k[1]:
                continue
            prev = last.get(k)
            if prev and r.ts - prev[0] <= window:
                dsu.union(prev[1], i)
            last[k] = (r.ts, i)
    for i, r in enumerate(seeds):
        r.root = dsu.find(i)
    members: dict[int, list[_R]] = defaultdict(list)
    for r in seeds:
        members[r.root].append(r)
    conf_of = {root: _cluster_conf(m) for root, m in members.items()}
    srcs_of = {root: {r.src for r in m} for root, m in members.items()}

    # (user, host) -> sorted seed timestamps/roots, to attach IP-less events
    uh: dict[tuple[str, str], tuple[list[datetime], list[int]]] = defaultdict(lambda: ([], []))
    for r in seeds:
        if r.user:
            uh[(r.user, r.host)][0].append(r.ts)
            uh[(r.user, r.host)][1].append(r.root)

    def attach(r: _R) -> int:
        if not r.user or (r.user, r.host) not in uh:
            return -1
        ts_list, roots = uh[(r.user, r.host)]
        p = bisect_left(ts_list, r.ts)
        best, best_gap = -1, window + timedelta(seconds=1)
        for q in (p - 1, p):
            if 0 <= q < len(ts_list):
                gap = abs(ts_list[q] - r.ts)
                if gap <= window and gap < best_gap:
                    best, best_gap = roots[q], gap
        return best

    # 4. rule hits
    cluster_hits: dict[tuple[int, str], dict] = {}
    solo_hits: dict[tuple[str, str, str], list[tuple[_R, str]]] = defaultdict(list)
    for r in recs:
        rules = RULE_INDEX.get((r.src, r.name))
        if not rules:
            continue
        for rule in rules:
            if rule.test and not rule.test(r.act):
                continue
            if rule.needs_origin and not r.seed:
                continue
            root = r.root if r.seed else attach(r)
            if root >= 0:
                g = cluster_hits.setdefault((root, rule.technique), {"recs": {}, "base": "low"})
                g["recs"][id(r)] = r
                g["base"] = _max_conf(g["base"], rule.base)
            else:
                solo_hits[(rule.technique, r.host, r.user)].append((r, rule.base))

    groups: list[tuple[datetime, str, str, str, list[_R]]] = []   # (first_ts, tech, conf, title, recs)
    for (root, tech), g in cluster_hits.items():
        rs = sorted(g["recs"].values(), key=lambda x: (x.ts, x.ev.id))
        srcs = srcs_of[root] | {r.src for r in rs}
        conf = _max_conf(g["base"], conf_of[root])
        groups.append((rs[0].ts, tech, conf, _title(tech, rs, srcs), rs))
    for (tech, host, user), items in solo_hits.items():
        items.sort(key=lambda x: (x[0].ts, x[0].ev.id))
        burst: list[tuple[_R, str]] = []
        for it in items + [None]:                                    # type: ignore[list-item]
            if burst and (it is None or it[0].ts - burst[-1][0].ts > window):
                base = "low"
                for _, b in burst:
                    base = _max_conf(base, b)
                uniq = list({id(r): r for r, _ in burst}.values())
                groups.append((uniq[0].ts, tech, base, _title(tech, uniq), uniq))
                burst = []
            if it is not None:
                burst.append(it)

    # 6b. brute force
    fails: dict[str, list[_R]] = defaultdict(list)
    for r in recs:
        if is_external_ip(r.ip) and (
            (r.src, r.name) in _FAIL or (r.src == "aws" and r.name == "signin:ConsoleLogin" and "result=Failure" in r.act)
        ):
            fails[r.ip].append(r)
    bw = timedelta(minutes=bruteforce_window_minutes)
    oks: dict[str, list[datetime]] = defaultdict(list)
    for r in recs:
        if is_external_ip(r.ip) and ((r.src, r.name) in _OK or (r.src == "aws" and "result=Success" in r.act and r.name == "signin:ConsoleLogin")):
            oks[r.ip].append(r.ts)
    for ip, items in fails.items():
        burst = []
        for it in items + [None]:                                    # type: ignore[list-item]
            if burst and (it is None or it.ts - burst[-1].ts > bw):
                if len(burst) >= bruteforce_min_failures:
                    won = any(burst[0].ts <= t <= burst[-1].ts + bw for t in oks.get(ip, ()))
                    groups.append((burst[0].ts, "T1110", "medium" if won else "low",
                                   _title("T1110", burst) + (" - followed by a successful login from the same IP" if won else ""),
                                   burst))
                burst = []
            if it is not None:
                burst.append(it)

    groups.sort(key=lambda g: (g[0], g[1]))
    findings = []
    for n, (_, tech, conf, title, rs) in enumerate(groups, 1):
        findings.append(Finding(id=f"F-{n:04d}", technique_id=tech, title=title,
                                event_ids=[r.ev.id for r in rs], confidence=conf))
    return findings
