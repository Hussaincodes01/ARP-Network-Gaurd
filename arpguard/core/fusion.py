"""Verdict fusion: combine rule alerts with Kitsune anomaly scores.

Alerts are grouped into incidents by the MAC they are about (the "actor").
Each incident looks at the Kitsune scores in a window around its activity,
[first - before, last + after] seconds. Kitsune evidence is "high" when at
least `min_hits` packets in that window score above the threshold AND they
make up at least `min_fraction` of the scored packets. A single noisy packet
can't flip a verdict this way, but traffic that is broadly abnormal (such as
everything being relayed through an attacker) does.

    rule evidence          Kitsune   verdict
    ---------------------  --------  ---------------------------------------
    strong (high/critical)  high     confirmed_spoofing
    strong                  low      likely_legitimate  (one-off: failover, NIC swap)
    strong + flip-flopping  low      suspicious         (repeated re-poisoning the model missed)
    conflict (medium)       high     probable_spoofing
    conflict                low      likely_legitimate  (log only)
    weak (low)              high     suspicious
    weak                    low      likely_legitimate
    none                    high     anomaly_not_arp    (flag for review)
    none                    low      normal

The plan's table defines the first two rows and the last two; the
"flip-flopping" and "probable" rows fill in the cases it leaves open. Verdicts
are causal: an incident reads `pending` until enough Kitsune evidence arrives
or its window closes, and a spoofing verdict is never downgraded.

A Kitsune-only episode that starts soon after another incident (a spoofing
incident or an earlier anomaly) and whose busiest talkers are that incident's
hosts is linked to it as an after-effect: Kitsune's slow-decaying statistics
keep scoring the same flows as unusual for a while after the event ends.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from .detector import SEVERITY_RANK, Alert
from .oui import vendor

VERDICTS = {
    "confirmed_spoofing": {"label": "Confirmed spoofing", "level": 5, "color": "red"},
    "probable_spoofing": {"label": "Probable spoofing", "level": 4, "color": "red"},
    "suspicious": {"label": "Suspicious, review", "level": 3, "color": "orange"},
    "anomaly_not_arp": {"label": "Anomaly, not ARP-related", "level": 2, "color": "orange"},
    "pending": {"label": "Rule alert, weighing evidence", "level": 2, "color": "yellow"},
    "likely_legitimate": {"label": "Likely legitimate change", "level": 1, "color": "yellow"},
    "normal": {"label": "Normal", "level": 0, "color": "green"},
}
SPOOFING_VERDICTS = {"confirmed_spoofing", "probable_spoofing", "suspicious"}


@dataclass
class FusionConfig:
    window_before: float = 2.0
    window_after: float = 10.0
    min_hits: int = 3              # packets above threshold needed for "Kitsune high"...
    min_fraction: float = 0.2      # ...making up at least this share of the window
    incident_gap: float = 120.0    # quiet time after which an actor's next alert opens a new incident
    aftermath: float = 120.0       # Kitsune episodes this soon after a spoofing incident may be its after-effects
    episode_window: float = 5.0    # sliding window for Kitsune-only anomaly episodes
    anomaly_gap: float = 5.0       # calm time that ends an anomaly episode


@dataclass
class Incident:
    id: int
    kind: str                      # "arp" or "kitsune"
    actor: Optional[str]
    first_ts: float
    last_ts: float
    alerts: list = field(default_factory=list)
    rules: dict = field(default_factory=dict)
    max_severity: str = "info"
    ips: set = field(default_factory=set)
    targets: set = field(default_factory=set)
    old_macs: set = field(default_factory=set)
    claim_times: list = field(default_factory=list)   # [first, last] spoofed claim ts
    flagged_packets: int = 0
    scored: int = 0                                   # Kitsune-scored packets in the window
    hits: int = 0                                     # ... of which above threshold
    max_score: float = 0.0
    verdict: str = "pending"
    verdict_ts: float = 0.0
    timeline: list = field(default_factory=list)      # [ts, verdict]
    detect_ts: Optional[float] = None                 # first time the verdict reached spoofing
    talkers: dict = field(default_factory=dict)       # kitsune episodes: "src > dst" -> hits
    calm_since: Optional[float] = None

    @property
    def rule_level(self) -> str:
        rank = SEVERITY_RANK[self.max_severity]
        if rank >= 3:
            return "strong"
        if rank == 2:
            return "conflict"
        if rank == 1:
            return "weak"
        return "none"

    related: Optional[int] = None                     # kitsune episode -> incident it follows

    @property
    def persistent(self) -> bool:
        """Re-poisoning: the binding keeps flipping back after the owner reclaims it.
        A replaced router or NIC changes once and stays changed."""
        return "binding_flip_flop" in self.rules


class FusionEngine:
    def __init__(self, threshold: Optional[float], config: Optional[FusionConfig] = None,
                 on_verdict=None):
        self.threshold = threshold
        self.cfg = config or FusionConfig()
        self.incidents: list[Incident] = []
        self.open: dict[str, Incident] = {}
        self.recent: deque = deque()          # (ts, score, is_hit, talker) over the last window
        self.recent_hits = 0
        self.episode: Optional[Incident] = None
        self.last_absorbed = float("-inf")    # last score that fell inside an incident window
        self.on_verdict = on_verdict          # callback(incident, old, new)

    def set_threshold(self, threshold: Optional[float]) -> None:
        self.threshold = threshold

    def kitsune_high(self, scored: int, hits: int) -> bool:
        return hits >= self.cfg.min_hits and hits >= self.cfg.min_fraction * max(scored, 1)

    # -------------------------------------------------------------- inputs
    def on_packet(self, ts: float, alerts: list, score: Optional[float],
                  flag: Optional[str] = None, actor: Optional[str] = None,
                  talker: Optional[str] = None) -> None:
        for a in alerts:
            self._on_alert(a)
        if flag and actor:
            inc = self.open.get(actor)
            if inc is not None:
                # ARP activity keeps the incident's evidence window open; relayed
                # traffic (mitm_path) doesn't, or a legitimate new owner's
                # ordinary traffic would keep the verdict pending forever.
                if flag != "mitm_path":
                    inc.last_ts = max(inc.last_ts, ts)
                inc.flagged_packets += 1
                if flag == "spoofed_claim":
                    if not inc.claim_times:
                        inc.claim_times = [ts, ts]
                    inc.claim_times[1] = ts
        if score is not None and self.threshold is not None:
            self._on_score(ts, score, score > self.threshold, talker)
        self._tick(ts)

    def finish(self, ts: float) -> None:
        self._tick(ts + self.cfg.window_after + self.cfg.incident_gap + 1, final=True)

    # ------------------------------------------------------------ internals
    def _on_alert(self, a: Alert) -> None:
        if a.severity == "info" and a.actor not in self.open:
            return  # e.g. a restore with no open incident
        inc = self.open.get(a.actor)
        if inc is None or a.ts - inc.last_ts > self.cfg.incident_gap:
            inc = Incident(id=len(self.incidents) + 1, kind="arp", actor=a.actor,
                           first_ts=a.ts, last_ts=a.ts, verdict_ts=a.ts)
            inc.timeline.append([a.ts, "pending"])
            self.incidents.append(inc)
            self.open[a.actor] = inc
            # scored packets shortly before the first alert belong to its window
            for rts, rscore, rhit, _ in self.recent:
                if a.ts - rts <= self.cfg.window_before:
                    inc.scored += 1
                    if rhit:
                        inc.hits += 1
                        inc.max_score = max(inc.max_score, rscore)
        inc.last_ts = max(inc.last_ts, a.ts)
        inc.alerts.append(a.id)
        inc.rules[a.rule] = inc.rules.get(a.rule, 0) + 1
        if SEVERITY_RANK[a.severity] > SEVERITY_RANK[inc.max_severity]:
            inc.max_severity = a.severity
        if a.ip and a.rule not in ("binding_restored", "arp_scan", "arp_flood"):
            inc.ips.add(a.ip)
        if a.old_mac and a.old_mac != a.actor:
            inc.old_macs.add(a.old_mac)
        target = a.evidence.get("target_ip") if a.evidence else None
        if target:
            inc.targets.add(target)
        self._evaluate(inc, a.ts)

    def _on_score(self, ts: float, score: float, hit: bool, talker: Optional[str]) -> None:
        cfg = self.cfg
        # `recent` covers the last episode_window seconds (>= window_before)
        horizon = max(cfg.window_before, cfg.episode_window)
        self.recent.append((ts, score, hit, talker))
        self.recent_hits += hit
        while self.recent and ts - self.recent[0][0] > horizon:
            self.recent_hits -= self.recent.popleft()[2]

        absorbed = None
        for inc in self.open.values():
            if inc.first_ts - cfg.window_before <= ts <= inc.last_ts + cfg.window_after:
                inc.scored += 1
                absorbed = inc
                if hit:
                    inc.hits += 1
                    inc.max_score = max(inc.max_score, score)
                    self._evaluate(inc, ts)
        if absorbed is not None:
            self.last_absorbed = ts
            ep = self.episode
            if ep is not None:
                if ep.last_ts >= absorbed.first_ts - cfg.window_before - cfg.anomaly_gap:
                    self.episode = None   # the lead-up to this incident, not a separate anomaly
                else:
                    self._close_episode()
            return

        # Kitsune-only episodes: is the last `episode_window` seconds anomalous?
        anomalous = self.kitsune_high(len(self.recent), self.recent_hits)
        ep = self.episode
        if anomalous:
            if ep is None:
                ep = self.episode = Incident(id=0, kind="kitsune", actor=None, first_ts=ts,
                                             last_ts=ts, verdict="anomaly_not_arp")
                for rts, rscore, rhit, rtalk in self.recent:
                    if ts - rts <= cfg.episode_window and rhit and rts > self.last_absorbed:
                        self._count_episode_hit(ep, rscore, rtalk)
                        ep.first_ts = min(ep.first_ts, rts)
            ep.calm_since = None
        if ep is not None:
            ep.last_ts = ts
            ep.scored += 1
            if hit:
                self._count_episode_hit(ep, score, talker)
            if not anomalous and ep.calm_since is None:
                ep.calm_since = ts

    @staticmethod
    def _count_episode_hit(ep: Incident, score: float, talker: Optional[str]) -> None:
        ep.hits += 1
        ep.max_score = max(ep.max_score, score)
        if talker:
            ep.talkers[talker] = ep.talkers.get(talker, 0) + 1

    def _close_episode(self) -> None:
        ep = self.episode
        self.episode = None
        if ep is None or ep.hits < self.cfg.min_hits:
            return
        ep.id = len(self.incidents) + 1
        ep.related = self._aftermath_of(ep)
        ep.timeline = [[ep.first_ts, "anomaly_not_arp"]]
        ep.verdict_ts = ep.first_ts
        self.incidents.append(ep)
        if self.on_verdict:
            self.on_verdict(ep, None, "anomaly_not_arp")

    @staticmethod
    def _talker_hosts(inc: Incident, top: int = 2) -> set:
        busiest = sorted(inc.talkers.items(), key=lambda kv: -kv[1])[:top]
        return {h for talker, _ in busiest for h in talker.split(" > ")}

    def _aftermath_of(self, ep: Incident) -> Optional[int]:
        """The incident this Kitsune episode probably echoes: one that ended shortly
        before it (a spoofing incident or another anomaly) and shares its hosts."""
        hosts = self._talker_hosts(ep)
        for inc in reversed(self.incidents):
            if not 0 <= ep.first_ts - inc.last_ts <= self.cfg.aftermath:
                continue
            if inc.kind == "arp" and inc.verdict in SPOOFING_VERDICTS and hosts & (inc.ips | inc.targets):
                return inc.id
            if inc.kind == "kitsune" and hosts & self._talker_hosts(inc):
                return inc.id
        return None

    def _tick(self, ts: float, final: bool = False) -> None:
        ep = self.episode
        if ep is not None and (final or (ep.calm_since is not None
                                         and ts - ep.calm_since > self.cfg.anomaly_gap)):
            self._close_episode()
        for actor, inc in list(self.open.items()):
            if final or ts > inc.last_ts + self.cfg.window_after:
                self._evaluate(inc, min(ts, inc.last_ts + self.cfg.window_after), window_closed=True)
            if final or ts - inc.last_ts > self.cfg.incident_gap:
                del self.open[actor]

    def _decide(self, inc: Incident, window_closed: bool) -> str:
        level = inc.rule_level
        if level == "none":
            return "normal" if window_closed else "pending"
        if self.kitsune_high(inc.scored, inc.hits):
            return {"strong": "confirmed_spoofing", "conflict": "probable_spoofing",
                    "weak": "suspicious"}[level]
        if self.threshold is None:
            # Kitsune disabled or still learning: the rules decide alone
            if level in ("strong", "conflict"):
                return "suspicious"
            return "likely_legitimate" if window_closed else "pending"
        if not window_closed:
            return "pending"
        if level == "strong" and inc.persistent:
            return "suspicious"
        return "likely_legitimate"

    def _evaluate(self, inc: Incident, ts: float, window_closed: bool = False) -> None:
        new = self._decide(inc, window_closed)
        if inc.verdict in SPOOFING_VERDICTS and VERDICTS[new]["level"] < VERDICTS[inc.verdict]["level"]:
            return
        if new != inc.verdict:
            old = inc.verdict
            inc.verdict, inc.verdict_ts = new, ts
            inc.timeline.append([ts, new])
            if new in SPOOFING_VERDICTS and inc.detect_ts is None:
                inc.detect_ts = ts
            if self.on_verdict:
                self.on_verdict(inc, old, new)

    # -------------------------------------------------------------- export
    def export(self, t0: float, alerts_by_id: dict) -> list[dict]:
        out = []
        for inc in self.incidents:
            ev_alerts = [alerts_by_id[i] for i in inc.alerts if i in alerts_by_id]
            gateway_involved = any(a.rule == "gateway_mac_change" or a.evidence.get("is_gateway")
                                   for a in ev_alerts)
            out.append({
                "id": inc.id, "kind": inc.kind, "actor": inc.actor,
                "actor_vendor": vendor(inc.actor) if inc.actor else None,
                "first_t": round(inc.first_ts - t0, 3), "last_t": round(inc.last_ts - t0, 3),
                "rules": inc.rules, "max_severity": inc.max_severity, "rule_level": inc.rule_level,
                "ips": sorted(inc.ips), "targets": sorted(inc.targets), "old_macs": sorted(inc.old_macs),
                "gateway_involved": gateway_involved,
                "persistent": inc.persistent, "related_incident": inc.related,
                "flagged_packets": inc.flagged_packets, "alert_ids": inc.alerts,
                "kitsune": {"scored": inc.scored, "hits": inc.hits,
                            "fraction": round(inc.hits / inc.scored, 3) if inc.scored else 0.0,
                            "max_score": round(inc.max_score, 6),
                            "ratio": round(inc.max_score / self.threshold, 3) if self.threshold else None},
                "talkers": dict(sorted(inc.talkers.items(), key=lambda kv: -kv[1])[:5]),
                "verdict": inc.verdict, "verdict_label": VERDICTS[inc.verdict]["label"],
                "timeline": [[round(t - t0, 3), v] for t, v in inc.timeline],
                "detect_t": round(inc.detect_ts - t0, 3) if inc.detect_ts is not None else None,
            })
        return out
