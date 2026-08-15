"""
A rule-based WAF — baseline B1 (spec §10.1).

B1 is "a rule-based filter with a standard ruleset ... what a conventional
off-the-shelf defence achieves". It exists so the paper can compare the learned,
cost-driven system against the thing most sites actually run: a set of regexes
that flag known-bad patterns. This is a deliberately SMALL, representative
ruleset in the spirit of the OWASP Core Rule Set — SQL injection, cross-site
scripting, path traversal, command injection and obvious scanners — not a
production WAF. The point is a fair, honest reference, not to lose on purpose or
to win on purpose.

A rule-based filter's defining properties, which the evaluation should surface:
  * it matches PATTERNS, so it is brittle: an encoding or comment-splitting
    evasion the learned features still catch (round 2) can slip a regex;
  * it has NO notion of session, cost, or accumulated evidence — every request
    is judged alone, so it cannot express "these ten requests together are an
    attack", and it fires the same way on a benign apostrophe as on an attack;
  * it never deceives — a match is a block/flag, which tells the attacker they
    were seen.

In the proxy, a match makes B1 "detect" the session (recorded as a divert
decision, so the same evaluation code scores every arm identically). The request
is still forwarded — B1 here is detection-only, so its recall/precision are
comparable to B2/B4 without conflating detection with blocking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    pattern: re.Pattern


# A compact, representative ruleset. Patterns are intentionally the kind a
# signature WAF ships with: they catch textbook payloads and miss deliberate
# obfuscation, which is exactly the brittleness the comparison is meant to show.
_RULES: list[Rule] = [
    # --- SQL injection ---
    Rule("WAF-SQL-1", "sqli", re.compile(r"\bunion\s+select\b", re.I)),
    Rule("WAF-SQL-2", "sqli", re.compile(r"\bor\s+1\s*=\s*1\b", re.I)),
    Rule("WAF-SQL-3", "sqli", re.compile(r"'\s*(or|and)\s+'?\d", re.I)),
    Rule("WAF-SQL-4", "sqli", re.compile(r"\b(select|insert|update|delete)\b.{0,40}\bfrom\b", re.I)),
    Rule("WAF-SQL-5", "sqli", re.compile(r"(--|\#|/\*).*$")),
    Rule("WAF-SQL-6", "sqli", re.compile(r";\s*(drop|truncate|delete)\b", re.I)),
    # --- cross-site scripting ---
    Rule("WAF-XSS-1", "xss", re.compile(r"<\s*script", re.I)),
    Rule("WAF-XSS-2", "xss", re.compile(r"javascript:", re.I)),
    Rule("WAF-XSS-3", "xss", re.compile(r"on(error|load|click)\s*=", re.I)),
    # --- path traversal / LFI ---
    Rule("WAF-LFI-1", "traversal", re.compile(r"\.\./|\.\.\\")),
    Rule("WAF-LFI-2", "traversal", re.compile(r"/etc/passwd|boot\.ini", re.I)),
    # --- command injection ---
    Rule("WAF-CMD-1", "cmdi", re.compile(r";\s*(cat|ls|id|whoami|nc|curl|wget)\b", re.I)),
    Rule("WAF-CMD-2", "cmdi", re.compile(r"\$\(|\bbash\b|\|\s*sh\b", re.I)),
    # --- scanners by user agent ---
    Rule("WAF-UA-1", "scanner", re.compile(r"sqlmap|nikto|nmap|acunetix|hydra|dirbuster", re.I)),
]


@dataclass
class RuleHit:
    rule_id: str
    category: str
    where: str          # "query", "body", or "user-agent"
    excerpt: str


class RuleWAF:
    """Stateless signature matcher. One request in, zero-or-more hits out."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or _RULES

    def inspect(self, *, query: str = "", body: str = "", user_agent: str = "") -> list[RuleHit]:
        # WAFs normalise before matching; a single URL-decode catches the
        # simplest evasion but not layered encoding — deliberately limited.
        fields = {
            "query": _normalise(query),
            "body": _normalise(body),
            "user-agent": user_agent or "",
        }
        hits: list[RuleHit] = []
        for rule in self.rules:
            for where, text in fields.items():
                if not text:
                    continue
                # UA rules only apply to the UA field; content rules to content.
                if rule.category == "scanner" and where != "user-agent":
                    continue
                if rule.category != "scanner" and where == "user-agent":
                    continue
                m = rule.pattern.search(text)
                if m:
                    hits.append(RuleHit(rule.rule_id, rule.category, where,
                                        text[max(0, m.start() - 5):m.end() + 15]))
                    break  # one hit per rule is enough
        return hits

    def flags(self, *, query: str = "", body: str = "", user_agent: str = "") -> bool:
        return bool(self.inspect(query=query, body=body, user_agent=user_agent))


def _normalise(text: str) -> str:
    try:
        return unquote(text)
    except Exception:  # noqa: BLE001 - malformed percent-encoding must not crash the WAF
        return text
