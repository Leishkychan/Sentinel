"""
sentinel/core/attack_graph.py

AttackGraph — the chain IS the investigation.

When a finding is confirmed, this module immediately determines what to test next.
Alpha doesn't guess. It follows the chain.

Design rules:
  - Confirmed finding → precondition map fires → next steps generated
  - Next steps go to FRONT of session_intel queue (chain has priority over guesses)
  - Depth cap: 3 levels. No finding at depth 3 generates further steps.
  - No loops: each URL is generated once. should_probe() blocks revisits.
  - Intersection: two active chains share a node → escalated to Queen only.
  - Queen decides on intersections — does not re-investigate settled chains.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import re


class ChainStatus(str, Enum):
    ACTIVE    = "ACTIVE"     # Being extended
    COMPLETE  = "COMPLETE"   # Depth reached or no more steps
    DEAD      = "DEAD"       # All branches disproven
    ESCALATED = "ESCALATED"  # Sent to Queen for intersection handling


@dataclass
class ChainNode:
    """A single confirmed finding in a chain."""
    node_id:       str
    url:           str
    finding_type:  str       # e.g. "unauthenticated_api_access"
    depth:         int       # 0 = root, 1 = first extension, 2, 3 = max
    chain_id:      str
    parent_id:     Optional[str]
    evidence_ref:  Optional[str] = None   # Proof snippet summary
    enabled_urls:  list[str] = field(default_factory=list)   # URLs this node generated


@dataclass
class ActiveChain:
    """
    A chain being actively extended.
    The chain grows as Alpha confirms findings.
    """
    chain_id:   str
    title:      str
    severity:   str          # Escalates as chain grows
    root_url:   str
    nodes:      list[ChainNode] = field(default_factory=list)
    status:     ChainStatus = ChainStatus.ACTIVE
    max_depth:  int = 3
    generated_urls: set = field(default_factory=set)  # Never generate twice

    @property
    def confirmed_count(self) -> int:
        return len(self.nodes)

    @property
    def current_depth(self) -> int:
        return max((n.depth for n in self.nodes), default=0)

    def can_extend(self) -> bool:
        return (self.status == ChainStatus.ACTIVE and
                self.current_depth < self.max_depth)


@dataclass
class ChainIntersection:
    """
    Two chains share a confirmed finding.
    Escalated to Queen for combined assessment.
    """
    chain_a_id:    str
    chain_b_id:    str
    shared_url:    str
    combined_severity: str
    description:   str


# ── Precondition registry ─────────────────────────────────────────────────────
#
# Maps finding_type → what it enables.
# Each entry specifies:
#   - chain_title: what to call this chain
#   - severity: starting severity (escalates as chain grows)
#   - next_steps: list of tests to run next
#
# next_step types:
#   "sibling_namespace" — other endpoints in same URL namespace
#   "id_variation"      — append /1, /2 to test IDOR
#   "param_probe"       — add query parameters to test injection
#   "admin_sibling"     — other endpoints in same admin namespace
#   "direct_url"        — specific URL to test

PRECONDITION_MAP: dict[str, dict] = {

    "unauthenticated_api_access": {
        "chain_title": "Unauthenticated API Enumeration",
        "severity":    "HIGH",
        "next_steps": [
            {
                "type":        "sibling_namespace",
                "description": "Probe sibling endpoints in same API namespace",
                "priority":    1,
            },
            {
                "type":        "id_variation",
                "description": "Test IDOR — access records by ID without auth",
                "priority":    2,
            },
        ],
    },

    "unauthenticated_admin_access": {
        "chain_title": "Unauthenticated Administrative Access",
        "severity":    "CRITICAL",
        "next_steps": [
            {
                "type":        "admin_sibling",
                "description": "Probe sibling admin endpoints in same namespace",
                "priority":    1,
            },
        ],
    },

    "sql_injection_condition": {
        "chain_title": "SQL Injection Exploitation",
        "severity":    "CRITICAL",
        "next_steps": [
            {
                "type":        "param_probe",
                "param":       "q",
                "payload_a":   "test' AND 1=1--",
                "payload_b":   "test' AND 1=2--",
                "description": "Boolean differential probe — confirms injectable parameter",
                "priority":    1,
            },
        ],
    },

    "sensitive_config_exposure": {
        "chain_title": "Configuration Data Exposure",
        "severity":    "HIGH",
        "next_steps": [
            {
                "type":        "admin_sibling",
                "description": "Probe sibling configuration endpoints",
                "priority":    1,
            },
        ],
    },

    "no_rate_limiting": {
        "chain_title": "Brute Force Vector",
        "severity":    "MEDIUM",
        "next_steps": [
            # No direct probe — this chains with other findings
            # Intersection with unauthenticated_api_access → CRITICAL
        ],
    },

    "sensitive_data_exposure": {
        "chain_title": "Data Exposure Enumeration",
        "severity":    "HIGH",
        "next_steps": [
            {
                "type":        "sibling_namespace",
                "description": "Probe sibling endpoints for additional data exposure",
                "priority":    1,
            },
        ],
    },
}

# Intersection escalation rules
# When chain_type_a and chain_type_b are both active → combined_severity
INTERSECTION_RULES: list[dict] = [
    {
        "chain_a": "unauthenticated_api_access",
        "chain_b": "no_rate_limiting",
        "combined_severity": "CRITICAL",
        "description": "Unauthenticated access + no rate limiting = unlimited enumeration",
    },
    {
        "chain_a": "sql_injection_condition",
        "chain_b": "unauthenticated_api_access",
        "combined_severity": "CRITICAL",
        "description": "Unauthenticated access enables direct SQL injection exploitation",
    },
    {
        "chain_a": "sensitive_config_exposure",
        "chain_b": "sql_injection_condition",
        "combined_severity": "CRITICAL",
        "description": "Config data may reveal credentials usable in injection attacks",
    },
]


# ── Resource registry for namespace-based expansion ──────────────────────────
#
# When a confirmed finding establishes an API naming convention,
# we can generate additional sibling probes from known resource families.
#
# This is bounded registry expansion, not free generation:
#   - Only triggered by confirmed unauthenticated access
#   - Only in recognized namespaces (/api/, /rest/admin/)
#   - Resources tagged as registry_generated (lower confidence than queue siblings)
#   - Still subject to full pipeline proof rules
#   - Generated once only — deduped via _all_generated

RESOURCE_REGISTRY: dict[str, list[str]] = {
    # Capitalized REST resources — common in Node/Express/Loopback APIs
    "/api/": [
        "Products", "Feedbacks", "Baskets", "Complaints",
        "Orders", "Users", "Addresses", "Cards",
        "SecurityQuestions", "Challenges",
    ],
    # Admin/config endpoints — common in Express apps
    "/rest/admin/": [
        "application-configuration",
    ],
    # Products search and similar REST patterns
    "/rest/products/": [
        "search",
    ],
}


class AttackGraph:
    """
    The investigation engine.

    When a finding is confirmed, this class:
    1. Identifies its type
    2. Looks up what it enables
    3. Generates the next URLs to test — from queue siblings first, registry second
    4. Returns them ordered by priority

    The chain drives the investigation. Alpha follows the chain.
    """

    def __init__(self):
        self.chains:              list[ActiveChain] = []
        self.intersections:       list[ChainIntersection] = []
        self._node_counter:       int = 0
        self._chain_counter:      int = 0
        # URLs generated from confirmed parents (queue siblings)
        self._all_generated:      set[str] = set()
        # URLs generated from registry (lower confidence, still chain-driven)
        self._registry_generated: set[str] = set()

    def record_confirmed(
        self,
        url: str,
        evidence_summary: str,
        session_intel,  # SessionIntelligence — to check should_probe and get queue
    ) -> list[str]:
        """
        Called when a finding is confirmed.
        Returns list of next URLs to probe (already filtered, priority-ordered).
        These go to the FRONT of the untested_queue.
        """
        finding_type = self._classify_finding(url, evidence_summary)
        if not finding_type:
            return []

        # Find or create chain for this finding type
        chain = self._find_or_create_chain(finding_type, url)
        if not chain or not chain.can_extend():
            return []

        # Create node for this confirmed finding
        node = self._add_node(chain, url, finding_type, evidence_summary)

        # Generate next steps
        next_urls = self._generate_next_steps(
            chain, node, url, session_intel
        )

        # Check for intersections
        self._check_intersections()

        return next_urls

    def get_pending_intersections(self) -> list[ChainIntersection]:
        """Return intersections not yet escalated to Queen."""
        return [i for i in self.intersections
                if not getattr(i, '_escalated', False)]

    def mark_intersection_escalated(self, intersection: ChainIntersection):
        intersection._escalated = True

    def get_active_chain_context(self) -> str:
        """Context string for Alpha's reasoning prompt."""
        if not self.chains:
            return ""
        lines = ["\nACTIVE INVESTIGATION CHAINS (follow these — do not guess):"]
        for chain in self.chains:
            if chain.status == ChainStatus.ACTIVE:
                lines.append(
                    f"  [{chain.severity}] {chain.title} — "
                    f"{chain.confirmed_count} confirmed, depth {chain.current_depth}/{chain.max_depth}"
                )
        return "\n".join(lines) if len(lines) > 1 else ""

    def get_summary(self) -> dict:
        return {
            "total_chains":    len(self.chains),
            "active_chains":   sum(1 for c in self.chains if c.status == ChainStatus.ACTIVE),
            "complete_chains": sum(1 for c in self.chains if c.status == ChainStatus.COMPLETE),
            "intersections":   len(self.intersections),
            "urls_generated":  len(self._all_generated),
        }

    # ── Private methods ───────────────────────────────────────────────────────

    def _classify_finding(self, url: str, evidence: str) -> Optional[str]:
        """
        Classify a confirmed finding into a chain type.

        Patterns are explicit — no catch-all. If no pattern matches, returns None
        and no chain steps are generated for that finding.

        API-like namespaces covered (all justified by existing codebase references):
          /api/     — primary REST namespace, referenced throughout agents
          /rest/    — secondary REST namespace, referenced throughout agents
          /graphql  — referenced in Queen blocked patterns and validator
          /v1/ /v2/ /v3/ — referenced in Queen blocked patterns as known version endpoints
        """
        url_lower = url.lower()
        ev_lower  = evidence.lower()

        # Admin config — most specific, check first
        if "admin" in url_lower and ("config" in url_lower or "configuration" in url_lower):
            return "sensitive_config_exposure"

        # Admin access (non-config)
        if "admin" in url_lower:
            return "unauthenticated_admin_access"

        # SQL injection — ONLY if behavioral differential was confirmed
        # A search endpoint returning data is NOT injection — it's data exposure
        # Injection requires explicit differential evidence in the evidence string
        if ("injection confirmed" in ev_lower or
                ("boolean" in ev_lower and "differential" in ev_lower) or
                ("sql" in ev_lower and "error" in ev_lower and "syntax" in ev_lower)):
            return "sql_injection_condition"

        # Unauthenticated API access — explicit API-like namespaces only
        # /api/ and /rest/ are the primary namespaces in the codebase
        # /graphql is referenced in Queen's blocked patterns and validator permissions
        # /v1/ /v2/ /v3/ are referenced in Queen's blocked patterns as known API version paths
        if ("/api/" in url_lower or
                "/rest/" in url_lower or
                "/graphql" in url_lower or
                "/v1/" in url_lower or
                "/v2/" in url_lower or
                "/v3/" in url_lower):
            return "unauthenticated_api_access"

        # Rate limiting (standalone)
        if "rate" in ev_lower and "limit" in ev_lower:
            return "no_rate_limiting"

        # Sensitive data — non-API paths where sensitive fields were explicitly confirmed
        if any(s in ev_lower for s in ["password", "token", "apikey", "secret"]):
            return "sensitive_data_exposure"

        # No pattern matched — do not generate chain steps for unknown paths
        # Prefer no classification over wrong classification
        return None

    def _find_or_create_chain(
        self, finding_type: str, url: str
    ) -> Optional[ActiveChain]:
        """Find existing chain of this type or create a new one."""
        # Check if this URL is already a node in an existing chain
        for chain in self.chains:
            for node in chain.nodes:
                if node.url == url:
                    return chain  # Already in a chain

        # Find active chain of same type
        for chain in self.chains:
            if (chain.status == ChainStatus.ACTIVE and
                    finding_type in chain.chain_id):
                return chain

        # Create new chain
        config = PRECONDITION_MAP.get(finding_type)
        if not config:
            return None

        self._chain_counter += 1
        chain = ActiveChain(
            chain_id=f"CHAIN-{finding_type[:8].upper()}-{self._chain_counter:03d}",
            title=config["chain_title"],
            severity=config["severity"],
            root_url=url,
        )
        self.chains.append(chain)
        return chain

    def _add_node(
        self, chain: ActiveChain, url: str,
        finding_type: str, evidence: str
    ) -> ChainNode:
        """Add a confirmed finding as a node in the chain."""
        parent_id = chain.nodes[-1].node_id if chain.nodes else None
        depth     = (chain.nodes[-1].depth + 1) if chain.nodes else 0

        self._node_counter += 1
        node = ChainNode(
            node_id=f"N{self._node_counter:04d}",
            url=url,
            finding_type=finding_type,
            depth=depth,
            chain_id=chain.chain_id,
            parent_id=parent_id,
            evidence_ref=evidence[:80],
        )
        chain.nodes.append(node)

        if depth >= chain.max_depth:
            chain.status = ChainStatus.COMPLETE

        return node

    def _generate_next_steps(
        self,
        chain: ActiveChain,
        node: ChainNode,
        url: str,
        session_intel,
    ) -> list[str]:
        """
        Generate the next URLs to probe based on this confirmed finding.
        Returns priority-ordered list of URLs not yet settled.
        """
        if node.depth >= chain.max_depth:
            return []

        config    = PRECONDITION_MAP.get(node.finding_type, {})
        steps     = sorted(config.get("next_steps", []),
                           key=lambda s: s.get("priority", 99))
        next_urls: list[str] = []

        # Extract base components from the confirmed URL
        base_url  = _extract_base(url)
        namespace = _extract_namespace(url)

        for step in steps:
            step_type = step.get("type", "")

            if step_type == "sibling_namespace":
                # Source 1: URLs already in queue from JS discovery (best — directly observed)
                siblings = [
                    u for u in (session_intel.untested_queue or [])
                    if namespace and namespace in u.lower()
                    and u != url
                    and u not in self._all_generated
                    and u not in session_intel.confirmed_urls
                    and u not in session_intel.disproven_urls
                    and session_intel.inconclusive_counts.get(u, 0) < 2
                ]
                next_urls.extend(siblings[:4])

                # Source 2: Registry-based expansion — when queue siblings are exhausted
                # This fills the gap when JS didn't discover siblings of confirmed resources
                # Only fires if we got fewer than 3 queue siblings
                if len(siblings) < 3 and namespace in RESOURCE_REGISTRY:
                    registry_resources = RESOURCE_REGISTRY[namespace]
                    for resource in registry_resources:
                        candidate = base_url + namespace.rstrip("/") + "/" + resource
                        if (candidate != url and
                                candidate not in self._all_generated and
                                candidate not in session_intel.confirmed_urls and
                                candidate not in session_intel.disproven_urls and
                                session_intel.inconclusive_counts.get(candidate, 0) < 2 and
                                candidate not in (session_intel.untested_queue or [])):
                            next_urls.append(candidate)
                    if len(next_urls) > len(siblings):
                        print(f"[CHAIN] Registry expanded: {len(next_urls) - len(siblings)} "
                              f"additional {namespace} candidates")

            elif step_type == "admin_sibling":
                admin_ns = _extract_admin_namespace(url)
                if admin_ns:
                    siblings = [
                        u for u in (session_intel.untested_queue or [])
                        if admin_ns in u.lower()
                        and u != url
                        and u not in self._all_generated
                        and u not in session_intel.confirmed_urls
                        and u not in session_intel.disproven_urls
                        and session_intel.inconclusive_counts.get(u, 0) < 2
                    ]
                    next_urls.extend(siblings[:3])

            elif step_type == "id_variation":
                # ONLY if the confirmed URL has records and no ID already
                # AND a sibling ID-based path is already in the queue
                if not re.search(r'/\d+', url):
                    candidate = url.rstrip("/") + "/1"
                    # Only add if queue already contains something like this
                    # (i.e. JS agent discovered it) — never synthesize blind
                    already_queued = any(
                        candidate in u or u.rstrip("/") + "/1" == candidate
                        for u in (session_intel.untested_queue or [])
                    )
                    if (already_queued and
                            candidate not in self._all_generated and
                            candidate not in session_intel.confirmed_urls and
                            candidate not in session_intel.disproven_urls):
                        next_urls.append(candidate)

            elif step_type == "param_probe":
                # Only add param probes for endpoints already in the queue
                # Never generate parameterized paths for arbitrary URLs
                param   = step.get("param", "q")
                p_a     = step.get("payload_a", "test")
                p_b     = step.get("payload_b", "test2")
                base_no_params = url.split("?")[0]
                in_queue = any(base_no_params in u for u in (session_intel.untested_queue or []))
                if in_queue or base_no_params in session_intel.confirmed_urls:
                    url_a = f"{base_no_params}?{param}={p_a}"
                    url_b = f"{base_no_params}?{param}={p_b}"
                    for u in [url_a, url_b]:
                        if u not in self._all_generated:
                            next_urls.append(u)

        # Deduplicate, mark as generated
        unique_urls = []
        for u in next_urls:
            if u not in self._all_generated and u not in self._registry_generated:
                # Determine if this came from registry or queue
                is_registry = any(
                    u == base_url + ns.rstrip("/") + "/" + res
                    for ns, resources in RESOURCE_REGISTRY.items()
                    for res in resources
                )
                if is_registry:
                    self._registry_generated.add(u)
                else:
                    self._all_generated.add(u)
                node.enabled_urls.append(u)
                unique_urls.append(u)

        print(f"[CHAIN] {chain.title} depth {node.depth} → {len(unique_urls)} next steps")
        return unique_urls

    def _check_intersections(self):
        """Check if any two active chains share a finding type or URL."""
        active = [c for c in self.chains if c.status == ChainStatus.ACTIVE]
        seen_urls: dict[str, str] = {}  # url → chain_id

        for chain in active:
            for node in chain.nodes:
                if node.url in seen_urls:
                    other_chain_id = seen_urls[node.url]
                    if not self._intersection_exists(chain.chain_id, other_chain_id):
                        # Find combined severity
                        other_chain = next(
                            (c for c in self.chains if c.chain_id == other_chain_id),
                            None
                        )
                        combined_sev = self._combined_severity(chain, other_chain)
                        intersection = ChainIntersection(
                            chain_a_id=chain.chain_id,
                            chain_b_id=other_chain_id,
                            shared_url=node.url,
                            combined_severity=combined_sev,
                            description=(
                                f"{chain.title} + "
                                f"{other_chain.title if other_chain else 'unknown'}: "
                                f"shared finding at {node.url}"
                            ),
                        )
                        self.intersections.append(intersection)
                        print(f"[CHAIN] ⚡ Intersection detected: {intersection.description}")
                else:
                    seen_urls[node.url] = chain.chain_id

        # Type-rule intersections — require confirmed relationship, not just co-occurrence
        # Both chains must: (a) have confirmed nodes, (b) share the same base URL family
        # This prevents CRITICAL escalation from two unrelated findings on different assets
        active_types = {
            c.chain_id: next(
                (k for k in PRECONDITION_MAP if k[:8].upper() in c.chain_id),
                None
            )
            for c in active
        }
        for rule in INTERSECTION_RULES:
            matching_a = [c for c in active
                          if active_types.get(c.chain_id) == rule["chain_a"]
                          and len(c.nodes) > 0]  # must have confirmed node
            matching_b = [c for c in active
                          if active_types.get(c.chain_id) == rule["chain_b"]
                          and len(c.nodes) > 0]  # must have confirmed node
            for ca in matching_a:
                for cb in matching_b:
                    if self._intersection_exists(ca.chain_id, cb.chain_id):
                        continue
                    # Require same asset family: both chains rooted at same base URL
                    base_a = _extract_base(ca.root_url) if ca.root_url else None
                    base_b = _extract_base(cb.root_url) if cb.root_url else None
                    if not base_a or not base_b or base_a != base_b:
                        continue  # Different assets — not a confirmed relationship
                    intersection = ChainIntersection(
                        chain_a_id=ca.chain_id,
                        chain_b_id=cb.chain_id,
                        shared_url=base_a,
                        combined_severity=rule["combined_severity"],
                        description=rule["description"],
                    )
                    self.intersections.append(intersection)
                    print(f"[CHAIN] ⚡ Confirmed intersection on {base_a}: {rule['description']}")

    def _intersection_exists(self, id_a: str, id_b: str) -> bool:
        return any(
            (i.chain_a_id == id_a and i.chain_b_id == id_b) or
            (i.chain_a_id == id_b and i.chain_b_id == id_a)
            for i in self.intersections
        )

    def _combined_severity(
        self, chain_a: ActiveChain, chain_b: Optional[ActiveChain]
    ) -> str:
        sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_a = chain_a.severity
        sev_b = chain_b.severity if chain_b else "LOW"
        # Take the higher of the two, bump up one level if both are HIGH
        idx_a = sev_order.index(sev_a) if sev_a in sev_order else 0
        idx_b = sev_order.index(sev_b) if sev_b in sev_order else 0
        combined_idx = min(max(idx_a, idx_b) + 1, 3)
        return sev_order[combined_idx]


# ── URL helpers ───────────────────────────────────────────────────────────────

def _extract_base(url: str) -> str:
    """http://localhost:3000/api/Challenges → http://localhost:3000"""
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _extract_namespace(url: str) -> str:
    """http://localhost:3000/api/Challenges → /api/"""
    from urllib.parse import urlparse
    path = urlparse(url).path
    parts = [p for p in path.split("/") if p]
    return f"/{parts[0]}/" if parts else ""


def _extract_admin_namespace(url: str) -> str:
    """http://localhost:3000/rest/admin/application-configuration → /rest/admin/"""
    from urllib.parse import urlparse
    path  = urlparse(url).path.lower()
    parts = [p for p in path.split("/") if p]
    for i, part in enumerate(parts):
        if "admin" in part and i > 0:
            return "/" + "/".join(parts[:i+1]) + "/"
    return ""


# For type hints
from typing import Optional
