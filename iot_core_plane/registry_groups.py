"""SQLite WAL Thing Registry & Incremental Inverted-Index Dynamic Thing Groups.

Models AWS IoT Core Thing Registry (`Thing`, `ThingType`, searchable `attributes`,
`billing_group`, `version`) alongside Fleet Indexing Dynamic Thing Groups:
  - Parses fleet query strings such as:
      `firmware_version < 2.4.0 AND temp_c > 75`
      `battery_pct < 20 AND connectivity = DISCONNECTED`
      `cert_days_remaining <= 14 AND region = us-west-2`
  - Maintains an inverted index + field-to-group subscription map so updating a
    single Thing's attributes or reported shadow re-evaluates ONLY the Dynamic
    Thing Groups referencing the mutated fields in O(k) sub-millisecond time,
    avoiding O(N) full-fleet linear scans.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

CLAUSE_RE = re.compile(r"^\s*([a-zA-Z0-9_.\-]+)\s*(<=|>=|!=|=|<|>)\s*(.+?)\s*$")
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")


def _normalize_comparable(raw: Any) -> Tuple[int, Any]:
    """Converts values into typed comparable tuples: (type_rank, value) for semver, float, or str."""
    if isinstance(raw, bool):
        return (2, "true" if raw else "false")
    if isinstance(raw, (int, float)):
        return (0, float(raw))
    text = str(raw).strip().strip("'").strip('"')
    m = SEMVER_RE.match(text)
    if m:
        return (1, (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)))
    try:
        return (0, float(text))
    except ValueError:
        return (2, text)


@dataclass
class QueryClause:
    field_name: str
    operator: str
    raw_rhs: str
    comp_rhs: Tuple[int, Any]

    def matches(self, attrs: Dict[str, Any]) -> bool:
        if self.field_name not in attrs or attrs[self.field_name] is None:
            return False
        lhs = _normalize_comparable(attrs[self.field_name])
        rhs = self.comp_rhs
        if lhs[0] != rhs[0]:
            # Fallback string comparison if types differ
            l_val, r_val = str(attrs[self.field_name]), self.raw_rhs
        else:
            l_val, r_val = lhs[1], rhs[1]

        op = self.operator
        if op == "=":
            return l_val == r_val
        if op == "!=":
            return l_val != r_val
        if op == "<":
            return l_val < r_val
        if op == "<=":
            return l_val <= r_val
        if op == ">":
            return l_val > r_val
        if op == ">=":
            return l_val >= r_val
        return False


def parse_fleet_query(query_string: str) -> List[QueryClause]:
    """Parses conjunctive AWS IoT Fleet Indexing query expressions (`A op X AND B op Y`)."""
    parts = re.split(r"\s+AND\s+", query_string.strip(), flags=re.IGNORECASE)
    clauses: List[QueryClause] = []
    for part in parts:
        if not part.strip():
            continue
        m = CLAUSE_RE.match(part)
        if not m:
            raise ValueError(f"Invalid Dynamic Thing Group query clause: '{part}'")
        field_name, op, rhs_raw = m.group(1), m.group(2), m.group(3).strip().strip("'").strip('"')
        clauses.append(
            QueryClause(
                field_name=field_name,
                operator=op,
                raw_rhs=rhs_raw,
                comp_rhs=_normalize_comparable(rhs_raw),
            )
        )
    if not clauses:
        raise ValueError("Dynamic Thing Group query cannot be empty")
    return clauses


@dataclass
class ThingRecord:
    thing_name: str
    thing_arn: str
    thing_type: str
    billing_group: str
    version: int
    attributes: Dict[str, Any]
    dynamic_groups: List[str]
    updated_at_utc: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "thing_name": self.thing_name,
            "thing_arn": self.thing_arn,
            "thing_type": self.thing_type,
            "billing_group": self.billing_group,
            "version": self.version,
            "attributes": dict(self.attributes),
            "dynamic_groups": list(self.dynamic_groups),
            "updated_at_utc": self.updated_at_utc,
        }


@dataclass
class DynamicGroupRecord:
    group_name: str
    group_arn: str
    query_string: str
    description: str
    indexed_fields: List[str]
    member_count: int
    sample_members: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_name": self.group_name,
            "group_arn": self.group_arn,
            "query_string": self.query_string,
            "description": self.description,
            "indexed_fields": list(self.indexed_fields),
            "member_count": self.member_count,
            "sample_members": list(self.sample_members),
        }


class ThingRegistry:
    """SQLite WAL Thing Registry with an incremental inverted index for Dynamic Thing Groups."""

    def __init__(
        self,
        db_path: Path,
        region: str = "us-west-2",
        account_id: str = "796330847946",
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.region = region
        self.account_id = account_id
        self._lock = threading.RLock()

        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

        # In-memory inverted index structures synchronized with SQLite WAL
        self._thing_attrs: Dict[str, Dict[str, Any]] = {}
        self._thing_meta: Dict[str, Tuple[str, str, int, str]] = {}  # (thing_type, billing_group, version, updated_at)
        # Equality inverted posting lists: field -> value_str -> Set[thing_name]
        self._eq_postings: Dict[str, Dict[str, Set[str]]] = {}
        # Dynamic Thing Group ASTs and live membership sets
        self._group_clauses: Dict[str, List[QueryClause]] = {}
        self._group_descriptions: Dict[str, str] = {}
        self._group_queries: Dict[str, str] = {}
        self._group_members: Dict[str, Set[str]] = {}
        self._thing_to_groups: Dict[str, Set[str]] = {}
        # Reverse field subscription index: field_name -> Set[group_name]
        self._field_to_groups: Dict[str, Set[str]] = {}

        self._reload_from_sqlite()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS things (
                    thing_name TEXT PRIMARY KEY,
                    thing_type TEXT NOT NULL,
                    billing_group TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    attributes_json TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dynamic_groups (
                    group_name TEXT PRIMARY KEY,
                    query_string TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS group_memberships (
                    group_name TEXT NOT NULL,
                    thing_name TEXT NOT NULL,
                    PRIMARY KEY (group_name, thing_name)
                );
                """
            )

    def _reload_from_sqlite(self) -> None:
        cur = self._conn.cursor()
        for g_name, q_str, desc in cur.execute("SELECT group_name, query_string, description FROM dynamic_groups"):
            clauses = parse_fleet_query(q_str)
            self._group_clauses[g_name] = clauses
            self._group_queries[g_name] = q_str
            self._group_descriptions[g_name] = desc
            self._group_members[g_name] = set()
            for cl in clauses:
                self._field_to_groups.setdefault(cl.field_name, set()).add(g_name)

        for t_name, t_type, b_grp, ver, attrs_json, upd in cur.execute(
            "SELECT thing_name, thing_type, billing_group, version, attributes_json, updated_at_utc FROM things"
        ):
            attrs = json.loads(attrs_json)
            self._thing_attrs[t_name] = attrs
            self._thing_meta[t_name] = (t_type, b_grp, int(ver), upd)
            self._index_equality_fields(t_name, {}, attrs)
            self._thing_to_groups[t_name] = set()
            for g_name, clauses in self._group_clauses.items():
                if all(cl.matches(attrs) for cl in clauses):
                    self._group_members[g_name].add(t_name)
                    self._thing_to_groups[t_name].add(g_name)

    def _index_equality_fields(self, thing_name: str, old_attrs: Dict[str, Any], new_attrs: Dict[str, Any]) -> None:
        for k, old_v in old_attrs.items():
            if new_attrs.get(k) != old_v:
                bucket = self._eq_postings.get(k, {}).get(str(old_v))
                if bucket is not None:
                    bucket.discard(thing_name)
        for k, new_v in new_attrs.items():
            if old_attrs.get(k) != new_v and new_v is not None:
                self._eq_postings.setdefault(k, {}).setdefault(str(new_v), set()).add(thing_name)

    def create_dynamic_thing_group(
        self,
        *,
        group_name: str,
        query_string: str,
        description: str = "",
    ) -> DynamicGroupRecord:
        """Registers a Dynamic Thing Group and populates initial membership via inverted index."""
        with self._lock:
            clauses = parse_fleet_query(query_string)
            now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Seed candidates using equality posting list intersection when available
            candidate_names: Optional[Set[str]] = None
            rem_clauses: List[QueryClause] = []
            for cl in clauses:
                if cl.operator == "=" and cl.field_name in self._eq_postings:
                    eq_set = set(self._eq_postings[cl.field_name].get(cl.raw_rhs, set()))
                    candidate_names = eq_set if candidate_names is None else (candidate_names & eq_set)
                else:
                    rem_clauses.append(cl)

            pool = candidate_names if candidate_names is not None else set(self._thing_attrs.keys())
            matched = {
                t_name
                for t_name in pool
                if all(c.matches(self._thing_attrs[t_name]) for c in (rem_clauses if candidate_names is not None else clauses))
            }

            # Clear old field subscriptions if updating an existing group
            for f_set in self._field_to_groups.values():
                f_set.discard(group_name)
            for t_set in self._thing_to_groups.values():
                t_set.discard(group_name)

            self._group_clauses[group_name] = clauses
            self._group_queries[group_name] = query_string
            self._group_descriptions[group_name] = description
            self._group_members[group_name] = matched
            for cl in clauses:
                self._field_to_groups.setdefault(cl.field_name, set()).add(group_name)
            for t_name in matched:
                self._thing_to_groups.setdefault(t_name, set()).add(group_name)

            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO dynamic_groups (group_name, query_string, description, created_at_utc)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(group_name) DO UPDATE SET
                        query_string=excluded.query_string,
                        description=excluded.description
                    """,
                    (group_name, query_string, description, now_iso),
                )
                self._conn.execute("DELETE FROM group_memberships WHERE group_name=?", (group_name,))
                if matched:
                    self._conn.executemany(
                        "INSERT INTO group_memberships (group_name, thing_name) VALUES (?, ?)",
                        [(group_name, t) for t in matched],
                    )

            return self.get_dynamic_group(group_name)

    def upsert_thing(
        self,
        thing_name: str,
        thing_type: str = "IndustrialGatewayV2",
        billing_group: str = "industrial-fleet-west",
        attributes: Optional[Dict[str, Any]] = None,
        persist_sqlite: bool = True,
    ) -> ThingRecord:
        """Creates or replaces a Thing and incrementally updates affected Dynamic Thing Groups."""
        with self._lock:
            old_attrs = dict(self._thing_attrs.get(thing_name, {}))
            old_meta = self._thing_meta.get(thing_name)
            new_ver = (old_meta[2] + 1) if old_meta else 1
            merged_attrs = dict(old_attrs)
            if attributes:
                merged_attrs.update(attributes)
            merged_attrs["thing_type"] = thing_type
            merged_attrs["billing_group"] = billing_group

            now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._index_equality_fields(thing_name, old_attrs, merged_attrs)
            self._thing_attrs[thing_name] = merged_attrs
            self._thing_meta[thing_name] = (thing_type, billing_group, new_ver, now_iso)

            changed_fields = {k for k, v in merged_attrs.items() if old_attrs.get(k) != v}
            if not old_meta:
                affected_groups = set(self._group_clauses.keys())
            else:
                affected_groups = set()
                for f in changed_fields:
                    affected_groups.update(self._field_to_groups.get(f, set()))

            t_groups = self._thing_to_groups.setdefault(thing_name, set())
            added_groups: List[str] = []
            removed_groups: List[str] = []

            for g_name in affected_groups:
                clauses = self._group_clauses[g_name]
                is_match = all(cl.matches(merged_attrs) for cl in clauses)
                was_member = thing_name in self._group_members[g_name]
                if is_match and not was_member:
                    self._group_members[g_name].add(thing_name)
                    t_groups.add(g_name)
                    added_groups.append(g_name)
                elif not is_match and was_member:
                    self._group_members[g_name].discard(thing_name)
                    t_groups.discard(g_name)
                    removed_groups.append(g_name)

            if persist_sqlite:
                with self._conn:
                    self._conn.execute(
                        """
                        INSERT INTO things (thing_name, thing_type, billing_group, version, attributes_json, updated_at_utc)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(thing_name) DO UPDATE SET
                            thing_type=excluded.thing_type,
                            billing_group=excluded.billing_group,
                            version=excluded.version,
                            attributes_json=excluded.attributes_json,
                            updated_at_utc=excluded.updated_at_utc
                        """,
                        (thing_name, thing_type, billing_group, new_ver, json.dumps(merged_attrs, sort_keys=True), now_iso),
                    )
                    for g_add in added_groups:
                        self._conn.execute(
                            "INSERT OR IGNORE INTO group_memberships (group_name, thing_name) VALUES (?, ?)",
                            (g_add, thing_name),
                        )
                    for g_rem in removed_groups:
                        self._conn.execute(
                            "DELETE FROM group_memberships WHERE group_name=? AND thing_name=?",
                            (g_rem, thing_name),
                        )

            return self.get_thing(thing_name)

    def update_thing_attributes(
        self,
        thing_name: str,
        attribute_patch: Dict[str, Any],
        persist_sqlite: bool = True,
    ) -> Dict[str, Any]:
        """Incrementally updates attributes on an existing Thing and returns group membership transitions."""
        t0 = time.perf_counter()
        with self._lock:
            if thing_name not in self._thing_meta:
                rec = self.upsert_thing(thing_name=thing_name, attributes=attribute_patch, persist_sqlite=persist_sqlite)
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
                return {
                    "thing": rec.to_dict(),
                    "groups_added": rec.dynamic_groups,
                    "groups_removed": [],
                    "reindex_ms": elapsed_ms,
                }
            before_groups = set(self._thing_to_groups.get(thing_name, set()))
            t_type, b_grp, _, _ = self._thing_meta[thing_name]
            rec = self.upsert_thing(
                thing_name=thing_name,
                thing_type=t_type,
                billing_group=b_grp,
                attributes=attribute_patch,
                persist_sqlite=persist_sqlite,
            )
            after_groups = set(rec.dynamic_groups)
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "thing": rec.to_dict(),
                "groups_added": sorted(after_groups - before_groups),
                "groups_removed": sorted(before_groups - after_groups),
                "reindex_ms": elapsed_ms,
            }

    def query_fleet_inverted_index(self, query_string: str) -> Dict[str, Any]:
        """Executes an ad-hoc Fleet Indexing query using equality posting lists + predicate filter."""
        t0 = time.perf_counter()
        with self._lock:
            clauses = parse_fleet_query(query_string)
            candidates: Optional[Set[str]] = None
            rem_clauses: List[QueryClause] = []
            for cl in clauses:
                if cl.operator == "=" and cl.field_name in self._eq_postings:
                    eq_matches = set(self._eq_postings[cl.field_name].get(cl.raw_rhs, set()))
                    candidates = eq_matches if candidates is None else (candidates & eq_matches)
                else:
                    rem_clauses.append(cl)
            pool = candidates if candidates is not None else set(self._thing_attrs.keys())
            check_clauses = rem_clauses if candidates is not None else clauses
            matched_names = sorted(
                t_name for t_name in pool if all(c.matches(self._thing_attrs[t_name]) for c in check_clauses)
            )
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "query_string": query_string,
                "matched_count": len(matched_names),
                "total_fleet_count": len(self._thing_attrs),
                "query_ms": elapsed_ms,
                "things": [self.get_thing(t).to_dict() for t in matched_names[:25]],
                "matched_thing_names": matched_names[:100],
            }

    def full_linear_scan_all_groups(self) -> Dict[str, Any]:
        """Baseline O(N * G) SQLite JSON deserialization + full linear scan for benchmark comparison."""
        t0 = time.perf_counter()
        with self._lock:
            rows = self._conn.execute("SELECT thing_name, attributes_json FROM things").fetchall()
            group_counts: Dict[str, int] = {g: 0 for g in self._group_clauses}
            for _t_name, raw_json in rows:
                attrs = json.loads(raw_json)
                for g_name, clauses in self._group_clauses.items():
                    if all(cl.matches(attrs) for cl in clauses):
                        group_counts[g_name] += 1
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            return {
                "fleet_scanned": len(rows),
                "groups_evaluated": len(self._group_clauses),
                "group_counts": group_counts,
                "linear_scan_ms": elapsed_ms,
            }

    def get_thing(self, thing_name: str) -> ThingRecord:
        with self._lock:
            if thing_name not in self._thing_meta:
                raise KeyError(f"Thing '{thing_name}' not found in Registry")
            t_type, b_grp, ver, upd = self._thing_meta[thing_name]
            return ThingRecord(
                thing_name=thing_name,
                thing_arn=f"arn:aws:iot:{self.region}:{self.account_id}:thing/{thing_name}",
                thing_type=t_type,
                billing_group=b_grp,
                version=ver,
                attributes=dict(self._thing_attrs[thing_name]),
                dynamic_groups=sorted(self._thing_to_groups.get(thing_name, set())),
                updated_at_utc=upd,
            )

    def get_dynamic_group(self, group_name: str) -> DynamicGroupRecord:
        with self._lock:
            if group_name not in self._group_clauses:
                raise KeyError(f"Dynamic Thing Group '{group_name}' not found")
            members = sorted(self._group_members[group_name])
            fields = sorted({c.field_name for c in self._group_clauses[group_name]})
            return DynamicGroupRecord(
                group_name=group_name,
                group_arn=f"arn:aws:iot:{self.region}:{self.account_id}:thinggroup/{group_name}",
                query_string=self._group_queries[group_name],
                description=self._group_descriptions[group_name],
                indexed_fields=fields,
                member_count=len(members),
                sample_members=members[:12],
            )

    def list_dynamic_groups(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self.get_dynamic_group(g).to_dict() for g in sorted(self._group_clauses.keys())]

    def list_things(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._lock:
            names = sorted(self._thing_meta.keys())[:limit]
            return [self.get_thing(n).to_dict() for n in names]

    def total_things(self) -> int:
        with self._lock:
            return len(self._thing_meta)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def flush_bulk(self) -> None:
        """Persists all in-memory Things and Dynamic Thing Group memberships to SQLite in one transaction."""
        with self._lock, self._conn:
            self._conn.executemany(
                """
                INSERT INTO things (thing_name, thing_type, billing_group, version, attributes_json, updated_at_utc)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(thing_name) DO UPDATE SET
                    thing_type=excluded.thing_type,
                    billing_group=excluded.billing_group,
                    version=excluded.version,
                    attributes_json=excluded.attributes_json,
                    updated_at_utc=excluded.updated_at_utc
                """,
                [
                    (
                        t_name,
                        self._thing_meta[t_name][0],
                        self._thing_meta[t_name][1],
                        self._thing_meta[t_name][2],
                        json.dumps(self._thing_attrs[t_name], sort_keys=True),
                        self._thing_meta[t_name][3],
                    )
                    for t_name in self._thing_meta
                ],
            )
            self._conn.execute("DELETE FROM group_memberships")
            membership_rows = [
                (g_name, t_name)
                for g_name, members in self._group_members.items()
                for t_name in members
            ]
            if membership_rows:
                self._conn.executemany(
                    "INSERT INTO group_memberships (group_name, thing_name) VALUES (?, ?)",
                    membership_rows,
                )
