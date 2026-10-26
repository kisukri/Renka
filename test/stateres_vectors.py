"""Generates internal/server/testdata/stateres_vectors.json.gz with Synapse's state resolution.

    pip install matrix-synapse==1.163.2
    python test/stateres_vectors.py internal/server/testdata/stateres_vectors.json.gz [rooms] [seed]

Simulates rooms whose event graph forks: each branch adds power level
changes, bans, kicks, joins, leaves, join rule and topic changes (only
events its own state allows), then Synapse resolves the branch states.
Each case lists every event of the room, the state sets and Synapse's result.
"""
import asyncio, collections.abc, copy, gzip, json, random, sys
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse import event_auth
from synapse.state import v2
from synapse.storage.databases.main.event_federation import StateDifference

ROOMS = int(sys.argv[2]) if len(sys.argv) > 2 else 120
rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 7)
USERS = ["@a:x", "@b:x", "@c:y", "@d:y", "@e:z", "@f:z"]


class Clock:
    async def sleep(self, d):
        pass


class Store:
    def __init__(self, em):
        self.em = em

    async def get_events(self, ids, allow_rejected=False):
        return {i: self.em[i] for i in ids if i in self.em}

    def chain(self, ids):
        seen, stack = set(), list(ids)
        while stack:
            i = stack.pop()
            if i in seen:
                continue
            seen.add(i)
            if i in self.em:
                stack.extend(self.em[i].auth_event_ids())
        return seen

    async def get_auth_chain_difference(self, room_id, state_sets, conflicted_state=None, additional=None):
        chains = [self.chain(s) for s in state_sets]
        common = set(chains[0]).intersection(*chains[1:])
        return StateDifference(auth_difference=set(chains[0]).union(*chains[1:]) - common, conflicted_subgraph=None)


class Room:
    def __init__(self, ver):
        self.ver = ver
        self.rv = KNOWN_ROOM_VERSIONS[ver]
        self.events = {}
        self.ts = 1000

    def make(self, state, prev, typ, sk, sender, content):
        self.ts += rng.choice([0, 1, 1, 5, 50])
        d = {"type": typ, "sender": sender, "room_id": "!r:x", "content": content, "prev_events": prev,
             "auth_events": [], "depth": 1 + max([self.events[p].depth for p in prev] or [0]),
             "origin_server_ts": self.ts if rng.random() < 0.8 else rng.randint(900, self.ts),
             "hashes": {"sha256": "x"}, "signatures": {}}
        if sk is not None:
            d["state_key"] = sk
        probe = make_event_from_dict(copy.deepcopy(d), self.rv)
        types = event_auth.auth_types_for_event(self.rv, probe)
        d["auth_events"] = sorted(state[k] for k in types if k in state)
        ev = make_event_from_dict(d, self.rv)
        auth = [self.events[a] for a in ev.auth_event_ids()]
        try:
            if typ == "m.room.create":
                event_auth._check_create(ev)
            else:
                event_auth.check_state_dependent_auth_rules(ev, auth)
        except Exception:
            return None
        self.events[ev.event_id] = ev
        new = dict(state)
        if sk is not None:
            new[(typ, sk)] = ev.event_id
        return ev, new

    def content(self, state, key):
        eid = state.get(key)
        return copy.deepcopy(dict(self.events[eid].content)) if eid else None


def plain(o):
    if isinstance(o, collections.abc.Mapping):
        return {k: plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [plain(v) for v in o]
    return o


def random_event(room, state, prev):
    sender = rng.choice(USERS)
    r = rng.random()
    if r < 0.25:
        pl = room.content(state, ("m.room.power_levels", "")) or {}
        users = pl.setdefault("users", {})
        for _ in range(rng.randint(1, 2)):
            if rng.random() < 0.7:
                users[rng.choice(USERS)] = rng.choice([0, 25, 50, 75, 100])
            else:
                pl[rng.choice(["ban", "kick", "state_default", "events_default", "invite", "redact"])] = rng.choice([0, 25, 50, 100])
        return room.make(state, prev, "m.room.power_levels", "", sender, pl)
    if r < 0.55:
        target = rng.choice(USERS)
        m = rng.choice(["ban", "leave", "leave", "join", "invite"])
        if m == "join":
            sender = target
        return room.make(state, prev, "m.room.member", target, sender, {"membership": m})
    if r < 0.65:
        return room.make(state, prev, "m.room.join_rules", "", sender, {"join_rule": rng.choice(["public", "invite"])})
    if r < 0.85:
        return room.make(state, prev, "m.room.topic", "", sender, {"topic": "t%d" % rng.randint(0, 99)})
    return room.make(state, prev, "m.room.name", "", sender, {"name": "n%d" % rng.randint(0, 99)})


def build_branch(room, state, head, n):
    for _ in range(n * 4):
        if n == 0:
            break
        res = random_event(room, state, [head])
        if res:
            ev, state = res
            head = ev.event_id
            n -= 1
    return state, head


async def resolve(room, sets):
    return await v2.resolve_events_with_store(Clock(), "!r:x", room.rv, sets, None, Store(room.events))


async def main():
    cases = []
    for _ in range(ROOMS):
        room = Room(rng.choice(["10", "11"]))
        c = {"room_version": room.ver}
        if room.ver == "10":
            c["creator"] = "@a:x"
        ev, state = room.make({}, [], "m.room.create", "", "@a:x", c)
        head = ev.event_id
        steps = [("m.room.member", "@a:x", "@a:x", {"membership": "join"}),
                 ("m.room.power_levels", "", "@a:x", {"users": {"@a:x": 100, "@b:x": 50, "@c:y": rng.choice([0, 50, 75])},
                                                     "users_default": 0, "ban": 50, "kick": 50, "state_default": 50}),
                 ("m.room.join_rules", "", "@a:x", {"join_rule": "public"})]
        for u in USERS[1:]:
            if rng.random() < 0.85:
                steps.append(("m.room.member", u, u, {"membership": "join"}))
        for typ, sk, sender, content in steps:
            res = room.make(state, [head], typ, sk, sender, content)
            if res:
                ev, state = res
                head = ev.event_id
        for _round in range(3):
            heads, sets = [], []
            for _b in range(rng.choice([2, 2, 3])):
                bstate, bhead = build_branch(room, state, head, rng.randint(1, 5))
                sets.append(bstate)
                heads.append(bhead)
            resolved = await resolve(room, sets)
            cases.append({
                "room_version": room.ver,
                "events": [plain({"event_id": e.event_id, "type": e.type, "state_key": e.state_key if e.is_state() else None,
                                  "sender": e.sender, "room_id": e.room_id, "content": e.content,
                                  "auth_events": e.auth_event_ids(), "prev_events": e.prev_event_ids(),
                                  "origin_server_ts": e.origin_server_ts, "depth": e.depth}) for e in room.events.values()],
                "state_sets": [[[k[0], k[1], v] for k, v in sorted(s.items())] for s in sets],
                "resolved": [[k[0], k[1], v] for k, v in sorted(dict(resolved).items())],
            })
            # merge the branches and carry on from the resolved state
            state = dict(resolved)
            res = None
            for _try in range(10):
                sender = rng.choice(USERS)
                res = room.make(state, sorted(heads), "m.room.topic", "", sender, {"topic": "merge"})
                if res:
                    break
            if not res:
                break
            ev, state = res
            head = ev.event_id
    with gzip.open(sys.argv[1], "wt") as f:
        json.dump({"cases": cases}, f, sort_keys=True, separators=(",", ":"))
    conflicts = sum(1 for c in cases if c["state_sets"][0] != c["state_sets"][1])
    print(len(cases), "cases,", conflicts, "with conflicts")

asyncio.run(main())
