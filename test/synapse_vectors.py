"""Generates internal/server/testdata/synapse_vectors.json.gz from Synapse's own code.

    pip install matrix-synapse==1.163.2
    python test/synapse_vectors.py internal/server/testdata/synapse_vectors.json.gz

auth: Synapse's allow/deny verdict and auth event types for random room
      states and events (room versions 10 and 11)
pdu:  redacted form, content hash, signature and event ID of random events
The output is deterministic for a given Synapse version (fixed seeds/keys).
"""
import base64, collections.abc, copy, gzip, json, random, sys
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse import event_auth
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.synapse_rust.events import redact_event_dict
from signedjson.key import decode_signing_key_base64
from signedjson.sign import sign_json
from unpaddedbase64 import encode_base64

rng = random.Random(20261026)
SEED = base64.b64encode(bytes(range(32))).decode().rstrip("=")
SERVER_KEY = decode_signing_key_base64("ed25519", "a_test", SEED)
IS_KEY = decode_signing_key_base64("ed25519", "0", base64.b64encode(bytes(range(32, 64))).decode().rstrip("="))
IS_PUB = encode_base64(IS_KEY.verify_key.encode())
OTHER_KEY = decode_signing_key_base64("ed25519", "0", base64.b64encode(bytes(range(64, 96))).decode().rstrip("="))
USERS = ["@a:x", "@b:x", "@c:x", "@d:x", "@e:y"]
ROOM = "!r:x"
counter = [0]

def mk(rv, typ, sk, sender, content, prev=None, room=ROOM):
    counter[0] += 1
    d = {"type": typ, "sender": sender, "room_id": room, "content": content,
         "auth_events": [], "prev_events": prev or ["$p%d" % counter[0]], "depth": 5,
         "origin_server_ts": counter[0], "hashes": {"sha256": "x"}, "signatures": {}}
    if sk is not None:
        d["state_key"] = sk
    return make_event_from_dict(d, rv)

def ser(e):
    d = {"event_id": e.event_id, "type": e.type, "sender": e.sender, "room_id": e.room_id, "content": e.content}
    if e.is_state():
        d["state_key"] = e.state_key
    return d

LEVELS = [0, 10, 50, 75, 100, 101]
def rand_pl():
    pl = {}
    for k in ["users_default", "events_default", "state_default", "ban", "kick", "redact", "invite"]:
        if rng.random() < 0.5:
            pl[k] = rng.choice(LEVELS)
    users = {u: rng.choice(LEVELS) for u in USERS if rng.random() < 0.6}
    if users or rng.random() < 0.5:
        pl["users"] = users
    if rng.random() < 0.5:
        pl["events"] = {t: rng.choice([0, 50, 100]) for t in rng.sample(
            ["m.room.message", "m.room.name", "m.room.power_levels", "m.room.member", "m.room.topic",
             "m.room.redaction", "m.room.third_party_invite"], k=rng.randint(0, 3))}
    if rng.random() < 0.3:
        pl["notifications"] = {"room": rng.choice([0, 50, 100])}
    return pl

def mutate_pl(pl):
    pl = copy.deepcopy(pl or {})
    for _ in range(rng.randint(1, 3)):
        r = rng.random()
        if r < 0.3:
            k = rng.choice(["users_default", "events_default", "state_default", "ban", "kick", "redact", "invite"])
            if k in pl and rng.random() < 0.3:
                del pl[k]
            else:
                pl[k] = rng.choice(LEVELS)
        elif r < 0.65:
            u = rng.choice(USERS + ["@new:x"])
            users = pl.setdefault("users", {})
            if u in users and rng.random() < 0.4:
                del users[u]
            else:
                users[u] = rng.choice(LEVELS)
        elif r < 0.8:
            ev = pl.setdefault("events", {})
            ev[rng.choice(["m.room.name", "m.room.power_levels", "x.custom"])] = rng.choice([0, 50, 100, 101])
        elif r < 0.9:
            pl.setdefault("notifications", {})["room"] = rng.choice(LEVELS)
        else:  # invalid types
            bad = rng.choice(["50", 50.5, True, None, [50], 2**60])
            if rng.random() < 0.5:
                pl[rng.choice(["ban", "kick", "users_default"])] = bad
            else:
                pl.setdefault("users", {})[rng.choice(USERS)] = bad
            if rng.random() < 0.2:
                pl["users"] = {"notauser": 50}
    return pl

def tpi_content(target, token, valid, sender_key=IS_KEY):
    signed = {"mxid": target, "token": token}
    if rng.random() < 0.1:
        signed["mxid"] = "@zz:x"
    signed = sign_json(signed, "id.server", sender_key if valid else OTHER_KEY)
    return {"membership": "invite", "third_party_invite": {"display_name": "x", "signed": signed}}

def gen_state(rv, ver):
    state = []
    creator = "@a:x"
    cc = {"room_version": ver}
    if ver == "10":
        cc["creator"] = creator if rng.random() < 0.9 else "@b:x"
    if rng.random() < 0.15:
        cc["m.federate"] = rng.choice([False, True, "yes", 0])
    create = mk(rv, "m.room.create", "", creator, cc, prev=[])
    state.append(create)
    pl = None
    if rng.random() < 0.75:
        pl = rand_pl()
        state.append(mk(rv, "m.room.power_levels", "", creator, pl))
    if rng.random() < 0.85:
        jr = rng.choice(["public", "invite", "knock", "restricted", "knock_restricted", "private", 123, None])
        c = {"join_rule": jr}
        if jr in ("restricted", "knock_restricted"):
            c["allow"] = [{"type": "m.room_membership", "room_id": "!o:x"}]
        if rng.random() < 0.05:
            c = {}
        state.append(mk(rv, "m.room.join_rules", "", creator, c))
    for u in USERS:
        m = rng.choice([None, "join", "join", "invite", "leave", "ban", "knock"])
        if m:
            state.append(mk(rv, "m.room.member", u, u if m in ("join", "leave", "knock") else creator, {"membership": m}))
    toks = []
    if rng.random() < 0.3:
        tok = "tok%d" % rng.randint(0, 9)
        inviter = rng.choice(USERS)
        c = {"display_name": "x", "key_validity_url": "https://id/x"}
        r = rng.random()
        if r < 0.6:
            c["public_key"] = IS_PUB
        elif r < 0.8:
            c["public_keys"] = [{"public_key": IS_PUB}]
        else:
            c["public_key"] = encode_base64(OTHER_KEY.verify_key.encode())
        state.append(mk(rv, "m.room.third_party_invite", tok, inviter, c))
        toks.append((tok, inviter))
    return state, create, pl, toks

def gen_event(rv, ver, state, create, pl, toks):
    r = rng.random()
    sender = rng.choice(USERS)
    prev = None
    if r < 0.55:
        target = sender if rng.random() < 0.5 else rng.choice(USERS)
        m = rng.choice(["join", "join", "invite", "leave", "leave", "ban", "knock", "bogus"])
        c = {"membership": m}
        if m == "join" and rng.random() < 0.3:
            c["join_authorised_via_users_server"] = rng.choice(USERS + [None, 5])
        if m == "invite" and toks and rng.random() < 0.5:
            tok, inviter = rng.choice(toks)
            if rng.random() < 0.7:
                sender = inviter
            c = tpi_content(target, tok, rng.random() < 0.8)
        if m == "join" and rng.random() < 0.25:
            prev = [create.event_id]
        return mk(rv, "m.room.member", target, sender, c, prev=prev)
    if r < 0.75:
        return mk(rv, "m.room.power_levels", "", sender, mutate_pl(pl))
    choice = rng.choice(["msg", "name", "userstate", "tpi", "redaction", "custom_state"])
    if choice == "msg":
        return mk(rv, "m.room.message", None, sender, {"body": "hi", "msgtype": "m.text"})
    if choice == "name":
        return mk(rv, "m.room.name", "", sender, {"name": "n"})
    if choice == "userstate":
        return mk(rv, "x.state", rng.choice(USERS), sender, {})
    if choice == "tpi":
        return mk(rv, "m.room.third_party_invite", "t1", sender, {"public_key": IS_PUB})
    if choice == "redaction":
        c = {"redacts": "$x"} if ver == "11" else {}
        return mk(rv, "m.room.redaction", None, sender, c)
    return mk(rv, "x.custom", "k", sender, {"a": 1})

def check(rv, ev, state):
    types = event_auth.auth_types_for_event(rv, ev)
    auth = [s for s in state if (s.type, s.state_key) in types]
    try:
        if ev.type == "m.room.create":
            event_auth._check_create(ev)
        else:
            event_auth.check_state_dependent_auth_rules(ev, auth)
        return True, sorted([t[0], t[1]] for t in types if isinstance(t[1], str)), ""
    except Exception as e:
        return False, sorted([t[0], t[1]] for t in types if isinstance(t[1], str)), type(e).__name__ + ": " + str(e)[:80]

auth_cases = {"states": [], "cases": []}
for i in range(260):
    ver = rng.choice(["10", "11"])
    rv = KNOWN_ROOM_VERSIONS[ver]
    state, create, pl, toks = gen_state(rv, ver)
    si = len(auth_cases["states"])
    auth_cases["states"].append({"v": ver, "events": [ser(e) for e in state]})
    for j in range(16):
        ev = gen_event(rv, ver, state, create, pl, toks)
        ok, types, why = check(rv, ev, state)
        auth_cases["cases"].append({"s": si, "event": ser(ev), "prev": ev.prev_event_ids(), "allow": ok,
                                    "types": types, "why": why})
# create events
for i in range(60):
    ver = rng.choice(["10", "11"])
    rv = KNOWN_ROOM_VERSIONS[ver]
    c = {}
    if rng.random() < 0.9:
        c["room_version"] = rng.choice(["10", "11", "1", "99", 10])
    if rng.random() < 0.7:
        c["creator"] = "@a:x"
    room = rng.choice(["!r:x", "!r:y"])
    prev = [] if rng.random() < 0.8 else ["$z"]
    try:
        ev = mk(rv, "m.room.create", "", "@a:x", c, prev=prev, room=room)
        ev.prev_event_ids()
    except Exception:
        continue
    if not prev:
        # mk() uses a placeholder when prev is empty; rebuild with none
        d = {"type": "m.room.create", "state_key": "", "sender": "@a:x", "room_id": room, "content": c,
             "auth_events": [], "prev_events": [], "depth": 1, "origin_server_ts": 1, "hashes": {"sha256": "x"}, "signatures": {}}
        ev = make_event_from_dict(d, rv)
    ok, types, why = check(rv, ev, [])
    auth_cases["states"].append({"v": ver, "events": []})
    auth_cases["cases"].append({"s": len(auth_cases["states"]) - 1, "event": ser(ev), "prev": ev.prev_event_ids(),
                                "allow": ok, "types": types, "why": why})

# ---- PDU vectors ----
def rand_value(depth=0):
    r = rng.random()
    if depth > 2 or r < 0.3:
        return rng.choice(["s", "ü x", "\x01", 0, -5, 2**53 - 1, True, False, None, "<&>"])
    if r < 0.65:
        return {rng.choice(["a", "b", "é", "é", "Z", "membership", "signed"]): rand_value(depth + 1) for _ in range(rng.randint(0, 3))}
    return [rand_value(depth + 1) for _ in range(rng.randint(0, 3))]

pdu_cases = []
TYPES = ["m.room.member", "m.room.create", "m.room.power_levels", "m.room.join_rules", "m.room.history_visibility",
         "m.room.redaction", "m.room.message", "m.room.aliases", "m.room.name"]
KEYS = {"m.room.member": ["membership", "join_authorised_via_users_server", "displayname", "third_party_invite", "reason"],
        "m.room.create": ["creator", "room_version", "m.federate", "type", "predecessor"],
        "m.room.power_levels": ["ban", "events", "events_default", "kick", "redact", "state_default", "users",
                                "users_default", "invite", "notifications", "historical"],
        "m.room.join_rules": ["join_rule", "allow", "x"],
        "m.room.history_visibility": ["history_visibility", "x"],
        "m.room.redaction": ["redacts", "reason"],
        "m.room.aliases": ["aliases", "x"]}
for i in range(240):
    ver = rng.choice(["10", "11"])
    rv = KNOWN_ROOM_VERSIONS[ver]
    typ = rng.choice(TYPES)
    content = {}
    for k in rng.sample(KEYS.get(typ, ["body", "msgtype"]), k=rng.randint(0, len(KEYS.get(typ, ["body", "msgtype"])))):
        content[k] = rand_value()
    if typ == "m.room.member" and "third_party_invite" in content and rng.random() < 0.6:
        content["third_party_invite"] = {"display_name": "x", "signed": {"mxid": "@a:x", "token": "t", "signatures": {}}}
    d = {"type": typ, "sender": "@a:test.server", "room_id": "!r:test.server", "content": content,
         "auth_events": ["$a1", "$a2"][: rng.randint(0, 2)], "prev_events": ["$p1"], "depth": rng.randint(1, 2**40),
         "origin_server_ts": rng.randint(0, 2**45)}
    if typ != "m.room.message" or rng.random() < 0.2:
        d["state_key"] = rng.choice(["", "@a:test.server", "x"])
    for extra in ["origin", "membership", "prev_state", "redacts", "unsigned", "zzz"]:
        if rng.random() < 0.15:
            d[extra] = {"unsigned": {"age_ts": 5, "replaces_state": "$r", "foo": 1}, "prev_state": [],
                        "membership": "join", "origin": "test.server"}.get(extra, "v")
    inp = copy.deepcopy(d)
    red = redact_event_dict(rv, copy.deepcopy(d))
    signed = copy.deepcopy(d)
    add_hashes_and_signatures(rv, signed, "test.server", SERVER_KEY)
    eid = make_event_from_dict(copy.deepcopy(signed), rv).event_id
    pdu_cases.append({"v": ver, "in": inp, "redacted": red, "hashes": signed["hashes"],
                      "signatures": signed["signatures"], "event_id": eid})

# fixed edge shapes (third_party_invite redaction in v11, create content)
fixed = [("m.room.member", {"membership": "join", "third_party_invite": t}) for t in
         [{}, {"x": 1}, {"signed": 5}, "str", None, [1], {"signed": None, "y": 2}]]
fixed += [("m.room.create", {"creator": "@a:test.server", "room_version": "11", "m.federate": False, "x": {"y": [1]}}),
          ("m.room.redaction", {"redacts": "$e", "reason": "r"}),
          ("m.room.power_levels", {"invite": 5, "ban": 1, "notifications": {"room": 1}, "historical": 100})]
for ver in ["10", "11"]:
    rv = KNOWN_ROOM_VERSIONS[ver]
    for typ, content in fixed:
        d = {"type": typ, "sender": "@a:test.server", "room_id": "!r:test.server", "content": content, "state_key": "",
             "auth_events": ["$a"], "prev_events": ["$p"], "depth": 3, "origin_server_ts": 1, "redacts": "$e",
             "origin": "test.server", "membership": "join", "prev_state": [], "unsigned": {"age_ts": 1, "x": 2}}
        inp = copy.deepcopy(d)
        red = redact_event_dict(rv, copy.deepcopy(d))
        signed = copy.deepcopy(d)
        add_hashes_and_signatures(rv, signed, "test.server", SERVER_KEY)
        eid = make_event_from_dict(copy.deepcopy(signed), rv).event_id
        pdu_cases.append({"v": ver, "in": inp, "redacted": red, "hashes": signed["hashes"],
                          "signatures": signed["signatures"], "event_id": eid})

out = {"seed": SEED, "is_pub": IS_PUB, "auth": auth_cases, "pdu": pdu_cases}
with gzip.open(sys.argv[1], "wt") as f:
    def dflt(o):
        if isinstance(o, collections.abc.Mapping): return dict(o)
        if isinstance(o, collections.abc.Sequence): return list(o)
        raise TypeError(type(o))
    json.dump(out, f, sort_keys=True, separators=(",", ":"), default=dflt)
n = len(auth_cases["cases"])
print(n, "auth cases,", sum(c["allow"] for c in auth_cases["cases"]), "allowed;", len(pdu_cases), "pdu cases")
