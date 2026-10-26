"""Edge-case and regression tests for renka: odd inputs, limits, abuse
attempts and past bugs. Run against a fresh test server (after api_test.py is
fine), e.g.:
    ./renka -config test/test.conf
    python test/edge_test.py [base_url]
The last section trips the login rate limiter for this IP, so restart the
server before running the suites again. Uses only the standard library."""
import http.client, json, struct, sys, threading, time, urllib.error, urllib.parse, urllib.request, uuid, zlib

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8008"
C = BASE + "/_matrix/client/v3"
C1 = BASE + "/_matrix/client/v1"
failures = 0


def req(method, url, body=None, token=None, raw=None, ctype="application/json", headers=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", ctype)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=40) as resp:
            b = resp.read()
            ct = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(b) if ct.startswith("application/json") else b)
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            b = json.loads(b)
        except Exception:
            pass
        return e.code, b


def check(name, cond, info=""):
    global failures
    print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else f"  -> {info}"))
    if not cond:
        failures += 1


def txn():
    return uuid.uuid4().hex


def err(b):
    return b.get("errcode") if isinstance(b, dict) else b


def register(name):
    st, b = req("POST", C + "/register", {"username": name, "password": "password123"})
    st, b = req("POST", C + "/register", {"username": name, "password": "password123",
                                           "auth": {"type": "m.login.dummy", "session": b.get("session")}})
    assert st == 200, b
    return b["access_token"], b["user_id"], b["device_id"]


def sync(token, since=None, extra=""):
    q = "?timeout=0" + (f"&since={since}" if since else "") + extra
    st, b = req("GET", C + "/sync" + q, token=token)
    assert st == 200, b
    return b


def send(token, room, body="hi", **extra):
    content = {"msgtype": "m.text", "body": body, **extra}
    st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", content, token=token)
    assert st == 200, b
    return b["event_id"]


def healthy():
    st, _ = req("GET", BASE + "/_matrix/client/versions")
    return st == 200


def tiny_png(w, h):
    raw = b"".join(b"\x00" + b"".join(bytes([(x * 7) % 256, (y * 5) % 256, 128]) for x in range(w))
                   for y in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


sfx = uuid.uuid4().hex[:6]
alice, alice_id, alice_dev = register("ealice" + sfx)
bob, bob_id, bob_dev = register("ebob" + sfx)
carol, carol_id, carol_dev = register("ecarol" + sfx)
st, b = req("POST", C + "/createRoom", {"preset": "public_chat", "name": "edge"}, token=alice)
room = b["room_id"]
req("POST", C + f"/join/{room}", {}, token=bob)

print("== crash regressions")
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.member/{txn()}", {"membership": "join"}, token=alice)
check("m.room.member via /send -> 400", st == 400, (st, b))
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.power_levels/{txn()}", {"users": {}}, token=alice)
check("m.room.power_levels via /send -> 400", st == 400, (st, b))
for i in range(6):  # used to leak a DB connection each time; 4 would hang the server
    req("PUT", C + f"/rooms/{room}/send/m.room.member/{txn()}", {}, token=alice)
check("server still answers after repeated bad sends", healthy())
for q in ["since=-1", "since=abc", "since=99999999999", "limit=-5", "limit=0&since=-99"]:
    st, b = req("GET", C + f"/publicRooms?{q}")
    check(f"publicRooms?{q} -> 200", st == 200, (st, b))
st, b = req("PUT", C + f"/user/{bob_id}/account_data/m.push_rules", {}, token=bob)
check("raw m.push_rules account data refused (405)", st == 405, (st, b))
st, b = req("PUT", C + f"/user/{bob_id}/rooms/{room}/account_data/m.fully_read", {"event_id": "$x"}, token=bob)
check("raw m.fully_read account data refused (405)", st == 405, (st, b))
st, b = req("GET", C + "/pushrules/", token=bob)
check("push rules still readable", st == 200 and "override" in b.get("global", {}), b)

print("== malformed and extreme JSON")
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", raw=b"{not json", token=alice)
check("invalid JSON -> 400 M_BAD_JSON", st == 400 and err(b) == "M_BAD_JSON", (st, b))
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", raw=b"[1,2,3]", token=alice)
check("array body -> 400", st == 400, (st, b))
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", raw=b'{"body":"' + b"x" * (1 << 20) + b'"}', token=alice)
check("body over 1MB -> 413 M_TOO_LARGE", st == 413 and err(b) == "M_TOO_LARGE", (st, err(b)))
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"body": "x" * 61000}, token=alice)
check("event over 60KB -> 413", st == 413, (st, err(b)))
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", raw=b'{"a":' + b"[" * 20000 + b"]" * 20000 + b"}", token=alice)
check("very deep nesting rejected cleanly", st in (400, 413), (st, err(b)))
big = 9007199254740993  # 2^53 + 1: not representable as a float64
st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"body": "big", "n": big, "neg": -big, "f": 1.25}, token=alice)
if st == 200:  # a local-only room stores any JSON number exactly
    st, b = req("GET", C + f"/rooms/{room}/event/{b['event_id']}", token=bob)
    check("integers above 2^53 stored exactly", st == 200 and b["content"]["n"] == big and b["content"]["neg"] == -big, b.get("content"))
else:  # a federated room (federation = true) holds signed events: integers in range only
    check("federated room refuses numbers it can't sign", st == 400 and err(b) == "M_BAD_JSON", (st, b))
    eid = send(alice, room, "ints", n=2**53 - 1, neg=-(2**53 - 1))
    st, b = req("GET", C + f"/rooms/{room}/event/{eid}", token=bob)
    check("...but keeps safe integers exactly", st == 200 and b["content"]["n"] == 2**53 - 1, b.get("content"))
weird = "emoji 🦊 · RTL שלום · zero​width · null\u0000byte · \U0001F468‍\U0001F469‍\U0001F467"
eid = send(alice, room, weird)
st, b = req("GET", C + f"/rooms/{room}/event/{eid}", token=bob)
check("unicode / NUL body round-trips", st == 200 and b["content"]["body"] == weird, b.get("content"))
st, b = req("PUT", C + f"/rooms/{room}/state/x.edge/a/b/c%2Fd", {"k": 1}, token=alice)
check("state_key with slashes accepted", st == 200, (st, b))
st, b = req("GET", C + f"/rooms/{room}/state/x.edge/a/b/c%2Fd", token=bob)
check("...and read back", st == 200 and b.get("k") == 1, (st, b))

print("== power levels must be integers")
st, pl = req("GET", C + f"/rooms/{room}/state/m.room.power_levels", token=alice)
for name, bad in [("string", "100"), ("float", 50.5), ("huge", 1e20), ("bool", True), ("null", None)]:
    p = json.loads(json.dumps(pl)); p["ban"] = bad
    st, b = req("PUT", C + f"/rooms/{room}/state/m.room.power_levels", p, token=alice)
    check(f"{name} power level rejected", st == 400, (st, b))
p = json.loads(json.dumps(pl)); p["users"]["not-a-user"] = 10
st, b = req("PUT", C + f"/rooms/{room}/state/m.room.power_levels", p, token=alice)
check("non-user key in users rejected", st == 400, (st, b))
st, b = req("POST", C + "/createRoom", {"power_level_content_override": {"kick": "50"}}, token=alice)
check("createRoom override with string level rejected", st == 400, (st, b))
p = json.loads(json.dumps(pl)); p["users"][bob_id] = 10
st, b = req("PUT", C + f"/rooms/{room}/state/m.room.power_levels", p, token=alice)
check("normal power level change still works", st == 200, (st, b))

print("== redaction rules")
st, b = req("GET", C + f"/rooms/{room}/state/m.room.create?format=event", token=alice)
create_id = b.get("event_id")
st, b = req("PUT", C + f"/rooms/{room}/redact/{create_id}/{txn()}", {}, token=alice)
check("m.room.create cannot be redacted", st == 403, (st, b))
root = send(alice, room, "thread root")
replies = [send(bob, room, f"reply {i}", **{"m.relates_to": {"rel_type": "m.thread", "event_id": root}}) for i in range(3)]
st, b = req("PUT", C + f"/rooms/{room}/redact/{replies[0]}/{txn()}", {}, token=bob)
check("bob redacts his own reply", st == 200, (st, b))
st, b = req("GET", C1 + f"/rooms/{room}/relations/{root}/m.thread", token=alice)
ids = [e["event_id"] for e in b.get("chunk", [])]
check("redacted reply left the thread", replies[0] not in ids and len(ids) == 2, ids)
st, b = req("GET", C + f"/rooms/{room}/event/{root}", token=alice)
check("thread summary count updated", b.get("unsigned", {}).get("m.relations", {}).get("m.thread", {}).get("count") == 2, b.get("unsigned"))
p = json.loads(json.dumps(pl)); p["users"][bob_id] = 10; p["events"]["m.room.redaction"] = 100
req("PUT", C + f"/rooms/{room}/state/m.room.power_levels", p, token=alice)
mine = send(bob, room, "my message")
st, b = req("PUT", C + f"/rooms/{room}/redact/{mine}/{txn()}", {}, token=bob)
check("m.room.redaction event level enforced (even on own message)", st == 403, (st, b))
p["events"]["m.room.redaction"] = 0
req("PUT", C + f"/rooms/{room}/state/m.room.power_levels", p, token=alice)

print("== canonical alias must point to the room")
a_alias = f"#edgea{sfx}:" + alice_id.split(":", 1)[1]
st, b = req("PUT", C + f"/directory/room/{urllib.request.quote(a_alias)}", {"room_id": room}, token=alice)
check("alice publishes an alias", st == 200, (st, b))
st, b = req("POST", C + "/createRoom", {}, token=bob)
broom = b["room_id"]
st, b = req("PUT", C + f"/rooms/{broom}/state/m.room.canonical_alias", {"alias": a_alias}, token=bob)
check("can't claim another room's alias", st == 400 and err(b) == "M_BAD_ALIAS", (st, b))
st, b = req("PUT", C + f"/rooms/{broom}/state/m.room.canonical_alias", {"alias": "#nope" + sfx + ":" + alice_id.split(":", 1)[1]}, token=bob)
check("can't use an alias that doesn't exist", st == 400 and err(b) == "M_BAD_ALIAS", (st, b))
st, b = req("PUT", C + f"/rooms/{broom}/state/m.room.canonical_alias", {"alt_aliases": [5]}, token=bob)
check("alt_aliases must be strings", st == 400, (st, b))
b_alias = f"#edgeb{sfx}:" + alice_id.split(":", 1)[1]
req("PUT", C + f"/directory/room/{urllib.request.quote(b_alias)}", {"room_id": broom}, token=bob)
st, b = req("PUT", C + f"/rooms/{broom}/state/m.room.canonical_alias", {"alias": b_alias}, token=bob)
check("own published alias accepted", st == 200, (st, b))
st, b = req("PUT", C + f"/directory/room/{urllib.request.quote('#bad name:' + alice_id.split(':', 1)[1])}", {"room_id": broom}, token=bob)
check("alias with a space rejected", st == 400, (st, b))

print("== former members don't see later state")
st, b = req("POST", C + "/createRoom", {"preset": "public_chat", "name": "before"}, token=alice)
proom = b["room_id"]
req("POST", C + f"/join/{proom}", {}, token=carol)
req("POST", C + f"/rooms/{proom}/leave", {}, token=carol)
req("PUT", C + f"/rooms/{proom}/state/m.room.name", {"name": "after"}, token=alice)
req("POST", C + f"/join/{proom}", {}, token=bob)
st, b = req("GET", C + f"/rooms/{proom}/state/m.room.name", token=carol)
check("left member sees the name as of leaving", st == 200 and b.get("name") == "before", (st, b))
st, b = req("GET", C + f"/rooms/{proom}/members", token=carol)
who = {e["state_key"] for e in b.get("chunk", [])}
check("left member doesn't see later joins", st == 200 and bob_id not in who and carol_id in who, who)
st, b = req("GET", C + f"/rooms/{proom}/state/m.room.name", token=bob)
check("current member sees the new name", b.get("name") == "after", b)

print("== relations pagination both ways")
root2 = send(alice, room, "root2")
kids = [send(alice, room, f"k{i}", **{"m.relates_to": {"rel_type": "m.thread", "event_id": root2}}) for i in range(5)]
for d, expect in [("f", kids), ("b", kids[::-1])]:
    got, frm = [], None
    for _ in range(10):
        q = f"?dir={d}&limit=2" + (f"&from={frm}" if frm else "")
        st, b = req("GET", C1 + f"/rooms/{room}/relations/{root2}{q}", token=alice)
        got += [e["event_id"] for e in b["chunk"]]
        frm = b.get("next_batch")
        if not frm:
            break
    check(f"relations dir={d} pages through all children in order", got == expect, (got, expect))

print("== profile change is not a re-join")
st, b = req("POST", C + "/createRoom", {"invite": [bob_id]}, token=alice)
r3 = b["room_id"]
req("POST", C + f"/join/{r3}", {}, token=bob)
since = sync(alice)["next_batch"]
send(bob, r3, "one"); send(bob, r3, "two")
req("PUT", C + f"/profile/{alice_id}/displayname", {"displayname": "Alice " + sfx}, token=alice)
s = sync(alice, since, extra="&filter=" + urllib.request.quote('{"room":{"timeline":{"limit":1}}}'))
jr = s["rooms"]["join"].get(r3, {})
stypes = [e["type"] for e in jr.get("state", {}).get("events", [])]
check("incremental sync doesn't resend the whole room", "m.room.create" not in stypes, stypes)
s = sync(alice, since)
jr = s["rooms"]["join"].get(r3, {})
check("unread count not reset by the profile change", jr.get("unread_notifications", {}).get("notification_count") == 2,
      jr.get("unread_notifications"))
types = [e["type"] for e in jr.get("timeline", {}).get("events", [])]
check("timeline carries the member update", "m.room.member" in types, types)

print("== cross-signing signatures")
req("POST", C + "/keys/upload", {"device_keys": {"user_id": alice_id, "device_id": alice_dev, "algorithms": [],
    "keys": {f"ed25519:{alice_dev}": "DK"}, "signatures": {alice_id: {f"ed25519:{alice_dev}": "REAL"}}}}, token=alice)
req("POST", C + "/keys/device_signing/upload", {"master_key": {"user_id": alice_id, "usage": ["master"],
    "keys": {"ed25519:AMK" + sfx: "AMK"}}}, token=alice)
st, b = req("POST", C + "/keys/signatures/upload", {alice_id: {alice_dev: {"signatures": {alice_id: {f"ed25519:{alice_dev}": "FORGED"}}}}}, token=bob)
check("forged signature reported as failure", alice_id in b.get("failures", {}), b)
st, b = req("POST", C + "/keys/signatures/upload", {alice_id: {"AMK" + sfx: {"signatures": {bob_id: {"ed25519:BUSK": "BOBSIG"}}}}}, token=bob)
check("signing another user's master key works (user verification)", st == 200 and not b.get("failures"), b)
st, b = req("POST", C + "/keys/query", {"device_keys": {alice_id: []}}, token=carol)
sigs = b["device_keys"][alice_id][alice_dev]["signatures"][alice_id]
check("alice's device signature untouched", sigs.get(f"ed25519:{alice_dev}") == "REAL", sigs)
check("carol can't see bob's verification of alice", "BOBSIG" not in json.dumps(b.get("master_keys")), b.get("master_keys"))
st, b = req("POST", C + "/keys/query", {"device_keys": {alice_id: []}}, token=bob)
check("bob sees his own verification", "BOBSIG" in json.dumps(b.get("master_keys")), b.get("master_keys"))

print("== push rule validation")
st, b = req("PUT", C + "/pushrules/global/override/.m.rule.master/enabled", {"enabled": "yes"}, token=alice)
check("enabled must be a boolean", st == 400, (st, b))
st, b = req("PUT", C + "/pushrules/global/override/.m.rule.master/actions", {"actions": "notify"}, token=alice)
check("actions must be an array", st == 400, (st, b))
st, b = req("PUT", C + "/pushrules/global/content/nopattern", {"actions": []}, token=alice)
check("content rule needs a pattern", st == 400, (st, b))
st, b = req("PUT", C + "/pushrules/global/bogus/x", {"actions": []}, token=alice)
check("unknown kind rejected", st == 400, (st, b))
threads = [threading.Thread(target=req, args=("PUT", C + f"/pushrules/global/room/!r{i}:x", {"actions": []}, alice)) for i in range(10)]
[t.start() for t in threads]; [t.join() for t in threads]
st, b = req("GET", C + "/pushrules/", token=alice)
check("10 concurrent rule adds all kept", len(b["global"]["room"]) == 10, len(b["global"]["room"]))

print("== to-device")
st, b = req("PUT", C + f"/sendToDevice/m.test/{txn()}", {"messages": {bob_id: {"NOSUCHDEVICE": {"x": 1}, bob_dev: {"x": 2}},
    "@ghost:" + alice_id.split(":", 1)[1]: {"*": {"x": 3}}, "@remote:other.org": {"*": {"x": 4}}}}, token=alice)
check("to-device with fake targets accepted", st == 200, (st, b))
td = sync(bob)["to_device"]["events"]
check("real device got exactly its message", [e["content"] for e in td if e["type"] == "m.test"] == [{"x": 2}], td)

print("== media")
png = tiny_png(400, 300)
st, b = req("POST", BASE + "/_matrix/media/v3/upload", raw=png, ctype="image/png", token=alice)
mxc = b["content_uri"][6:]
outs = []
for w, h in [(100, 100), (150, 150), (321, 1), (0, 0), (-1, -1)]:
    st, body = req("GET", BASE + f"/_matrix/media/v3/thumbnail/{mxc}?width={w}&height={h}&method=scale")
    outs.append((st, body))
check("odd thumbnail sizes all served", all(o[0] == 200 for o in outs), [o[0] for o in outs])
check("nearby sizes share one cached thumbnail", outs[0][1] == outs[1][1], (len(outs[0][1]), len(outs[1][1])))
st, b = req("GET", BASE + f"/_matrix/media/v3/thumbnail/{mxc}?width=999999&height=999999&method=crop")
check("huge crop request served", st == 200, st)
for bad in ["..%2F..%2Fetc%2Fpasswd", "x" * 65, "a.b"]:
    st, b = req("GET", BASE + f"/_matrix/media/v3/download/{alice_id.split(':', 1)[1]}/{bad}")
    check(f"bad media id {bad[:20]!r} -> 404", st == 404, st)
st, b = req("GET", BASE + f"/_matrix/media/v3/download/other.org/{mxc.split('/')[1]}")
check("remote server media -> 404", st == 404, st)
# The server answers from Content-Length alone and doesn't read an oversized
# body, so send just the headers and a little data, then read the response.
host = urllib.parse.urlsplit(BASE)
hc = http.client.HTTPConnection(host.hostname, host.port or 80, timeout=10)
hc.putrequest("POST", "/_matrix/media/v3/upload")
hc.putheader("Authorization", "Bearer " + alice)
hc.putheader("Content-Type", "application/octet-stream")
hc.putheader("Content-Length", str(11 << 20))
hc.endheaders()
hc.send(b"x" * 1024)
resp = hc.getresponse()
check("upload over max_upload_mb -> 413 before reading the body", resp.status == 413, resp.status)
hc.close()
st, b = req("POST", BASE + "/_matrix/media/v3/upload", raw=b"<script>alert(1)</script>", ctype="text/html", token=alice)
hid = b["content_uri"][6:]
r = urllib.request.urlopen(BASE + f"/_matrix/media/v3/download/{hid}")
check("uploaded HTML is served as a download, not a page",
      r.headers["Content-Type"] == "application/octet-stream" and "attachment" in r.headers["Content-Disposition"]
      and "sandbox" in r.headers["Content-Security-Policy"], dict(r.headers))

print("== sync and pagination edges")
for since in ["garbage", "s-5", "s99999999999999", ""]:
    st, b = req("GET", C + f"/sync?timeout=0&since={since}", token=bob)
    check(f"sync since={since!r} -> 200", st == 200 and "next_batch" in b, st)
t0 = time.time()
st, b = req("GET", C + f"/sync?timeout=-5&since={sync(bob)['next_batch']}", token=bob)
check("negative timeout returns at once", st == 200 and time.time() - t0 < 2, time.time() - t0)
s = sync(bob, extra="&filter=" + urllib.request.quote('{"room":{"timeline":{"limit":1}}}'))
tl = s["rooms"]["join"][room]["timeline"]
check("inline filter limits the timeline", len(tl["events"]) == 1 and tl["limited"], len(tl["events"]))
for q in ["limit=0", "limit=-1", "limit=abc", "limit=100000", "dir=x", "from=garbage", "from=s5&dir=f", "to=zzz"]:
    st, b = req("GET", C + f"/rooms/{room}/messages?{q}", token=bob)
    check(f"messages?{q} -> no 5xx", st < 500 and (st == 200 or err(b) == "M_INVALID_PARAM"), (st, b))
st, b = req("GET", C + f"/rooms/{room}/context/{root}?limit=-3", token=bob)
check("context with negative limit", st == 200, (st, b))

print("== idempotency under concurrency")
same = txn(); ids = []
def put():
    st, b = req("PUT", C + f"/rooms/{room}/send/m.room.message/{same}", {"msgtype": "m.text", "body": "once"}, token=alice)
    ids.append(b.get("event_id"))
threads = [threading.Thread(target=put) for _ in range(15)]
[t.start() for t in threads]; [t.join() for t in threads]
check("15 parallel sends with one txn id -> one event", len(set(ids)) == 1 and None not in ids, set(ids))

print("== concurrent writes and syncs never fail")
codes = {}; clock = threading.Lock()
def tally(st):
    with clock: codes[st] = codes.get(st, 0) + 1
def spam(tok, n):
    for i in range(40):
        tally(req("PUT", C + f"/rooms/{room}/send/m.room.message/stress{n}-{i}-{sfx}", {"msgtype": "m.text", "body": "s"}, token=tok)[0])
def poller(tok):
    since = sync(tok)["next_batch"]
    for i in range(40):
        st, b = req("GET", C + f"/sync?timeout=0&since={since}", token=tok); tally(st)
        if st == 200: since = b["next_batch"]
ths = [threading.Thread(target=spam, args=(t, n)) for n, t in enumerate([alice, bob, alice, bob, alice, bob])] + \
      [threading.Thread(target=poller, args=(t,)) for t in [alice, bob, carol, alice, bob, carol]]
[t.start() for t in ths]; [t.join() for t in ths]
check("480 concurrent sends/syncs all succeed (no SQLITE_BUSY 500s)", codes.get(200, 0) == 480, codes)

print("== membership edge cases")
st, b = req("POST", C + f"/rooms/{room}/invite", {"user_id": "@x:other.server"}, token=alice)
# federation off: refused; federation on: tried, and the server doesn't exist
check("inviting a user of an unreachable server fails cleanly", st in (403, 502) and ".fed/" not in str(b), (st, b))
st, b = req("POST", C + f"/rooms/{room}/invite", {"user_id": "@nobody" + sfx + ":" + alice_id.split(":", 1)[1]}, token=alice)
check("inviting a non-existent user -> 404", st == 404, (st, b))
st, b = req("POST", C + f"/rooms/{room}/ban", {"user_id": alice_id}, token=bob)
check("low-power user can't ban the admin", st == 403, (st, b))
st, b = req("POST", C + f"/rooms/{room}/ban", {"user_id": alice_id}, token=alice)
check("admin can't ban themselves", st == 403, (st, b))
st, b = req("POST", C + f"/rooms/{room}/kick", {"user_id": carol_id}, token=alice)
check("kicking a non-member refused", st == 403, (st, b))
st, b = req("POST", C + f"/rooms/{room}/unban", {"user_id": carol_id}, token=alice)
check("unbanning a non-banned user refused", st == 403, (st, b))
st, b = req("POST", C + "/join/!doesnotexist:" + alice_id.split(":", 1)[1], {}, token=bob)
check("joining an unknown room -> 404", st == 404, (st, b))
st, b = req("GET", C + f"/rooms/{room}/messages", token=carol)
check("non-member can't read history", st == 403, (st, b))

print("== status page")
r = urllib.request.urlopen(BASE + "/")
body = r.read().decode()
check("/ is plain text, no markup", r.headers["Content-Type"].startswith("text/plain") and "<" not in body and "renka" in body, body)

print("== registration token endpoint without a token configured")
st, b = req("GET", C1 + "/register/m.login.registration_token/validity?token=x")
check("validity says false, no 5xx", st == 200 and b.get("valid") is False, (st, b))

print("== login brute force is rate limited (keep last: blocks this IP)")
codes = []
for i in range(12):
    st, b = req("POST", C + "/login", {"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "ebob" + sfx},
                                       "password": f"wrong{i}"})
    codes.append(st)
    if st == 429:
        break
check("429 after repeated wrong passwords", codes[-1] == 429 and len(codes) <= 11, codes)
st, b = req("POST", C + "/login", {"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "ebob" + sfx},
                                   "password": "password123"})
check("even the right password waits out the lockout", st == 429 and "retry_after_ms" in b, (st, b))
check("server healthy at the end", healthy())

print()
print("ALL PASSED" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
