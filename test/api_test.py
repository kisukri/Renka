"""End-to-end API test for renka. Run the server first, then:
    python test/api_test.py [base_url]
Uses only the Python standard library."""
import json, struct, sys, threading, time, urllib.error, urllib.request, uuid, zlib

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8008"
C = BASE + "/_matrix/client/v3"
failures = 0


def req(method, url, body=None, token=None, raw=None, ctype="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", ctype)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=40) as resp:
            b = resp.read()
            return resp.status, (json.loads(b) if resp.headers.get("Content-Type", "").startswith("application/json") else b), resp.headers
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            b = json.loads(b)
        except Exception:
            pass
        return e.code, b, e.headers


def check(name, cond, info=""):
    global failures
    print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else f"  -> {info}"))
    if not cond:
        failures += 1


def txn():
    return uuid.uuid4().hex


def register(name):
    st, b, _ = req("POST", C + "/register", {"username": name, "password": "password123"})
    check(f"register {name}: UIA challenge", st == 401 and "flows" in b, b)
    st, b, _ = req("POST", C + "/register", {"username": name, "password": "password123",
                                              "auth": {"type": "m.login.dummy", "session": b.get("session")}})
    check(f"register {name}", st == 200 and "access_token" in b, b)
    return b["access_token"], b["user_id"], b["device_id"]


def sync(token, since=None, timeout=0):
    q = f"?timeout={timeout}" + (f"&since={since}" if since else "")
    st, b, _ = req("GET", C + "/sync" + q, token=token)
    assert st == 200, b
    return b


def tiny_png(w, h):
    raw = b"".join(b"\x00" + b"".join(bytes([(x * 7) % 256, (y * 5) % 256, 128]) for x in range(w))
                   for y in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


print("== basics")
st, b, _ = req("GET", BASE + "/_matrix/client/versions")
check("versions", st == 200 and "v1.11" in b["versions"], b)
st, b, _ = req("GET", BASE + "/.well-known/matrix/client")
check("well-known", st == 200 and "m.homeserver" in b, b)
st, b, _ = req("GET", C + "/nonexistent")
check("unknown endpoint -> M_UNRECOGNIZED", st == 404 and b.get("errcode") == "M_UNRECOGNIZED", b)

print("== accounts")
suffix = uuid.uuid4().hex[:6]
alice, alice_id, alice_dev = register("alice" + suffix)
bob, bob_id, bob_dev = register("bob" + suffix)
st, b, _ = req("POST", C + "/register", {"username": "alice" + suffix, "password": "password123",
                                          "auth": {"type": "m.login.dummy"}})
check("duplicate username rejected", st == 400 and b.get("errcode") == "M_USER_IN_USE", b)
st, b, _ = req("POST", C + "/login", {"type": "m.login.password",
                                       "identifier": {"type": "m.id.user", "user": "alice" + suffix}, "password": "wrong"})
check("wrong password rejected", st == 403, b)
st, b, _ = req("POST", C + "/login", {"type": "m.login.password",
                                       "identifier": {"type": "m.id.user", "user": alice_id}, "password": "password123"})
check("login", st == 200 and b.get("user_id") == alice_id, b)
alice2 = b["access_token"]
st, b, _ = req("GET", C + "/account/whoami", token=alice2)
check("whoami", st == 200 and b["user_id"] == alice_id, b)
st, b, _ = req("GET", C + "/account/whoami", token="bogus")
check("bad token -> 401 M_UNKNOWN_TOKEN", st == 401 and b.get("errcode") == "M_UNKNOWN_TOKEN", b)
st, b, _ = req("GET", C + "/devices", token=alice)
check("two devices listed", st == 200 and len(b["devices"]) == 2, b)
st, b, _ = req("POST", C + "/logout", token=alice2)
st, b, _ = req("GET", C + "/account/whoami", token=alice2)
check("logout invalidates token", st == 401, b)
st, b, _ = req("PUT", C + f"/profile/{alice_id}/displayname", {"displayname": "Alice"}, token=alice)
st, b, _ = req("GET", C + f"/profile/{alice_id}")
check("profile", b.get("displayname") == "Alice", b)

print("== rooms")
bob_sync = sync(bob)
bob_since = bob_sync["next_batch"]
st, b, _ = req("POST", C + "/createRoom", {"name": "Test Room", "topic": "hello", "invite": [bob_id],
                                            "room_alias_name": "test" + suffix, "preset": "private_chat"}, token=alice)
check("createRoom", st == 200 and b["room_id"].startswith("!"), b)
room = b["room_id"]
s = sync(bob, bob_since)
check("bob sees invite", room in s["rooms"]["invite"], s["rooms"])
bob_since = s["next_batch"]
st, b, _ = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"msgtype": "m.text", "body": "x"}, token=bob)
check("non-member cannot send", st == 403, b)
st, b, _ = req("GET", C + f"/directory/room/%23test{suffix}:localhost:8008")
check("alias resolves", st == 200 and b.get("room_id") == room, b)
st, b, _ = req("POST", C + f"/join/%23test{suffix}:localhost:8008", {}, token=bob)
check("bob joins via alias", st == 200 and b.get("room_id") == room, b)
s = sync(bob, bob_since)
jr = s["rooms"]["join"].get(room)
check("bob's sync has the room with full state", jr is not None and
      any(e["type"] == "m.room.name" for e in jr["state"]["events"] + jr["timeline"]["events"]), s["rooms"])
check("room summary", jr and jr["summary"]["m.joined_member_count"] == 2, jr and jr.get("summary"))
bob_since = s["next_batch"]

# long-poll: bob waits, alice sends
result = {}
def waiter():
    t0 = time.time()
    result["sync"] = sync(bob, bob_since, timeout=10000)
    result["dt"] = time.time() - t0
th = threading.Thread(target=waiter); th.start()
time.sleep(0.5)
t = txn()
st, b, _ = req("PUT", C + f"/rooms/{room}/send/m.room.message/{t}", {"msgtype": "m.text", "body": "hello bob"}, token=alice)
check("alice sends message", st == 200 and b["event_id"].startswith("$"), b)
msg_id = b["event_id"]
st, b, _ = req("PUT", C + f"/rooms/{room}/send/m.room.message/{t}", {"msgtype": "m.text", "body": "hello bob"}, token=alice)
check("same txn id is idempotent", b.get("event_id") == msg_id, b)
th.join()
s = result["sync"]
tl = s["rooms"]["join"].get(room, {}).get("timeline", {}).get("events", [])
check("long-poll wakes up quickly", result["dt"] < 3, result["dt"])
check("bob receives message", any(e["event_id"] == msg_id and e["content"]["body"] == "hello bob" for e in tl), tl)
check("unread count = 1", s["rooms"]["join"][room]["unread_notifications"]["notification_count"] == 1,
      s["rooms"]["join"][room]["unread_notifications"])
bob_since = s["next_batch"]

for i in range(25):
    req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"msgtype": "m.text", "body": f"msg {i}"}, token=alice)
s = sync(bob, bob_since)
tl = s["rooms"]["join"][room]["timeline"]
check("timeline limited at 20", tl["limited"] and len(tl["events"]) == 20, (tl["limited"], len(tl["events"])))
st, b, _ = req("GET", C + f"/rooms/{room}/messages?dir=b&limit=10&from={tl['prev_batch']}", token=bob)
check("/messages backfills older events", st == 200 and len(b["chunk"]) == 10 and b["chunk"][0]["content"]["body"] == "msg 4",
      [e["content"].get("body") for e in b.get("chunk", [])])
bob_since = s["next_batch"]

st, b, _ = req("POST", C + f"/rooms/{room}/receipt/m.read/{tl['events'][-1]['event_id']}", {}, token=bob)
check("read receipt", st == 200, b)
s = sync(bob, bob_since)
r = s["rooms"]["join"].get(room, {})
check("receipt in ephemeral + unread reset", any(e["type"] == "m.receipt" for e in r.get("ephemeral", {}).get("events", []))
      and r["unread_notifications"]["notification_count"] == 0, r)
bob_since = s["next_batch"]

st, b, _ = req("PUT", C + f"/rooms/{room}/typing/{alice_id}", {"typing": True, "timeout": 5000}, token=alice)
s = sync(bob, bob_since)
eph = s["rooms"]["join"].get(room, {}).get("ephemeral", {}).get("events", [])
check("typing notification", any(e["type"] == "m.typing" and alice_id in e["content"]["user_ids"] for e in eph), eph)
bob_since = s["next_batch"]

print("== permissions")
st, b, _ = req("PUT", C + f"/rooms/{room}/state/m.room.name", {"name": "hacked"}, token=bob)
check("bob (PL 0) cannot rename room", st == 403, b)
st, b, _ = req("POST", C + f"/rooms/{room}/kick", {"user_id": alice_id}, token=bob)
check("bob cannot kick alice", st == 403, b)
st, b, _ = req("GET", C + f"/rooms/{room}/state/m.room.power_levels", token=bob)
pl = b; pl["users"][bob_id] = 100
st, b, _ = req("PUT", C + f"/rooms/{room}/state/m.room.power_levels", pl, token=bob)
check("bob cannot promote himself", st == 403, b)
st, b, _ = req("PUT", C + f"/rooms/{room}/state/m.room.name", {"name": "Renamed"}, token=alice)
check("alice can rename", st == 200, b)
st, b, _ = req("PUT", C + f"/rooms/{room}/redact/{msg_id}/{txn()}", {"reason": "oops"}, token=bob)
check("bob cannot redact alice's message", st == 403, b)
st, b, _ = req("PUT", C + f"/rooms/{room}/redact/{msg_id}/{txn()}", {"reason": "oops"}, token=alice)
check("alice redacts her message", st == 200, b)
st, b, _ = req("GET", C + f"/rooms/{room}/event/{msg_id}", token=bob)
check("redacted content is gone", st == 200 and b["content"] == {} and "redacted_because" in b["unsigned"], b)

print("== threads, context, members")
st, b, _ = req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"msgtype": "m.text", "body": "root"}, token=alice)
root = b["event_id"]
for i in range(2):
    req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"msgtype": "m.text", "body": f"reply {i}",
        "m.relates_to": {"rel_type": "m.thread", "event_id": root}}, token=bob)
st, b, _ = req("GET", BASE + f"/_matrix/client/v1/rooms/{room}/relations/{root}/m.thread", token=alice)
check("relations", st == 200 and len(b["chunk"]) == 2, b)
st, b, _ = req("GET", BASE + f"/_matrix/client/v1/rooms/{room}/threads", token=alice)
check("thread list with summary", st == 200 and b["chunk"][0]["event_id"] == root and
      b["chunk"][0]["unsigned"]["m.relations"]["m.thread"]["count"] == 2, b)
st, b, _ = req("GET", C + f"/rooms/{room}/context/{root}?limit=4", token=bob)
check("context", st == 200 and b["event"]["event_id"] == root and len(b["events_after"]) == 2, b)
st, b, _ = req("GET", C + f"/rooms/{room}/joined_members", token=bob)
check("joined_members", st == 200 and set(b["joined"]) == {alice_id, bob_id}, b)

print("== leave & visibility")
st, b, _ = req("POST", C + f"/rooms/{room}/leave", {}, token=bob)
check("bob leaves", st == 200, b)
s = sync(bob, bob_since)
check("leave shows in sync", room in s["rooms"]["leave"], s["rooms"])
bob_since = s["next_batch"]
req("PUT", C + f"/rooms/{room}/send/m.room.message/{txn()}", {"msgtype": "m.text", "body": "secret after leave"}, token=alice)
st, b, _ = req("GET", C + f"/rooms/{room}/messages?dir=b&limit=5", token=bob)
check("left user can't see new messages", st == 200 and all(e["content"].get("body") != "secret after leave" for e in b["chunk"]), b)
st, b, _ = req("POST", C + f"/rooms/{room}/join", {}, token=bob)
check("cannot rejoin invite-only room uninvited", st == 403, b)

print("== end-to-end encryption plumbing")
st, b, _ = req("POST", C + "/keys/upload", {
    "device_keys": {"user_id": bob_id, "device_id": bob_dev, "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                    "keys": {f"curve25519:{bob_dev}": "ck", f"ed25519:{bob_dev}": "ek"}, "signatures": {}},
    "one_time_keys": {"signed_curve25519:AAA": {"key": "otk1"}, "signed_curve25519:BBB": {"key": "otk2"}},
    "fallback_keys": {"signed_curve25519:FB1": {"key": "fb", "fallback": True}}}, token=bob)
check("keys/upload", st == 200 and b["one_time_key_counts"].get("signed_curve25519") == 2, b)
st, b, _ = req("POST", C + "/keys/query", {"device_keys": {bob_id: []}}, token=alice)
check("keys/query", st == 200 and bob_dev in b["device_keys"][bob_id], b)
for i in range(3):
    st, b, _ = req("POST", C + "/keys/claim", {"one_time_keys": {bob_id: {bob_dev: "signed_curve25519"}}}, token=alice)
check("keys/claim falls back to fallback key", "signed_curve25519:FB1" in b["one_time_keys"][bob_id][bob_dev], b)
alice_since = sync(alice)["next_batch"]
st, b, _ = req("PUT", C + f"/sendToDevice/m.room.encrypted/{txn()}", {"messages": {alice_id: {"*": {"ciphertext": "x"}}}}, token=bob)
s = sync(alice, alice_since)
check("to-device delivered", any(e["sender"] == bob_id for e in s["to_device"]["events"]), s["to_device"])
s2 = sync(alice, s["next_batch"])
check("to-device not repeated", len(s2["to_device"]["events"]) == 0, s2["to_device"])
st, b, _ = req("POST", C + "/room_keys/version", {"algorithm": "m.megolm_backup.v1.curve25519-aes-sha2", "auth_data": {"public_key": "pk"}}, token=bob)
ver = b.get("version")
st, b, _ = req("PUT", C + f"/room_keys/keys?version={ver}", {"rooms": {room: {"sessions": {"sess1": {
    "first_message_index": 0, "forwarded_count": 0, "is_verified": False, "session_data": {"x": 1}}}}}}, token=bob)
check("backup keys upload", st == 200 and b["count"] == 1, b)
st, b, _ = req("GET", C + "/room_keys/version", token=bob)
check("backup version", st == 200 and b["version"] == ver and b["count"] == 1, b)

print("== media")
png = tiny_png(400, 300)
st, b, _ = req("POST", BASE + "/_matrix/media/v3/upload?filename=test.png", raw=png, ctype="image/png", token=alice)
check("upload", st == 200 and b["content_uri"].startswith("mxc://"), b)
mxc = b["content_uri"][6:]
st, b, h = req("GET", BASE + f"/_matrix/client/v1/media/download/{mxc}", token=bob)
check("authenticated download", st == 200 and b == png, (st, len(b) if isinstance(b, bytes) else b))
st, b, h = req("GET", BASE + f"/_matrix/client/v1/media/thumbnail/{mxc}?width=64&height=64&method=scale", token=bob)
check("thumbnail is smaller", st == 200 and b[:4] == b"\x89PNG" and len(b) < len(png), (st, len(b)))
st, b, h = req("GET", BASE + f"/_matrix/client/v1/media/download/{mxc}")
check("v1 download needs auth", st == 401, b)

print("== push rules")
st, b, _ = req("GET", C + "/pushrules/", token=alice)
check("default push rules", st == 200 and any(r["rule_id"] == ".m.rule.message" for r in b["global"]["underride"]), b)
st, b, _ = req("PUT", C + "/pushrules/global/underride/.m.rule.message/enabled", {"enabled": False}, token=alice)
st, b, _ = req("GET", C + "/pushrules/global/underride/.m.rule.message/enabled", token=alice)
check("toggle push rule", st == 200 and b == {"enabled": False}, b)

print()
print("ALL PASSED" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
