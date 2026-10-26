"""Checks PDUs written by renka with Synapse's own code.

    RENKA_DUMP_PDUS=/tmp/pdus go test -run TestFederatedRoomEvents ./internal/server
    python check_pdus.py /tmp/pdus.10.json /tmp/pdus.11.json   # in a venv with matrix-synapse

For every event: Synapse computes the same event ID, the content hash and
signature verify, and the event passes Synapse's auth rules against the
auth events it names.
"""
import copy, json, sys
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import make_event_from_dict
from synapse import event_auth
from synapse.crypto.event_signing import check_event_content_hash
from synapse.synapse_rust.events import redact_event_dict
from signedjson.key import decode_verify_key_bytes
from signedjson.sign import verify_signed_json
from unpaddedbase64 import decode_base64

for path in sys.argv[1:]:
    d = json.load(open(path))
    rv = KNOWN_ROOM_VERSIONS[d["version"]]
    vk = decode_verify_key_bytes(d["key_id"], decode_base64(d["key"]))
    by_id = {}
    for i, p in enumerate(d["pdus"]):
        ev = make_event_from_dict(copy.deepcopy(p), rv)
        assert ev.event_id == d["event_ids"][i], "event ID %d: %s vs %s" % (i, ev.event_id, d["event_ids"][i])
        red = redact_event_dict(rv, copy.deepcopy(p))
        verify_signed_json(red, d["server"], vk)
        redacted = ev.type == "m.room.message" and not ev.content
        if not redacted:
            assert check_event_content_hash(ev), "content hash %d" % i
        if ev.type == "m.room.create":
            event_auth._check_create(ev)
        else:
            auth = [by_id[a] for a in ev.auth_event_ids()]
            types = event_auth.auth_types_for_event(rv, ev)
            assert all((a.type, a.state_key) in types for a in auth), "unexpected auth event %d" % i
            event_auth.check_state_dependent_auth_rules(ev, auth)
        by_id[ev.event_id] = ev
    print(path, "ok:", len(d["pdus"]), "events")
