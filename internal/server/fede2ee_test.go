package server

import (
	"context"
	"testing"
)

func deviceOf(s *Server, uid string) string {
	var d string
	s.db.QueryRow("SELECT device_id FROM devices WHERE user_id = ? ORDER BY device_id LIMIT 1", uid).Scan(&d)
	return d
}

func uploadKeys(t *testing.T, u fedUser, dev string) {
	t.Helper()
	code, res := u.do(t, "POST", "/_matrix/client/v3/keys/upload", map[string]any{
		"device_keys": map[string]any{"user_id": u.id, "device_id": dev, "algorithms": []string{"m.olm.v1.curve25519-aes-sha2"},
			"keys":       map[string]any{"curve25519:" + dev: "curve-" + dev, "ed25519:" + dev: "ed-" + dev},
			"signatures": map[string]any{u.id: map[string]any{"ed25519:" + dev: "sig"}}},
		"one_time_keys": map[string]any{"signed_curve25519:AAAA": map[string]any{"key": "otk1"}, "signed_curve25519:BBBB": map[string]any{"key": "otk2"}},
	})
	if code != 200 {
		t.Fatalf("keys/upload: %d %v", code, res)
	}
}

func TestEncryptionAcrossServers(t *testing.T) {
	ss, hs := fedServers(t, 3)
	aid, at := addUser(t, ss[0], "alice")
	bid, bt := addUser(t, ss[1], "bob")
	cid, ct := addUser(t, ss[2], "carol")
	alice, bob, carol := fedUser{ss[0], hs[0], aid, at}, fedUser{ss[1], hs[1], bid, bt}, fedUser{ss[2], hs[2], cid, ct}
	room := sharedRoom(t, alice, bob, "private_chat")
	bdev, adev := deviceOf(bob.s, bid), deviceOf(alice.s, aid)
	uploadKeys(t, bob, bdev)
	uploadKeys(t, alice, adev)
	// bob's cross-signing master key
	if code, res := bob.do(t, "POST", "/_matrix/client/v3/keys/device_signing/upload", map[string]any{
		"master_key": map[string]any{"user_id": bid, "usage": []string{"master"}, "keys": map[string]any{"ed25519:BOBMASTER": "BOBMASTER"}}}); code != 200 {
		t.Fatalf("cross-signing upload: %d %v", code, res)
	}

	// alice fetches bob's keys from his server
	_, q := alice.do(t, "POST", "/_matrix/client/v3/keys/query", map[string]any{"device_keys": map[string]any{bid: []string{}}})
	devs, _ := q["device_keys"].(map[string]any)[bid].(map[string]any)
	if _, ok := devs[bdev]; !ok {
		t.Fatalf("bob's device keys not found: %v", q)
	}
	if _, ok := q["master_keys"].(map[string]any)[bid]; !ok {
		t.Errorf("bob's master key not found: %v", q)
	}

	// and claims a one-time key
	_, c := alice.do(t, "POST", "/_matrix/client/v3/keys/claim", map[string]any{"one_time_keys": map[string]any{bid: map[string]any{bdev: "signed_curve25519"}}})
	if got, _ := c["one_time_keys"].(map[string]any)[bid].(map[string]any)[bdev].(map[string]any); len(got) != 1 {
		t.Fatalf("one-time key claim: %v", c)
	}
	if n := bob.s.otkCounts(bid, bdev)["signed_curve25519"]; n != 1 {
		t.Errorf("bob has %d one-time keys left, want 1", n)
	}

	// to-device messages (how room keys travel)
	if code, res := alice.do(t, "PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/t1", map[string]any{
		"messages": map[string]any{bid: map[string]any{bdev: map[string]any{"ciphertext": "secret"}}}}); code != 200 {
		t.Fatal(code, res)
	}
	waitFor(t, "to-device on B", func() bool {
		var sender string
		bob.s.db.QueryRow("SELECT sender FROM to_device WHERE user_id = ? AND device_id = ?", bid, bdev).Scan(&sender)
		return sender == aid
	})

	// bob's devices change: alice's sync is told to re-fetch
	_, sync := alice.do(t, "GET", "/_matrix/client/v3/sync", nil)
	since := sync["next_batch"].(string)
	uploadKeys(t, bob, bdev) // same keys: no change
	bob.do(t, "POST", "/_matrix/client/v3/keys/upload", map[string]any{"device_keys": map[string]any{"user_id": bid, "device_id": bdev,
		"algorithms": []string{"m.olm.v1.curve25519-aes-sha2"}, "keys": map[string]any{"curve25519:" + bdev: "new-curve"}}})
	waitFor(t, "device list change on A", func() bool {
		_, sync := alice.do(t, "GET", "/_matrix/client/v3/sync?timeout=0&since="+since, nil)
		dl, _ := sync["device_lists"].(map[string]any)
		ch, _ := dl["changed"].([]any)
		for _, u := range ch {
			if u == bid {
				return true
			}
		}
		return false
	})
	_, q = alice.do(t, "POST", "/_matrix/client/v3/keys/query", map[string]any{"device_keys": map[string]any{bid: []string{}}})
	k := q["device_keys"].(map[string]any)[bid].(map[string]any)[bdev].(map[string]any)["keys"].(map[string]any)
	if k["curve25519:"+bdev] != "new-curve" {
		t.Errorf("stale keys after the change: %v", k)
	}

	// alice verifies bob: her signature on his master key, visible only to her
	if code, res := alice.do(t, "POST", "/_matrix/client/v3/keys/signatures/upload", map[string]any{bid: map[string]any{"BOBMASTER": map[string]any{
		"user_id": bid, "usage": []string{"master"}, "keys": map[string]any{"ed25519:BOBMASTER": "BOBMASTER"},
		"signatures": map[string]any{aid: map[string]any{"ed25519:ALICEUSK": "sig"}}}}}); code != 200 || len(res["failures"].(map[string]any)) != 0 {
		t.Fatalf("signature upload: %d %v", code, res)
	}
	_, q = alice.do(t, "POST", "/_matrix/client/v3/keys/query", map[string]any{"device_keys": map[string]any{bid: []string{}}})
	mk := q["master_keys"].(map[string]any)[bid].(map[string]any)
	if sigs, _ := mk["signatures"].(map[string]any)[aid].(map[string]any); sigs["ed25519:ALICEUSK"] != "sig" {
		t.Errorf("alice's signature on bob's master key missing: %v", mk)
	}

	// privacy: carol's server shares no room with alice or bob
	var resp map[string]any
	carol.s.fedRequest(context.Background(), "POST", alice.s.cfg.ServerName, "/_matrix/federation/v1/user/keys/query",
		map[string]any{"device_keys": map[string]any{aid: []string{}}}, &resp)
	if dk, _ := resp["device_keys"].(map[string]any); len(dk) != 0 {
		t.Errorf("a stranger server got alice's keys: %v", resp)
	}
	_, cq := carol.do(t, "POST", "/_matrix/client/v3/keys/claim", map[string]any{"one_time_keys": map[string]any{aid: map[string]any{adev: "signed_curve25519"}}})
	if got, _ := cq["one_time_keys"].(map[string]any); len(got) != 0 {
		t.Errorf("a stranger claimed alice's one-time key: %v", cq)
	}
	_ = room
}

func TestKeysForPendingRemoteInvite(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	uploadKeys(t, bob, deviceOf(b, bid))
	alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"invite": []string{bid}, "is_direct": true})
	// bob hasn't accepted yet, but alice's client can already encrypt for him
	_, q := alice.do(t, "POST", "/_matrix/client/v3/keys/query", map[string]any{"device_keys": map[string]any{bid: []string{}}})
	if d, _ := q["device_keys"].(map[string]any)[bid].(map[string]any); len(d) != 1 {
		t.Errorf("invitee's keys not available to the inviter: %v", q)
	}
}
