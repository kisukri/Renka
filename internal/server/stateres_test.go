package server

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

// testdata/stateres_vectors.json.gz: forked rooms resolved by Synapse's
// state resolution v2 (test/stateres_vectors.py).
func TestStateResolutionMatchesSynapse(t *testing.T) {
	f, err := os.Open("testdata/stateres_vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			RoomVersion string `json:"room_version"`
			Events      []struct {
				vecEvent
				AuthEvents []string `json:"auth_events"`
				PrevEvents []string `json:"prev_events"`
				TS         int64    `json:"origin_server_ts"`
				Depth      int64    `json:"depth"`
			} `json:"events"`
			StateSets [][][3]string `json:"state_sets"`
			Resolved  [][3]string   `json:"resolved"`
		} `json:"cases"`
	}
	if err := json.NewDecoder(zr).Decode(&v); err != nil {
		t.Fatal(err)
	}
	toMap := func(rows [][3]string) stateMap {
		m := stateMap{}
		for _, r := range rows {
			m[stateTuple{r[0], r[1]}] = r[2]
		}
		return m
	}
	differs := 0
	for i, c := range v.Cases {
		events := map[string]*Event{}
		for _, e := range c.Events {
			ev := e.event()
			ev.AuthEvents, ev.PrevEvents, ev.OriginTS, ev.Depth = e.AuthEvents, e.PrevEvents, e.TS, e.Depth
			events[ev.EventID] = ev
		}
		get := func(id string) *Event { return events[id] }
		var sets []stateMap
		for _, s := range c.StateSets {
			sets = append(sets, toMap(s))
		}
		got := resolveState(c.RoomVersion, sets, get)
		want := toMap(c.Resolved)
		if len(got) != len(want) {
			t.Errorf("case %d: %d keys, Synapse %d", i, len(got), len(want))
		}
		for k, w := range want {
			if got[k] != w {
				t.Errorf("case %d (v%s): %v resolved to %s, Synapse %s", i, c.RoomVersion, k, got[k], w)
			}
		}
		// count cases where the answer isn't simply one of the branches
		for _, s := range sets {
			same := len(s) == len(want)
			for k, w := range want {
				if s[k] != w {
					same = false
				}
			}
			if same {
				differs--
				break
			}
		}
		differs++
	}
	if len(v.Cases) < 300 || differs < 50 {
		t.Fatalf("weak vectors: %d cases, %d not equal to any branch", len(v.Cases), differs)
	}
	t.Logf("%d cases, %d where the result mixes branches", len(v.Cases), differs)
}
