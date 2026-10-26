package server

import (
	"container/heap"
	"sort"
)

// State resolution v2, step by step as in Synapse's state/v2.py.

// stateMap is a room state: (type, state_key) -> event ID.
type stateMap map[stateTuple]string

// eventGetter returns an event with its graph fields, or nil.
type eventGetter func(id string) *Event

func resolveState(version string, sets []stateMap, get eventGetter) stateMap {
	unconflicted, conflicted := separateState(sets)
	if len(conflicted) == 0 {
		return unconflicted
	}
	full := map[string]bool{}
	for _, ids := range conflicted {
		for _, id := range ids {
			full[id] = true
		}
	}
	for id := range authDifference(sets, get) {
		full[id] = true
	}
	for id := range full {
		if get(id) == nil {
			delete(full, id)
		}
	}

	var power []string
	for id := range full {
		if isPowerEvent(get(id)) {
			power = append(power, id)
		}
	}
	sortedPower := reverseTopologicalPowerSort(version, power, full, get)
	resolved := iterativeAuthChecks(version, sortedPower, unconflicted, get)

	inPower := map[string]bool{}
	for _, id := range sortedPower {
		inPower[id] = true
	}
	var rest []string
	for id := range full {
		if !inPower[id] {
			rest = append(rest, id)
		}
	}
	rest = mainlineSort(rest, resolved[plTuple], get)
	resolved = iterativeAuthChecks(version, rest, resolved, get)
	for k, v := range unconflicted {
		resolved[k] = v
	}
	return resolved
}

// separateState splits agreed keys from conflicted ones (missing = conflicted).
func separateState(sets []stateMap) (stateMap, map[stateTuple][]string) {
	unconflicted := stateMap{}
	conflicted := map[stateTuple][]string{}
	keys := map[stateTuple]bool{}
	for _, s := range sets {
		for k := range s {
			keys[k] = true
		}
	}
	for k := range keys {
		ids := map[string]bool{}
		missing := false
		for _, s := range sets {
			if v, ok := s[k]; ok {
				ids[v] = true
			} else {
				missing = true
			}
		}
		if len(ids) == 1 && !missing {
			for id := range ids {
				unconflicted[k] = id
			}
			continue
		}
		var list []string
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		conflicted[k] = list
	}
	return unconflicted, conflicted
}

// authChain is every event reachable through auth_events from ids, ids included.
func authChain(ids []string, get eventGetter) map[string]bool {
	seen := map[string]bool{}
	stack := append([]string(nil), ids...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if ev := get(id); ev != nil {
			stack = append(stack, ev.AuthEvents...)
		}
	}
	return seen
}

// authDifference is the events in some but not all of the sets' auth chains.
func authDifference(sets []stateMap, get eventGetter) map[string]bool {
	count := map[string]int{}
	for _, s := range sets {
		ids := make([]string, 0, len(s))
		for _, id := range s {
			ids = append(ids, id)
		}
		for id := range authChain(ids, get) {
			count[id]++
		}
	}
	diff := map[string]bool{}
	for id, n := range count {
		if n < len(sets) {
			diff[id] = true
		}
	}
	return diff
}

func isPowerEvent(ev *Event) bool {
	if ev == nil || ev.StateKey == nil {
		return false
	}
	switch ev.Type {
	case "m.room.power_levels", "m.room.join_rules", "m.room.create":
		return *ev.StateKey == ""
	case "m.room.member":
		m := membershipOf(ev)
		return (m == "leave" || m == "ban") && ev.Sender != *ev.StateKey
	}
	return false
}

// senderPowerLevel is the sender's level according to the event's own auth events.
func senderPowerLevel(version string, ev *Event, get eventGetter) int64 {
	r, _ := rulesFor(version)
	var pl, create *Event
	for _, id := range ev.AuthEvents {
		a := get(id)
		if a == nil || a.StateKey == nil || *a.StateKey != "" {
			continue
		}
		switch a.Type {
		case "m.room.power_levels":
			if pl == nil {
				pl = a
			}
		case "m.room.create":
			if create == nil {
				create = a
			}
		}
	}
	if pl == nil {
		if create != nil && creatorOf(r, create) == ev.Sender {
			return 100
		}
		return 0
	}
	c := contentOf(pl)
	users, _ := c["users"].(map[string]any)
	if v, ok := users[ev.Sender]; ok && v != nil {
		return asLevel(v)
	}
	if v, ok := c["users_default"]; ok && v != nil {
		return asLevel(v)
	}
	return 0
}

type powerKey struct {
	negLevel int64
	ts       int64
	id       string
}

func (a powerKey) less(b powerKey) bool {
	if a.negLevel != b.negLevel {
		return a.negLevel < b.negLevel
	}
	if a.ts != b.ts {
		return a.ts < b.ts
	}
	return a.id < b.id
}

type keyHeap []powerKey

func (h keyHeap) Len() int           { return len(h) }
func (h keyHeap) Less(i, j int) bool { return h[i].less(h[j]) }
func (h keyHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *keyHeap) Push(x any)        { *h = append(*h, x.(powerKey)) }
func (h *keyHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// reverseTopologicalPowerSort: auth events first, then sender power,
// timestamp, event ID.
func reverseTopologicalPowerSort(version string, ids []string, full map[string]bool, get eventGetter) []string {
	graph := map[string]map[string]bool{}
	for _, id := range ids {
		stack := []string{id}
		for len(stack) > 0 {
			eid := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if graph[eid] == nil {
				graph[eid] = map[string]bool{}
			}
			ev := get(eid)
			if ev == nil {
				continue
			}
			for _, aid := range ev.AuthEvents {
				if full[aid] {
					if graph[aid] == nil {
						stack = append(stack, aid)
					}
					graph[eid][aid] = true
				}
			}
		}
	}
	key := func(id string) powerKey {
		ev := get(id)
		return powerKey{-senderPowerLevel(version, ev, get), ev.OriginTS, id}
	}
	return topoSort(graph, key)
}

// topoSort is Kahn's algorithm with a heap for ties.
func topoSort(graph map[string]map[string]bool, key func(string) powerKey) []string {
	outdeg := map[string]int{}
	reverse := map[string][]string{}
	h := &keyHeap{}
	for node, edges := range graph {
		outdeg[node] = len(edges)
		if len(edges) == 0 {
			heap.Push(h, key(node))
		}
		for e := range edges {
			reverse[e] = append(reverse[e], node)
		}
	}
	var out []string
	for h.Len() > 0 {
		node := heap.Pop(h).(powerKey).id
		out = append(out, node)
		for _, parent := range reverse[node] {
			outdeg[parent]--
			if outdeg[parent] == 0 {
				heap.Push(h, key(parent))
			}
		}
	}
	return out
}

// iterativeAuthChecks applies each event that passes auth on top of base.
func iterativeAuthChecks(version string, ids []string, base stateMap, get eventGetter) stateMap {
	resolved := make(stateMap, len(base))
	for k, v := range base {
		resolved[k] = v
	}
	for _, id := range ids {
		ev := get(id)
		if ev == nil || ev.Rejected || ev.StateKey == nil {
			continue
		}
		auth := authState{}
		for _, aid := range ev.AuthEvents {
			if a := get(aid); a != nil && !a.Rejected && a.StateKey != nil {
				auth[stateTuple{a.Type, *a.StateKey}] = a
			}
		}
		for _, k := range authTypes(ev) {
			if rid, ok := resolved[k]; ok {
				if a := get(rid); a != nil && !a.Rejected {
					auth[k] = a
				}
			}
		}
		if checkAuth(version, ev, ev.PrevEvents, auth) == nil {
			resolved[stateTuple{ev.Type, *ev.StateKey}] = id
		}
	}
	return resolved
}

// powerLevelsIn returns the power levels event among an event's auth events.
func powerLevelsIn(ev *Event, get eventGetter) string {
	for _, aid := range ev.AuthEvents {
		if a := get(aid); a != nil && a.Type == "m.room.power_levels" && a.StateKey != nil && *a.StateKey == "" {
			return aid
		}
	}
	return ""
}

// mainlineSort orders by position on the power levels chain, then ts, then ID.
func mainlineSort(ids []string, resolvedPL string, get eventGetter) []string {
	if len(ids) == 0 {
		return nil
	}
	var mainline []string
	for pl := resolvedPL; pl != ""; {
		mainline = append(mainline, pl)
		ev := get(pl)
		if ev == nil {
			break
		}
		pl = powerLevelsIn(ev, get)
	}
	pos := map[string]int64{}
	for i, id := range mainline {
		pos[id] = int64(len(mainline) - i)
	}
	depthOf := func(ev *Event) int64 {
		for seen := 0; ev != nil && seen < 1_000_000; seen++ {
			if d, ok := pos[ev.EventID]; ok {
				return d
			}
			next := powerLevelsIn(ev, get)
			if next == "" {
				return 0
			}
			ev = get(next)
		}
		return 0
	}
	keys := map[string]powerKey{}
	for _, id := range ids {
		ev := get(id)
		keys[id] = powerKey{depthOf(ev), ev.OriginTS, id}
	}
	out := append([]string(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return keys[out[i]].less(keys[out[j]]) })
	return out
}
