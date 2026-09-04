package model

import (
	"math/rand"
	"strings"
	"testing"
)

func TestExposeRoutesOverlapExactAndSegmentAwarePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		firstMode  RouteMode
		firstPath  string
		secondMode RouteMode
		secondPath string
		want       bool
	}{
		{RouteExact, "/api", RouteExact, "/api", true},
		{RouteExact, "/api", RouteExact, "/api/v1", false},
		{RoutePrefix, "/api", RouteExact, "/api", true},
		{RoutePrefix, "/api", RouteExact, "/api/v1", true},
		{RoutePrefix, "/api", RouteExact, "/apiv1", false},
		{RoutePrefix, "/api", RoutePrefix, "/api/v1", true},
		{RoutePrefix, "/api/v1", RoutePrefix, "/api/v2", false},
		{RoutePrefix, "/", RouteExact, "/anything", true},
		{RoutePrefix, "/", RoutePrefix, "/anything", true},
	}
	for _, test := range tests {
		if got := ExposeRoutesOverlap(test.firstMode, test.firstPath, test.secondMode, test.secondPath); got != test.want {
			t.Errorf("ExposeRoutesOverlap(%s, %q, %s, %q) = %t, want %t", test.firstMode, test.firstPath, test.secondMode, test.secondPath, got, test.want)
		}
		if got := ExposeRoutesOverlap(test.secondMode, test.secondPath, test.firstMode, test.firstPath); got != test.want {
			t.Errorf("ExposeRoutesOverlap symmetry = %t, want %t", got, test.want)
		}
	}
}

func TestExposeRoutesOverlapSymmetryProperty(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewSource(42))
	segments := []string{"api", "v1", "telegram", "hook", "x", "xy"}
	modes := []RouteMode{RouteExact, RoutePrefix}
	path := func() string {
		count := 1 + random.Intn(4)
		parts := make([]string, count)
		for index := range parts {
			parts[index] = segments[random.Intn(len(segments))]
		}
		return "/" + strings.Join(parts, "/")
	}
	for sample := 0; sample < 5000; sample++ {
		firstMode, secondMode := modes[random.Intn(2)], modes[random.Intn(2)]
		firstPath, secondPath := path(), path()
		first := ExposeRoutesOverlap(firstMode, firstPath, secondMode, secondPath)
		second := ExposeRoutesOverlap(secondMode, secondPath, firstMode, firstPath)
		if first != second {
			t.Fatalf("overlap is asymmetric for %s %q and %s %q", firstMode, firstPath, secondMode, secondPath)
		}
	}
}

func TestExposeRouteIndexMatchesPairwiseOverlapProperty(t *testing.T) {
	t.Parallel()

	type route struct {
		mode RouteMode
		path string
	}
	routes := []route{
		{RouteExact, "/"}, {RouteExact, "/api"}, {RouteExact, "/api/"},
		{RouteExact, "/api/v1"}, {RouteExact, "/apiv1"},
		{RoutePrefix, "/"}, {RoutePrefix, "/api"}, {RoutePrefix, "/api/v1"},
	}
	for firstIndex, first := range routes {
		for secondIndex, second := range routes {
			index := NewExposeRouteIndex()
			if owner, err := index.Add(first.mode, first.path, "first"); err != nil || owner != "" {
				t.Fatalf("index first route %d: owner=%q err=%v", firstIndex, owner, err)
			}
			owner, err := index.Add(second.mode, second.path, "second")
			wantConflict := ExposeRoutesOverlap(first.mode, first.path, second.mode, second.path)
			if err != nil || (owner != "") != wantConflict {
				t.Fatalf("index routes %d/%d owner=%q error=%v, overlap=%t", firstIndex, secondIndex, owner, err, wantConflict)
			}
		}
	}
}

func TestExposePathValidationRejectsAmbiguousAndReservedForms(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		path string
		mode RouteMode
		ok   bool
	}{
		{path: "/telegram/webhook", mode: RouteExact, ok: true},
		{path: "/api", mode: RoutePrefix, ok: true},
		{path: "/", mode: RoutePrefix, ok: true},
		{path: "/api/", mode: RouteExact, ok: true},
		{path: "/api/", mode: RoutePrefix},
		{path: "/.well-known/vpnctl", mode: RouteExact},
		{path: "/.well-known/vpnctl/enroll", mode: RouteExact},
		{path: "/api/%2e%2e/private", mode: RouteExact},
		{path: "/api/../private", mode: RouteExact},
		{path: "/api\\private", mode: RouteExact},
		{path: "/api path", mode: RouteExact},
	} {
		if err := ValidateExposePath(test.path, test.mode); (err == nil) != test.ok {
			t.Errorf("ValidateExposePath(%q, %s) error = %v, ok=%t", test.path, test.mode, err, test.ok)
		}
	}
}

func TestStateValidationEnforcesNodeLocalExposeNamesAndRouteOverlap(t *testing.T) {
	t.Parallel()

	duplicateName := gatewayState()
	second := duplicateName.Exposes[0]
	second.ID = "dededede-dede-4ede-8ede-dededededede"
	second.TunnelPort++
	second.Name = strings.ToUpper(second.Name)
	second.Path = "/another"
	duplicateName.Exposes = append(duplicateName.Exposes, second)
	if err := duplicateName.Validate(); err == nil || !strings.Contains(err.Error(), "duplicates node-local expose name") {
		t.Fatalf("duplicate node-local name error = %v", err)
	}

	overlap := gatewayState()
	second = overlap.Exposes[0]
	second.ID = "dededede-dede-4ede-8ede-dededededede"
	second.TunnelPort++
	second.Name = "other"
	second.RouteMode = RoutePrefix
	second.Path = "/telegram"
	overlap.Exposes = append(overlap.Exposes, second)
	if err := overlap.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps active route") {
		t.Fatalf("overlapping prefix error = %v", err)
	}

	disabled := gatewayState()
	second = disabled.Exposes[0]
	second.ID = "dededede-dede-4ede-8ede-dededededede"
	second.TunnelPort++
	second.Name = "disabled-old-route"
	second.State = ExposeDisabled
	disabled.Exposes = append(disabled.Exposes, second)
	if err := disabled.Validate(); err != nil {
		t.Fatalf("disabled route should not reserve public routing: %v", err)
	}
}
