package detect

import (
	"reflect"
	"testing"
)

func TestNewRegistryViewWithPeersInspectsOnlyTargets(t *testing.T) {
	targets := []ToolView{
		{Server: "a", Name: "read_file", Description: "Reads a file."},
		{Server: "a", Name: "write_file", Description: "Writes a file."},
	}
	peers := []ToolView{
		{Server: "b", Name: "read_file", Description: "Reads a file from b."},
		{Server: "c", Name: "list_dir", Description: "Lists a directory."},
		{Server: "c", Name: "boom", Description: "panics if inspected"},
	}

	var inspected []string
	counting := fakeCheck{id: "count", fn: func(tv ToolView, _ RegistryView) []Signal {
		if tv.Name == "boom" {
			panic("peer inspected")
		}
		inspected = append(inspected, tv.Server+":"+tv.Name)
		return nil
	}}

	res := NewEngine(Options{Checks: []Check{counting}}).Scan(NewRegistryViewWithPeers(targets, peers))

	if want := []string{"a:read_file", "a:write_file"}; !reflect.DeepEqual(inspected, want) {
		t.Fatalf("inspected %v, want only the targets %v", inspected, want)
	}
	if res.Coverage.ChecksFailed != 0 {
		t.Fatalf("a check failed on a peer that should not have been inspected: %+v", res.Coverage)
	}
}

func TestNewRegistryViewWithPeersIndexesPeers(t *testing.T) {
	targets := []ToolView{{Server: "a", Name: "read_file", Description: "Reads a file."}}
	peers := []ToolView{
		{Server: "b", Name: "read_file", Description: "Reads a file from b."},
		{Server: "c", Name: "list_dir", Description: "Lists a directory."},
	}

	reg := NewRegistryViewWithPeers(targets, peers)

	if len(reg.Tools) != 1 || reg.Tools[0].NormalizedText == "" || reg.Tools[0].PhraseText == "" {
		t.Fatalf("targets must be normalized and be the only scanned tools, got %+v", reg.Tools)
	}
	owners := reg.ToolsByName["read_file"]
	if len(owners) != 2 || owners[0].Server != "a" || owners[1].Server != "b" {
		t.Fatalf("ToolsByName[read_file] = %+v, want target then peer in input order", owners)
	}
	if owners[1].Description != "Reads a file from b." {
		t.Fatalf("peer description lost: %+v", owners[1])
	}
	for _, name := range []string{"read_file", "list_dir"} {
		if _, ok := reg.ToolNames[name]; !ok {
			t.Fatalf("ToolNames missing %q", name)
		}
	}
}
