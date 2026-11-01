package runtime

import (
	"fmt"
	"testing"

	"github.com/smart-mcp-proxy/mcpproxy-go/internal/runtime/stateview"
)

func TestCollectPeerToolMetadataReusesProjectionPerSnapshot(t *testing.T) {
	rt := newTestRuntime(t)
	seedStateViewServer(t, rt, "a", true, []stateview.ToolInfo{
		{Name: "read", Description: "Reads.", InputSchema: map[string]interface{}{"type": "object"}},
	})
	seedStateViewServer(t, rt, "b", true, []stateview.ToolInfo{{Name: "write", Description: "Writes."}})

	first := rt.collectPeerToolMetadata("b")
	second := rt.collectPeerToolMetadata("b")
	if len(first) != 1 || len(first["a"]) != 1 || first["a"][0].ParamsJSON != `{"type":"object"}` {
		t.Fatalf("peers of b = %#v, want a's one tool with its schema", first)
	}
	if _, own := first["b"]; own {
		t.Fatal("a server's own tools must not be its peers")
	}
	if first["a"][0] != second["a"][0] {
		t.Fatal("an unchanged StateView snapshot must reuse the peer projection")
	}
	if fromA := rt.collectPeerToolMetadata("a"); len(fromA) != 1 || fromA["b"][0].Name != "write" {
		t.Fatalf("peers of a = %#v, want b's tool", fromA)
	}

	seedStateViewServer(t, rt, "a", true, []stateview.ToolInfo{{Name: "read_v2", Description: "Reads more."}})
	if got := rt.collectPeerToolMetadata("b"); got["a"][0].Name != "read_v2" {
		t.Fatalf("a new StateView snapshot must be projected again, got %#v", got["a"])
	}
}

func BenchmarkCollectPeerToolMetadata(b *testing.B) {
	rt := newTestRuntime(b)
	schema := map[string]interface{}{"type": "object", "properties": map[string]interface{}{
		"id": map[string]interface{}{"type": "string", "description": "record id"}}}
	for s := 0; s < 10; s++ {
		tools := make([]stateview.ToolInfo, 200)
		for i := range tools {
			tools[i] = stateview.ToolInfo{Name: fmt.Sprintf("tool_%d", i), Description: "Fetches a record.", InputSchema: schema}
		}
		rt.supervisor.StateView().UpdateServer(fmt.Sprintf("srv-%d", s), func(st *stateview.ServerStatus) { st.Tools = tools })
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt.collectPeerToolMetadata("srv-0")
	}
}
