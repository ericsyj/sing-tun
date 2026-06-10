package ping

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUnprivilegedConnPruneExpiredMappings(t *testing.T) {
	now := time.Unix(100, 0)
	conn := &UnprivilegedConn{
		idleTimeout: time.Second,
		mapping: map[uint16]*unprivilegedConnEntry{
			1: {lastUsed: now.Add(-2 * time.Second)},
			2: {lastUsed: now},
		},
	}

	conn.mappingAccess.Lock()
	conn.pruneExpiredMappingsLocked(now)
	conn.mappingAccess.Unlock()

	require.NotContains(t, conn.mapping, uint16(1))
	require.Contains(t, conn.mapping, uint16(2))
}

func TestUnprivilegedConnEvictOldestMapping(t *testing.T) {
	now := time.Unix(100, 0)
	conn := &UnprivilegedConn{
		mapping: make(map[uint16]*unprivilegedConnEntry),
	}
	for i := range maxUnprivilegedConnMappings {
		conn.mapping[uint16(i)] = &unprivilegedConnEntry{
			lastUsed: now.Add(time.Duration(i) * time.Second),
		}
	}

	conn.mappingAccess.Lock()
	conn.evictOldestMappingLocked()
	conn.mappingAccess.Unlock()

	require.Len(t, conn.mapping, maxUnprivilegedConnMappings-1)
	require.NotContains(t, conn.mapping, uint16(0))
	require.Contains(t, conn.mapping, uint16(maxUnprivilegedConnMappings-1))
}
