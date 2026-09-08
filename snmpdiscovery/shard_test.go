package snmpdiscovery

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestShardOfMatchesAlloyHashmod(t *testing.T) {
	const shards = 4
	addrs := []string{
		"172.20.20.2",
		"172.20.20.3",
		"10.0.0.1",
		"192.168.1.50",
		"2001:db8::1",
	}
	for _, addr := range addrs {
		sum := md5.Sum([]byte(addr))
		want := int(binary.BigEndian.Uint64(sum[8:]) % uint64(shards))
		got := shardOf(addr, shards)
		if got != want {
			t.Errorf("shardOf(%q)=%d want %d (Alloy hashmod)", addr, got, want)
		}
	}
}

func TestShardPartitionCompleteNoOverlap(t *testing.T) {
	const shards = 4
	var targets []AlloyTarget
	for i := 0; i < 32; i++ {
		addr := fmt.Sprintf("10.0.0.%d", i+1)
		targets = append(targets, AlloyTarget{Address: addr, Name: addr})
	}
	seen := map[string]int{}
	total := 0
	for s := 0; s < shards; s++ {
		part := filterShard(targets, s, shards)
		for _, tgt := range part {
			if prev, ok := seen[tgt.Address]; ok {
				t.Fatalf("%s in shard %d and %d", tgt.Address, prev, s)
			}
			seen[tgt.Address] = s
			if shardOf(tgt.Address, shards) != s {
				t.Fatalf("%s filterShard shard=%d but shardOf=%d", tgt.Address, s, shardOf(tgt.Address, shards))
			}
		}
		total += len(part)
	}
	if total != len(targets) {
		t.Fatalf("partitioned %d of %d", total, len(targets))
	}
	if len(seen) != len(targets) {
		t.Fatalf("unique=%d want %d", len(seen), len(targets))
	}
}

func TestParseShardQuery(t *testing.T) {
	_, _, filter, err := parseShardQuery("", "")
	if err != nil || filter {
		t.Fatalf("empty query should not filter: filter=%v err=%v", filter, err)
	}
	if _, _, _, err := parseShardQuery("0", ""); err == nil {
		t.Fatal("shard without shards should error")
	}
	if _, _, _, err := parseShardQuery("", "4"); err == nil {
		t.Fatal("shards without shard should error")
	}
	if _, _, _, err := parseShardQuery("4", "4"); err == nil {
		t.Fatal("shard == shards should error")
	}
	s, n, filter, err := parseShardQuery("1", "4")
	if err != nil || !filter || s != 1 || n != 4 {
		t.Fatalf("got shard=%d shards=%d filter=%v err=%v", s, n, filter, err)
	}
}
