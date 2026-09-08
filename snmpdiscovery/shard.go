package snmpdiscovery

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
)

// shardOf is Alloy/Prometheus hashmod of addr: MD5, last 8 bytes as
// big-endian uint64, then % shards. Pollers that relabel with
//
//	source_labels = ["__address__"]
//	action        = "hashmod"
//
// on HTTP SD targets land in the same bucket as GET /sd?shard=&shards=.
func shardOf(addr string, shards int) int {
	if shards <= 1 {
		return 0
	}
	sum := md5.Sum([]byte(addr))
	return int(binary.BigEndian.Uint64(sum[8:]) % uint64(shards))
}

func filterShard(targets []AlloyTarget, shard, shards int) []AlloyTarget {
	if shards <= 1 {
		if targets == nil {
			return []AlloyTarget{}
		}
		return targets
	}
	out := make([]AlloyTarget, 0, len(targets)/shards+1)
	for _, t := range targets {
		if shardOf(t.Address, shards) == shard {
			out = append(out, t)
		}
	}
	return out
}

// parseShardQuery returns (shard, shards, filter, err).
// filter is false when both query params are omitted (serve the full catalog).
func parseShardQuery(shardS, shardsS string) (shard, shards int, filter bool, err error) {
	if shardS == "" && shardsS == "" {
		return 0, 0, false, nil
	}
	if shardS == "" || shardsS == "" {
		return 0, 0, false, fmt.Errorf("shard and shards must both be set")
	}
	n, err := strconv.Atoi(shardsS)
	if err != nil || n < 1 {
		return 0, 0, false, fmt.Errorf("shards must be a positive integer")
	}
	s, err := strconv.Atoi(shardS)
	if err != nil || s < 0 || s >= n {
		return 0, 0, false, fmt.Errorf("shard must be in [0, shards)")
	}
	return s, n, true, nil
}
