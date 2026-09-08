// Package snmpdiscovery implements Prometheus-shaped SNMP service discovery
// (groups + named auths + fingerprinters). Used by the snmp-discovery CLI
// and by Grafana Alloy discovery.snmp.
//
// snmp.yml and fingerprinters.yml must be the same convert: module= names
// missing from modules: are dropped. The snmp_group label is the group name.
// Secrets stay in auths:; SD only emits the auth name.
package snmpdiscovery
