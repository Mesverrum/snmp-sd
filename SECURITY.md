# Security

## Secrets

`auths.yml` (communities, v3 USM) is gitignored. Copy `snmp/auths.example.yml` and keep the real file mode `0600`. Example communities in that file are placeholders — do not commit production secrets.

Discovery lists **auth names** only. `GET /sd/prometheus` and `--out-file-sd` emit `__param_auth`, never a community or password. Treat a leak of the module library as public OIDs, not credentials.

## Reporting

Use [GitHub Security Advisories](https://github.com/Mesverrum/snmp-sd/security/advisories) on this repository. Do not open a public issue for a credential leak or remotely exploitable bug until it is coordinated.
