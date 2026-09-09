# Security

## Secrets

`auths.yml` (communities, v3 USM) is gitignored. `snmp-discovery init` writes that file mode `0600` and a matching `discovery.yml` so group `auths:` names cannot typo-drift. Copy `snmp/auths.example.yml` if you prefer to edit by hand. Example communities are placeholders — do not commit production secrets. The init prompts echo v3 passwords (stdin); prefer a private terminal.

Discovery lists **auth names** only. `GET /sd/prometheus` and `--out-file-sd` emit `__param_auth`, never a community or password. Treat a leak of the module library as public OIDs, not credentials.

## Reporting

Use [GitHub Security Advisories](https://github.com/Mesverrum/snmp-sd/security/advisories) on this repository. Do not open a public issue for a credential leak or remotely exploitable bug until it is coordinated.
