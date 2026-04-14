# HATCHERY Test Samples

This directory contains safe test samples for validating HATCHERY analysis.

## Samples

| File | Source | Purpose |
|------|--------|---------|
| `eicar.com` | [EICAR](https://www.eicar.org/download-anti-malware-testfile/) | Standard AV test file — triggers YARA rules, safe to handle |
| `hello.elf` | Generated | Simple hello-world ELF binary for Linux sandbox testing |
| `benign_pe.exe` | Generated | Minimal PE binary for static analysis testing |

## Safety

- **EICAR** is not malware — it's an industry-standard test string recognized by all AV engines
- **hello.elf** is a compiled hello-world program — completely benign
- **benign_pe.exe** is a minimal PE header with no executable code — for parser testing only

## Adding Samples

For real malware testing, use samples from:
- [MalwareBazaar](https://bazaar.abuse.ch/) — free, community-submitted samples
- [TheZoo](https://github.com/ytisf/theZoo) — live malware samples (use with extreme caution)
- [VirusTotal](https://www.virustotal.com/) — upload and analyze (no download of live samples)

⚠️ **Never test with live malware on production systems. Always use isolated environments.**