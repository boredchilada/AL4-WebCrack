# WebCrack

AssemblyLine 4 service that deobfuscates, unminifies and unpacks JavaScript with [webcrack](https://github.com/j4k0xb/webcrack). Deobfuscated code and any embedded WebAssembly are resubmitted to AssemblyLine for further analysis, and URLs, domains and IPs found in the result are tagged.

The service is static only. Behavioural JavaScript detection (eval chains, phishing pages, exfiltration) is left to the official JsJaws service.

## Accepted files

`code/javascript`, `code/html`, `code/jscript`, `code/wsf`, `image/svg`

## Heuristics

| ID | Name | Score | ATT&CK |
|---|---|---|---|
| 1 | Obfuscated JavaScript deobfuscated | 100 | T1027 |
| 2 | Known obfuscator detected | 500 | T1027.013 |
| 3 | JavaScript bundle detected | 50 | |
| 4 | Embedded WebAssembly detected | 500 | T1027.009 |

Heuristic 2 records which markers matched as signatures: `obfuscator_io_call`, `obfuscator_io_string_array`, `atob_long_string`.

## Output

- Extracted `deobfuscated.js` when webcrack changed the code.
- Extracted `embedded_N.wasm` for each base64-encoded WebAssembly module (data URIs and string literals).
- Tags: `network.static.uri`, `network.static.domain`, `network.static.ip`. URLs are tagged without a score.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `max_deobfuscated_size` | 10485760 | Larger webcrack output is not analysed or extracted. |

Submission parameters `deobfuscate_code`, `unminify_code` and `unpack_bundles` (all default `true`) switch the matching webcrack transforms.

## Build

The image builds webcrack from a pinned upstream commit (`WEBCRACK_COMMIT` in the Dockerfile) on Node.js 24 LTS, including the `isolated-vm` sandbox that string-decoder deobfuscation depends on. The build fails if `isolated-vm` does not load or webcrack does not run.

## Development

```bash
bash scripts/build-image.sh al4-webcrack:test 4.7.0.dev0 podman
bash scripts/ci-gate.sh al4-webcrack:test podman
```

Releases are git tags: `v4.7.0.devN` for test builds, `v4.7.0.stableN` for releases.


## License

MIT. See [LICENSE](LICENSE).
