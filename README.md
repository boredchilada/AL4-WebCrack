# WebCrack Service for Assemblyline 4

This is a custom Assemblyline 4 service that implements [WebCrack](https://github.com/j4k0xb/webcrack) (v2.16.0-beta.1), a tool for reverse engineering, deobfuscating, and unpacking JavaScript. Designed for phishing kit and malicious website analysis.

## Features

- **Deobfuscation**: Automatically reverses obfuscation techniques from tools like Obfuscator.io.
- **Unminification**: Formats and beautifies minified JavaScript for analyst readability.
- **Bundle Unpacking**: Detects and unpacks JavaScript bundles (Webpack 4/5, Browserify) into their constituent modules.
- **IOC Extraction**: Extracts URLs, domains, and IPs from deobfuscated code and tags them for AL correlation.
- **Phishing Detection**: Identifies credential harvesting patterns, suspicious DOM manipulation, and data exfiltration indicators.
- **Result Extraction**: Deobfuscated code is automatically resubmitted to Assemblyline as an extracted child file for recursive analysis.

## Submission Parameters

- `deobfuscate_code` (Boolean, Default: True): Attempt to deobfuscate JavaScript code.
- `unminify_code` (Boolean, Default: True): Attempt to unminify JavaScript code.
- `unpack_bundles` (Boolean, Default: True): Attempt to unpack webpack/browserify bundles.

## Heuristics

| ID | Name | Score | MITRE ATT&CK | Description |
|----|------|-------|---------------|-------------|
| 1 | Obfuscated JavaScript Deobfuscated | 100 | T1027 | Code was successfully deobfuscated |
| 2 | Known Obfuscator Detected | 500 | T1027.013 | Known obfuscator tool detected (e.g. obfuscator.io) |
| 3 | JavaScript Bundle Detected | 50 | - | Webpack or Browserify bundle unpacked |
| 4 | Suspicious URLs Found | 100 | T1566.002 | URLs extracted from deobfuscated code |
| 5 | Credential Harvesting Indicators | 500 | T1056.003 | Form interception, password field access patterns |
| 6 | Suspicious DOM Manipulation | 250 | T1185 | Phishing overlays, fake login forms, content injection |
| 7 | Data Exfiltration Pattern | 300 | T1041 | Data sent to external endpoints via fetch/XHR/sendBeacon |

## Installation

1. In the AL4 UI, go to **Administration > Services > Add Service**
2. Paste the contents of `service_manifest.yml`
3. The Docker image is automatically built and pushed to `ghcr.io/boredchilada/al4-webcrack` via GitHub Actions on push to `main`

## Version Bumping

Update the version in two places in `service_manifest.yml`:
- `version:` field at the top
- `docker_config.image:` tag at the bottom

Then commit and push. CI will build and tag the image automatically.
