# WebCrack Service for Assemblyline 4

This is a custom Assemblyline 4 service that implements [WebCrack](https://github.com/j4k0xb/webcrack), a tool for reverse engineering, deobfuscating, and unpacking JavaScript.

## Features

- **Deobfuscation**: Automatically reverses obfuscation techniques from tools like Obfuscator.io.
- **Unminification**: Formats and beautifies minified JavaScript for analyst readability.
- **Bundle Unpacking**: Detects and unpacks JavaScript bundles (such as Webpack or Browserify) into their constituent modules.
- **Result Extraction**: Deobfuscated and extracted contents are automatically resubmitted to Assemblyline as extracted child files for recursive analysis.

## Submission Parameters

The service allows users to configure its behavior at submission time via Assemblyline parameters:

- `deobfuscate_code` (Boolean, Default: True): Attempt to deobfuscate JavaScript code.
- `unminify_code` (Boolean, Default: True): Attempt to unminify JavaScript code.
- `unpack_bundles` (Boolean, Default: True): Attempt to unpack webpack/browserify bundles.

## Heuristics

The service implements the following heuristics to flag potentially malicious behavior:
- **Heuristic 1 (Score: 100)**: Obfuscated JavaScript detected and successfully deobfuscated.
- **Heuristic 2 (Score: 500)**: Known Obfuscator (e.g. Obfuscator.io) explicitly detected.
- **Heuristic 3 (Score: 100)**: JavaScript Bundle Detected and unpacked.

## Installation and Deployment

This repository includes a GitHub Action to automatically build and push the Docker image to GitHub Container Registry (ghcr.io). The image version will directly map to the `version` configured in `service_manifest.yml`.

To deploy in Assemblyline, ensure your AL4 configuration is pointing to the proper Docker registry and that the `service_manifest.yml` is loaded into the core system.