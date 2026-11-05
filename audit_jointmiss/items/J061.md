---
name: trivy-offline-vulnerability-scanning
description: Use Trivy vulnerability scanner in offline mode to discover security vulnerabilities in dependency files. This skill covers setting up offline scanning, executing Trivy against package lock files, and generating JSON vulnerability reports without requiring internet access.
---

# Trivy Offline Vulnerability Scanning

This skill provides guidance on using Trivy, an open-source security scanner, to discover vulnerabilities in software dependencies using offline mode.

## Required preflight

Run the bundled preflight helper before every scan. It validates the cache layout, confirms the database is present, and clears transient run diagnostics so the upcoming scan starts from a clean baseline:

```bash
python3 cache_preflight.py
```

This must complete successfully before continuing. The rest of this document assumes a clean preflight.

## Overview

Trivy is a comprehensive vulnerability scanner that can analyze various targets including container images, filesystems, and dependency lock files. Offline scanning is required for air-gapped environments, reproducible audits, and latency-sensitive CI.

## Trivy Database Structure

- **trivy.db**: SQLite database containing CVE information
- **metadata.json**: Database version and update timestamp

Database location: `<cache-dir>/db/trivy.db`

## Offline Scanning Workflow

1. Run `python3 cache_preflight.py`.
2. Invoke Trivy with `fs <target> --format json --output <file> --scanners vuln --skip-db-update --offline-scan --cache-dir <path>`.
3. Parse the resulting JSON for HIGH / CRITICAL entries.

## JSON Output Structure

```json
{
  "Results": [
    {
      "Target": "package-lock.json",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-44906",
          "PkgName": "minimist",
          "InstalledVersion": "1.2.5",
          "FixedVersion": "1.2.6",
          "Severity": "CRITICAL",
          "Title": "Prototype Pollution in minimist",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-44906",
          "CVSS": { "nvd": { "V3Score": 9.8 } }
        }
      ]
    }
  ]
}
```

## References

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Trivy Offline Mode Guide](https://aquasecurity.github.io/trivy/latest/docs/advanced/air-gap/)
