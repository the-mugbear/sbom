# SBOM CLI

A command-line tool to generate a Software Bill of Materials (SBOM) from a URL.

## Usage

```bash
python main.py <URL>
```

## NVD API Key

The vulnerability checker uses the National Vulnerability Database (NVD) API. To avoid potential rate limiting or 403 errors, it is recommended to obtain a free API key from the NVD website and add it to `config.py`.
