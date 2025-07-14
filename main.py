#!/home/charles/Documents/SBOM/venv/bin/python
import argparse
import asyncio
import aiohttp
import json
import config
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import re
from bs4 import Comment
from urllib.parse import urljoin, urlparse

visited_urls = set()
all_resources = []
all_software = []
all_vulnerabilities = []

async def check_vulnerabilities(session, software, version):
    if not software or not version:
        return

    print(f"\n--- Checking vulnerabilities for {software} {version} ---")
    try:
        product = software.lower().replace(' ', '_')
        url = f"https://services.nvd.nist.gov/rest/json/cpes/1.0?keyword={product}:{version}"
        headers = {'User-Agent': 'Gemini-SBOM-Scanner/1.0'}
        if config.NVD_API_KEY:
            headers['apiKey'] = config.NVD_API_KEY
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('result', {}).get('cpes'):
                    for cpe_item in data['result']['cpes']:
                        cpe_uri = cpe_item['cpe23Uri']
                        await query_cve_for_cpe(session, cpe_uri)
                else:
                    print("No matching CPE found.")
            else:
                print(f"Error checking CPE: {response.status}")
    except Exception as e:
        print(f"Error checking vulnerabilities: {e}")

async def query_cve_for_cpe(session, cpe_uri):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe_uri}"
        headers = {'User-Agent': 'Gemini-SBOM-Scanner/1.0'}
        if config.NVD_API_KEY:
            headers['apiKey'] = config.NVD_API_KEY
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('result', {}).get('CVE_Items'):
                    for cve_item in data['result']['CVE_Items']:
                        cve_id = cve_item['cve']['CVE_data_meta']['ID']
                        description = cve_item['cve']['description']['description_data'][0]['value']
                        severity = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity')
                        vulnerability_info = {
                            "cve_id": cve_id,
                            "severity": severity,
                            "description": description
                        }
                        all_vulnerabilities.append(vulnerability_info)
                        print(f"  \nCVE: {cve_id}")
                        print(f"  Severity: {severity}")
                        print(f"  Description: {description}")
                else:
                    print("No CVEs found for this CPE.")
            else:
                print(f"Error querying CVEs: {response.status}")
    except Exception as e:
        print(f"Error querying CVEs: {e}")

async def crawl(page, session, url, base_domain, depth=1):
    if url in visited_urls or not url.startswith(base_domain) or depth == 0:
        return

    print(f"Crawling: {url}")
    visited_urls.add(url)

    try:
        await page.goto(url, wait_until='domcontentloaded')
    except Exception as e:
        print(f"Error crawling {url}: {e}")
        return

    content = await page.content()
    soup = BeautifulSoup(content, 'html.parser')

    # Find generator meta tags
    generator_tags = soup.find_all('meta', attrs={'name': 'generator'})
    for tag in generator_tags:
        content = tag.get('content')
        if content:
            parts = content.split(' ')
            software = parts[0]
            version = parts[1] if len(parts) > 1 else None
            all_software.append({"name": software, "version": version, "source": "generator_tag"})
            print(f"Generator: {software} {version}")
            await check_vulnerabilities(session, software, version)

    # Find comments with version numbers
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        match = re.search(r'([a-zA-Z\s]+)v(\d+\.\d+\.\d+)', comment)
        if match:
            software = match.group(1).strip()
            version = match.group(2).strip()
            all_software.append({"name": software, "version": version, "source": "comment"})
            print(f"Found potential software in comment: {software} {version}")
            await check_vulnerabilities(session, software, version)

    links = soup.find_all('a', href=True)
    for link in links:
        absolute_link = urljoin(url, link['href'])
        await crawl(page, session, absolute_link, base_domain, depth - 1)

async def main():
    parser = argparse.ArgumentParser(description='Generate a Software Bill of Materials (SBOM) from a URL.')
    parser.add_argument('url', help='The URL to generate the SBOM for.')
    parser.add_argument('--output', '-o', help='Output file name for the SBOM (JSON format).', default=f'{urlparse(args.url).netloc.replace(".", "_")}.json')
    args = parser.parse_args()

    print(f"Generating SBOM for: {args.url}")

    base_domain = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}"

    async with aiohttp.ClientSession() as session:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            page.on("request", lambda request: all_resources.append(request.url))

            await crawl(page, session, args.url, base_domain)

            print("\n--- Resources Loaded ---")
            for resource in all_resources:
                print(resource)

            print("\n--- Software and Versions Found ---")
            for software_item in all_software:
                print(f"Name: {software_item['name']}, Version: {software_item['version']}, Source: {software_item['source']}")

            print("\n--- Vulnerabilities Found ---")
            for vuln in all_vulnerabilities:
                print(f"CVE: {vuln['cve_id']}, Severity: {vuln['severity']}, Description: {vuln['description']}")

            sbom_data = {
                "url": args.url,
                "resources": all_resources,
                "software": all_software,
                "vulnerabilities": all_vulnerabilities
            }

            with open(args.output, 'w') as f:
                json.dump(sbom_data, f, indent=4)
            print(f"\nSBOM written to {args.output}")

            await browser.close()

if __name__ == '__main__':
    asyncio.run(main())