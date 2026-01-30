import subprocess
import requests
from packaging import version
import click


class VulnerabilityScanner:
    OSV_ECOSYSTEM = "Debian"
    OSV_API_URL = "https://api.osv.dev/v1/query"

    INSTALLED_PACKAGES_CMD = ['dpkg-query', '-W', '-f=${Package} ${Version}\n']
    UPGRADABLE_PACKAGES_CMD = ['apt', 'list', '--upgradable']

    #Severity levels based on CVSS scores
    SEVERITY_THRESHOLDS = [
        (9.0, "CRITICAL"),
        (7.0, "HIGH"),
        (4.0, "MEDIUM"),
        (0.1, "LOW"),
    ]

    def __init__(self, only_upgradable=True):
        self.only_upgradable = only_upgradable
        self.installed_packages = self.get_installed_packages()
        self.upgradable_packages = self.get_upgradable_packages() if only_upgradable else set()


    def get_installed_packages(self):
        result = subprocess.run(self.INSTALLED_PACKAGES_CMD, capture_output=True, text=True)
        packages = {}
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                name, ver = line.strip().split(maxsplit=1)
                packages[name] = ver
            except ValueError:
                continue
        return packages
    
    def get_upgradable_packages(self):
        result = subprocess.run(self.UPGRADABLE_PACKAGES_CMD, capture_output=True, text=True)
        upgradable = set()
        for line in result.stdout.splitlines():
            if '/' in line and '[installed' in line:
                name = line.split('/')[0].strip()
                upgradable.add(name)
        return upgradable
    
    def query_osv(self, package_name, installed_version):
        payload = {
            "package":{"name": package_name, "ecosystem": self.OSV_ECOSYSTEM},
            "version": installed_version
        }
        try:
            response = requests.post(self.OSV_API_URL, json=payload, timeout=10)
            response.raise_for_status()
            return response.json().get("vulns", [])
        except (requests.RequestException, ValueError):
            return []
    
    def is_fixable(self, vuln, current_version):
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_ver = event["fixed"]
                        try:
                            if version.parse(current_version) < version.parse(fixed_ver):
                                return fixed_ver
                        except:
                            pass
        return None

    def get_severity(self, vuln):
        for entry in vuln.get("severity", []):
            if entry.get("type") == "CVSS_V3":
                score_str = entry.get("score")
                try:
                    score = float(score_str)
                    for threshold, label in self.SEVERITY_THRESHOLDS:
                        if score >= threshold:
                            return label, score
                except:
                    pass
        return "UNKNOWN", None

    def scan(self):
        total_vulns = 0
        target_packages = self.installed_packages.items()
        
        if self.only_upgradable:
            print("Scanning only upgradable packages...")
            target_packages = [(n, v) for n, v in target_packages if n in self.upgradable_packages]

        for name, ver in target_packages:
            vulns = self.query_osv(name, ver)
            if vulns:
                print(f"\n{name} ({ver}) has {len(vulns)} known vulnerability(ies):")
                for vuln in vulns:
                    severity, score = self.get_severity(vuln)
                    fixed = self.is_fixable(vuln, ver)
                    fix_text = f" → upgrade to {fixed}" if fixed else " (no fix known)"
                    print(f"  - {vuln.get('id', '???')}: {vuln.get('summary', 'No summary')}")
                    print(f"    Severity: {severity} (CVSS: {score}){fix_text}")
                total_vulns += len(vulns)

        print(f"\nScan finished. Total vulnerabilities found: {total_vulns}")


@click.command()
@click.option('--only-upgradable', is_flag=True, default=False, help="Only scan packages that can be upgraded via apt")

def main(only_upgradable):
    scanner = VulnerabilityScanner(only_upgradable=only_upgradable)
    scanner.scan()

if __name__ == '__main__':
    main()
