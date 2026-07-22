from models import ScanResult, Vulnerability

SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "UNKNOWN": 10,
}


def _severity_score(vuln: Vulnerability) -> float:
    return SEVERITY_SCORES.get(vuln.severity.upper(), 10)


def _epss_score(vuln: Vulnerability) -> float:
    if vuln.epss is not None:
        return vuln.epss * 100
    return 0


def _fix_score(vuln: Vulnerability) -> float:
    has_fix = bool(vuln.fixed_version and vuln.fixed_version.strip())
    return 0 if has_fix else 100


def compute_risk(vuln: Vulnerability) -> tuple[float, str]:
    severity = _severity_score(vuln)
    epss = _epss_score(vuln)
    fix = _fix_score(vuln)

    sev_w = 0.50
    epss_w = 0.35
    fix_w = 0.15

    score = severity * sev_w + epss * epss_w + fix * fix_w
    score = min(100, max(0, score))

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "info"

    return round(score, 1), level


def enrich(results: list[ScanResult]) -> list[ScanResult]:
    for scan in results:
        for v in scan.vulnerabilities:
            score, level = compute_risk(v)
            v.risk_score = score
            v.risk_level = level
    return results


def get_top(results: list[ScanResult], n: int = 10) -> list[dict]:
    findings: list[dict] = []
    for scan in results:
        for v in scan.vulnerabilities:
            findings.append({
                "repo": scan.repo,
                "scanner": scan.scanner,
                "id": v.id,
                "package": v.package,
                "severity": v.severity,
                "epss": v.epss,
                "risk_score": v.risk_score,
                "risk_level": v.risk_level,
                "fixed_version": v.fixed_version,
                "description": v.description[:120],
            })

    findings.sort(key=lambda f: f.get("risk_score") or 0, reverse=True)
    return findings[:n]
