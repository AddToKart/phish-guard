import math
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

# A selection of red-flag keywords that commonly appear in phishing attempts
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "update",
    "invoice",
    "account",
    "secure",
    "unlock",
    "bank",
    "urgent",
    "password",
    "confirm",
    "click",
    "warning",
    "limited",
    "suspend",
    "expire",
}

SUSPICIOUS_TLDS = {
    "zip",
    "ru",
    "cn",
    "tk",
    "ml",
    "ga",
    "cf",
    "work",
    "support",
    "gq",
}

SAFE_KEYWORDS = {
    "support",
    "help",
    "docs",
    "learn",
    "status",
    "safe",
}

IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class Feature:
    name: str
    value: float
    weight: float
    description: str
    evidence: Optional[str] = None

    @property
    def impact(self) -> float:
        return self.value * self.weight

    @property
    def is_flagged(self) -> bool:
        return self.value > 0.35 and self.weight >= 0


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def _normalize(value: float, scale: float) -> float:
    if scale <= 0:
        return 0.0
    return max(0.0, min(value / scale, 1.0))


def _count_suspicious_terms(text: str) -> List[str]:
    text_lower = text.lower()
    hits = [term for term in SUSPICIOUS_KEYWORDS if term in text_lower]
    return hits


def _looks_like_ip(host: str) -> bool:
    return bool(IP_REGEX.match(host))


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    digits = sum(1 for char in text if char.isdigit())
    return digits / len(text)


def _shannon_entropy(text: str) -> float:
    """Return Shannon entropy of the input string."""
    if not text:
        return 0.0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def extract_features(url: str, content: Optional[str] = None) -> List[Feature]:
    """Derive heuristic features from a URL and optional HTML/content."""
    parsed = urlparse(url if re.match(r"^[a-zA-Z]+://", url) else f"https://{url}")

    host = parsed.netloc.lower()
    path = parsed.path or "/"
    full_url = parsed.geturl()
    has_https = parsed.scheme == "https"

    host_parts = [part for part in host.split(".") if part]
    tld = host_parts[-1] if host_parts else ""
    subdomain_depth = max(len(host_parts) - 2, 0)
    host_label_count = len(host_parts)
    host_core = host.replace(".", "")

    digit_weight = _normalize(_digit_ratio(host_core), 0.35)
    entropy_value = _shannon_entropy(host_core)
    entropy_normalized = _normalize(max(entropy_value - 3.3, 0.0), 1.7)
    keyword_hits = _count_suspicious_terms(full_url)

    # Feature construction
    features: List[Feature] = [
        Feature(
            name="url_length",
            value=_normalize(len(full_url), 110),
            weight=1.4,
            description="URL is unusually long, which can hide malicious parameters.",
            evidence=f"Length {len(full_url)} characters",
        ),
        Feature(
            name="has_ip_address",
            value=1.0 if _looks_like_ip(host) else 0.0,
            weight=1.6,
            description="Domain is a direct IP address instead of a hostname.",
            evidence=f"Host '{host}'",
        ),
        Feature(
            name="suspicious_tld",
            value=1.0 if tld in SUSPICIOUS_TLDS else 0.0,
            weight=1.2,
            description="Top-level domain is frequently associated with phishing.",
            evidence=f"TLD '{tld or 'unknown'}'",
        ),
        Feature(
            name="missing_https",
            value=0.0 if has_https else 1.0,
            weight=1.1,
            description="Site does not use HTTPS, reducing authenticity.",
            evidence=f"Scheme '{parsed.scheme or 'http assumed'}'",
        ),
        Feature(
            name="contains_at_symbol",
            value=1.0 if "@" in full_url else 0.0,
            weight=0.9,
            description="URL contains '@', often used to obscure real destinations.",
            evidence="'@' present in URL" if "@" in full_url else None,
        ),
        Feature(
            name="hyphen_density",
            value=_normalize(full_url.count("-"), 4),
            weight=0.7,
            description="Heavy hyphen use can spoof subdomains or brands.",
            evidence=f"{full_url.count('-')} hyphen characters",
        ),
        Feature(
            name="subdomain_depth",
            value=_normalize(subdomain_depth, 4),
            weight=0.8,
            description="Deeply nested subdomains can disguise true origin.",
            evidence=f"Depth {subdomain_depth}",
        ),
        Feature(
            name="url_keyword_risk",
            value=_normalize(len(keyword_hits), 3),
            weight=0.9,
            description="URL contains high-risk keywords linked to phishing.",
            evidence=", ".join(keyword_hits) or None,
        ),
        Feature(
            name="single_label_domain",
            value=1.0 if host_label_count < 2 else 0.0,
            weight=1.0,
            description="Domain is missing a public suffix or dot, which is atypical for legitimate sites.",
            evidence=f"Host '{host}'",
        ),
        Feature(
            name="numeric_subdomain_bias",
            value=digit_weight,
            weight=0.7,
            description="High ratio of digits in the hostname can indicate algorithmically generated domains.",
            evidence=f"Digit ratio {digit_weight:.2f}",
        ),
        Feature(
            name="hostname_entropy",
            value=entropy_normalized,
            weight=0.6,
            description="Hostname exhibits high character entropy, often used to evade filters.",
            evidence=f"Entropy {entropy_value:.2f}",
        ),
        Feature(
            name="trusted_term_balance",
            value=-_normalize(len([t for t in SAFE_KEYWORDS if t in host]), 3),
            weight=0.6,
            description="Recognizable support keywords reduce risk.",
            evidence=", ".join([t for t in SAFE_KEYWORDS if t in host]) or None,
        ),
    ]

    if content:
        lowered = content.lower()
        keyword_hits = _count_suspicious_terms(lowered)
        urgent_hits = [w for w in ("urgent", "immediately", "within 24 hours", "suspend") if w in lowered]
        form_present = "<form" in lowered
        link_count = lowered.count("<a")

        features.extend(
            [
                Feature(
                    name="content_keyword_risk",
                    value=_normalize(len(keyword_hits), 5),
                    weight=1.3,
                    description="Page copy heavily uses sensitive terms.",
                    evidence=", ".join(keyword_hits) or None,
                ),
                Feature(
                    name="urgent_language",
                    value=_normalize(len(urgent_hits), 3),
                    weight=1.0,
                    description="Content pressures the user with urgent language.",
                    evidence=", ".join(urgent_hits) or None,
                ),
                Feature(
                    name="form_presence",
                    value=1.0 if form_present else 0.0,
                    weight=0.6,
                    description="Forms embedded in unsolicited messages can harvest credentials.",
                    evidence="<form> tag detected" if form_present else None,
                ),
                Feature(
                    name="link_density",
                    value=_normalize(link_count, 12),
                    weight=0.5,
                    description="Unusually high link count may funnel users to malicious destinations.",
                    evidence=f"{link_count} anchor tags",
                ),
            ]
        )

    return features


def analyze(url: str, content: Optional[str] = None) -> dict:
    features = extract_features(url, content)
    bias = -1.35
    weighted_sum = bias

    for feature in features:
        weighted_sum += feature.impact

    score = _sigmoid(weighted_sum)
    if score >= 0.7:
        verdict = "phishing"
    elif score >= 0.45:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    confidence = round(abs(score - 0.5) * 2, 3)
    signals = []

    for feature in features:
        if feature.is_flagged and feature.weight >= 0:
            signals.append(
                {
                    "feature": feature.name,
                    "message": feature.description,
                    "impact": round(feature.impact, 3),
                    "evidence": feature.evidence,
                }
            )

    signals = sorted(signals, key=lambda item: item["impact"], reverse=True)

    recommendations: List[str] = []
    if verdict != "legitimate":
        recommendations.append("Do not enter credentials or personal information on this site.")
        recommendations.append("Verify the sender or URL by contacting the organization through a known channel.")
    if score >= 0.8:
        recommendations.append("Report the site to your security team or email provider.")
    if score < 0.4:
        recommendations.append("Continue monitoring this domain; automate periodic re-checks.")

    return {
        "normalizedUrl": urlparse(url if re.match(r"^[a-zA-Z]+://", url) else f"https://{url}").geturl(),
        "score": round(score, 3),
        "verdict": verdict,
        "confidence": confidence,
        "signals": signals,
        "featureVector": [
            {
                "name": feature.name,
                "value": round(feature.value, 3),
                "weight": feature.weight,
                "impact": round(feature.impact, 3),
                "description": feature.description,
                "evidence": feature.evidence,
            }
            for feature in features
        ],
        "recommendations": recommendations,
    }
