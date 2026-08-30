from __future__ import annotations
import re
from bs4 import BeautifulSoup
from app.adapters.base import Observation, SignalResult, SourceReport
from typing import Optional


def analyze_content(body_text: Optional[str], headers: Optional[dict] = None) -> SourceReport:
    report = SourceReport(source="content", status="ACTIVE")
    if not body_text:
        report.status = "UNAVAILABLE"
        for sig, w in [
            ("has_contact_info", 3),
            ("has_privacy_policy", 3),
            ("has_about_page", 2),
        ]:
            report.observations.append(
                Observation(
                    source="content",
                    signal=sig,
                    result=SignalResult.UNAVAILABLE,
                    weight=w,
                    reason="No content retrieved",
                    confidence=0.0,
                )
            )
        return report

    soup = BeautifulSoup(body_text, "lxml")
    text = soup.get_text(" ", strip=True).lower()
    links = [a.get("href", "").lower() for a in soup.find_all("a", href=True)]

    has_contact = any(x in " ".join(links) for x in ["/contact", "contact-us", "contact.html"]) or bool(
        re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)
    ) or bool(re.search(r"(\+?\d[\d\s\-().]{7,}\d)", text))
    report.observations.append(
        Observation(
            source="content",
            signal="has_contact_info",
            result=SignalResult.PASS if has_contact else SignalResult.FAIL,
            weight=3,
            confidence=0.7,
            reason="Contact signals found" if has_contact else "No clear contact signals",
        )
    )

    has_privacy = any("privacy" in l for l in links)
    report.observations.append(
        Observation(
            source="content",
            signal="has_privacy_policy",
            result=SignalResult.PASS if has_privacy else SignalResult.FAIL,
            weight=3,
            confidence=0.65,
            reason="Privacy policy link found" if has_privacy else "No privacy policy link detected",
        )
    )

    has_about = any(x in " ".join(links) for x in ["/about", "about-us", "about.html"])
    report.observations.append(
        Observation(
            source="content",
            signal="has_about_page",
            result=SignalResult.PASS if has_about else SignalResult.FAIL,
            weight=2,
            confidence=0.6,
            reason="About page found" if has_about else "No about page detected",
        )
    )

    return report
