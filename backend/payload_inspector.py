from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PayloadRule:
    name: str
    category: str
    pattern: str
    score: int
    description: str


class PayloadInspector:
    def __init__(self) -> None:
        self.rules = [
            PayloadRule(
                name="SQLi Union Select",
                category="sql_injection",
                pattern=r"(union\s+select|select\s+\*\s+from|or\s+1=1|drop\s+table)",
                score=38,
                description="Common SQL injection syntax detected.",
            ),
            PayloadRule(
                name="XSS Script Tag",
                category="xss",
                pattern=r"(<script.*?>|javascript:|onerror=|alert\()",
                score=32,
                description="Client-side script injection pattern detected.",
            ),
            PayloadRule(
                name="Command Injection",
                category="command_injection",
                pattern=r"(\bwhoami\b|\bcurl\b|\bwget\b|cmd\.exe|/bin/sh|&&|\|\|)",
                score=36,
                description="Operating-system command execution markers detected.",
            ),
            PayloadRule(
                name="Suspicious Shell Fragment",
                category="shell_fragment",
                pattern=r"(\$\(|`.+?`|powershell\s+-enc|base64\s+-d|chmod\s+\+x)",
                score=28,
                description="Encoded or shell-oriented fragment detected.",
            ),
            PayloadRule(
                name="Path Traversal",
                category="path_traversal",
                pattern=r"(\.\./|\.\.\\|/etc/passwd|boot\.ini)",
                score=25,
                description="Directory traversal pattern detected.",
            ),
        ]

    def inspect(self, payload: str | None, enabled: bool = True) -> dict:
        if not enabled or not payload:
            return {"total_score": 0.0, "findings": []}

        findings: list[dict] = []
        for rule in self.rules:
            matches = re.finditer(rule.pattern, payload, flags=re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "rule_name": rule.name,
                        "category": rule.category,
                        "matched_fragment": match.group(0)[:255],
                        "risk_score": float(rule.score),
                        "details": rule.description,
                    }
                )

        total_score = min(sum(item["risk_score"] for item in findings), 100.0)
        return {"total_score": total_score, "findings": findings}
