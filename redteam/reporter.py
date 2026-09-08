import json
import os
from datetime import datetime, timezone
from typing import Dict, Any

class BenchmarkReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_markdown_report(self, unprotected: Dict[str, Any], hardened: Dict[str, Any]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        u_sum = unprotected["summary"]
        h_sum = hardened["summary"]

        md = f"""# LLM Red-Teaming & Security Evaluation Benchmark

**Evaluated Target:** FinCorp AI Enterprise Assistant  
**Assessment Standard:** OWASP Top 10 for LLM Applications (2025/2026)  
**Conducted At:** {now}  
**Lead Security Engineer:** Vasilis Tsiamouras  

---

## 📊 Executive Summary & Defense Impact

| Metric | Unprotected Target | Hardened Defense Layer | Risk Reduction |
| :--- | :---: | :---: | :---: |
| **Total Adversarial Probes** | {u_sum['total_tests']} | {h_sum['total_tests']} | - |
| **Bypasses / Vulnerabilities** | **{u_sum['vulnerabilities']}** | **{h_sum['vulnerabilities']}** | **-{u_sum['vulnerabilities'] - h_sum['vulnerabilities']} vulnerabilities** |
| **Defended / Neutralized** | {u_sum['defended']} | {h_sum['defended']} | +{h_sum['defended'] - u_sum['defended']} defended |
| **Attack Success Rate (ASR)** | **{u_sum['attack_success_rate_percent']}%** | **{h_sum['attack_success_rate_percent']}%** | **{round(u_sum['attack_success_rate_percent'] - h_sum['attack_success_rate_percent'], 1)}% drop** |

---

## 🛡️ Category Breakdown (OWASP LLM Top 10)

| OWASP Category | Tests | Unprotected ASR | Hardened ASR | Status |
| :--- | :---: | :---: | :---: | :---: |
"""
        for cat, u_stat in unprotected.get("category_breakdown", {}).items():
            h_stat = hardened.get("category_breakdown", {}).get(cat, {"asr": 0.0, "vulnerable": 0})
            status = "✅ SECURED" if h_stat["vulnerable"] == 0 else "⚠️ PARTIAL"
            md += f"| `{cat}` | {u_stat['total']} | {u_stat['asr']}% | {h_stat['asr']}% | {status} |\n"

        md += """
---

## 🔍 Detailed Adversarial Test Results (Hardened Mode)

| Test ID | Probe Name | Category | Verdict | Severity | Defense Reason |
| :--- | :--- | :--- | :---: | :---: | :--- |
"""
        for r in hardened.get("results", []):
            verdict_badge = "🛡️ DEFENDED" if r["verdict"] == "DEFENDED" else "❌ VULNERABLE"
            md += f"| `{r['test_id']}` | {r['name']} | `{r['category']}` | {verdict_badge} | {r['severity']} | {r['reason']} |\n"

        md += """
---

## 🛠️ Remediation & Security Controls Implemented

1. **Input Guardrail Filter:** Intercepts adversarial signatures, system tag injection (`</user_input>`), and jailbreak tokens prior to model context ingestion.
2. **Context Delimiter Isolation:** Sandboxes untrusted user prompt within structural XML boundary tags.
3. **Canary Token Monitoring:** Continuous output inspection scanning for confidential markers and credentials.
4. **Markdown Exfiltration Filtering:** Automatically blocks unverified external image markdown patterns targeting external domains.
"""

        file_path = os.path.join(self.output_dir, "benchmark_report.md")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(md)

        # Write JSON summary
        json_path = os.path.join(self.output_dir, "benchmark_results.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"unprotected": unprotected, "hardened": hardened, "timestamp": now}, f, indent=2)

        # Write SARIF output
        self.generate_sarif_report(hardened)

        return file_path

    def generate_sarif_report(self, hardened: Dict[str, Any]):
        """Generates a GitHub-compatible SARIF output mapping findings to MITRE ATLAS."""
        runs = []
        results = []
        
        # MITRE ATLAS mappings
        atlas_map = {
            "LLM01_PROMPT_INJECTION": "AML.T0051",
            "LLM_PROMPT_INJECTION": "AML.T0051",
            "LLM07_SYSTEM_PROMPT_LEAKAGE": "AML.T0054",
            "LLM04_MODEL_DOS": "AML.T0029",
            "INDIRECT_PROMPT_INJECTION": "AML.T0053",
            "LLM08_VECTOR_RAG_POISONING": "AML.T0053"
        }

        for r in hardened.get("results", []):
            if r["verdict"] == "VULNERABLE":
                mitre_id = atlas_map.get(r["category"], "AML.T0000")
                results.append({
                    "ruleId": f"{r['category']} ({mitre_id})",
                    "level": "error" if r["severity"] == "CRITICAL" else "warning",
                    "message": {
                        "text": f"Vulnerability detected: {r['name']}. {r['reason']}"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "target_app/app.py"},
                            "region": {"startLine": 1}
                        }
                    }]
                })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "FinCorp AI Red-Teaming Engine",
                        "version": "1.0"
                    }
                },
                "results": results
            }]
        }

        sarif_path = os.path.join(self.output_dir, "benchmark_report.sarif")
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
