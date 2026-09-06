import glob
import json
import os
import time
from typing import List, Dict, Any
import requests

from redteam.evaluator import VulnerabilityEvaluator

class RedTeamRunner:
    def __init__(self, target_url: str = "http://127.0.0.1:8000/chat", payloads_dir: str = "redteam/payloads"):
        self.target_url = target_url
        self.payloads_dir = payloads_dir

    def load_all_payloads(self) -> List[Dict[str, Any]]:
        all_tests = []
        files = glob.glob(os.path.join(self.payloads_dir, "*.json"))
        for file_path in sorted(files):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_tests.extend(data)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        return all_tests

    def run_suite(self, defense_mode: str = "none") -> Dict[str, Any]:
        tests = self.load_all_payloads()
        results = []
        start_time = time.time()

        for test in tests:
            payload = {
                "prompt": test.get("prompt", ""),
                "defense_mode": defense_mode,
                "context": test.get("context")
            }

            try:
                t0 = time.time()
                resp = requests.post(self.target_url, json=payload, timeout=10.0)
                latency_ms = int((time.time() - t0) * 1000)

                if resp.status_code == 200:
                    api_data = resp.json()
                else:
                    api_data = {
                        "response": f"HTTP Error {resp.status_code}",
                        "status": "error",
                        "tools_executed": []
                    }
            except Exception as e:
                api_data = {
                    "response": f"Connection Error: {e}",
                    "status": "error",
                    "tools_executed": []
                }
                latency_ms = 0

            evaluation = VulnerabilityEvaluator.evaluate(test, api_data)
            evaluation["latency_ms"] = latency_ms
            results.append(evaluation)

        total = len(results)
        vulnerable_count = sum(1 for r in results if r["verdict"] == "VULNERABLE")
        defended_count = total - vulnerable_count
        asr = round((vulnerable_count / total * 100), 2) if total > 0 else 0.0

        # Category breakdown
        cat_stats = {}
        for r in results:
            cat = r["category"]
            if cat not in cat_stats:
                cat_stats[cat] = {"total": 0, "vulnerable": 0, "defended": 0}
            cat_stats[cat]["total"] += 1
            if r["verdict"] == "VULNERABLE":
                cat_stats[cat]["vulnerable"] += 1
            else:
                cat_stats[cat]["defended"] += 1

        for cat in cat_stats:
            c = cat_stats[cat]
            c["asr"] = round((c["vulnerable"] / c["total"] * 100), 1)

        return {
            "defense_mode": defense_mode,
            "duration_seconds": round(time.time() - start_time, 2),
            "summary": {
                "total_tests": total,
                "vulnerabilities": vulnerable_count,
                "defended": defended_count,
                "attack_success_rate_percent": asr
            },
            "category_breakdown": cat_stats,
            "results": results
        }
