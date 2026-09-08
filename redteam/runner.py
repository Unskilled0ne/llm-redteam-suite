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

        # Load custom target config if available
        custom_config = None
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "target_config.yaml")
        if os.path.exists(config_path):
            try:
                import yaml
                with open(config_path, "r") as f:
                    custom_config = yaml.safe_load(f).get("target")
            except Exception as e:
                print(f"Warning: Could not parse target_config.yaml: {e}")

        for test in tests:
            prompt_text = test.get("prompt", "")
            context_text = test.get("context", "")

            # Default internal payload logic
            payload = {
                "prompt": prompt_text,
                "defense_mode": defense_mode,
                "context": context_text
            }
            
            headers = {}
            target_url = self.target_url

            # Override with custom target config if specified
            if custom_config:
                target_url = custom_config.get("url", target_url)
                headers = custom_config.get("headers", {})
                req_body = custom_config.get("request_body", {})
                
                # Render payload template
                body_str = json.dumps(req_body)
                body_str = body_str.replace('"{{prompt}}"', json.dumps(prompt_text))
                body_str = body_str.replace('"{{context}}"', json.dumps(context_text) if context_text else 'null')
                payload = json.loads(body_str)

            try:
                t0 = time.time()
                resp = requests.post(target_url, headers=headers, json=payload, timeout=10.0)
                latency_ms = int((time.time() - t0) * 1000)

                if resp.status_code == 200:
                    api_data = resp.json()
                    
                    # Extract fields based on custom mappings
                    if custom_config and "response_mapping" in custom_config:
                        m = custom_config["response_mapping"]
                        text_path = m.get("text_path", "response")
                        status_path = m.get("status_path", "status")
                        tools_path = m.get("tools_path", "tools_executed")
                        
                        api_data = {
                            "response": api_data.get(text_path, str(api_data)),
                            "status": api_data.get(status_path, "allowed"),
                            "tools_executed": api_data.get(tools_path, [])
                        }
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
