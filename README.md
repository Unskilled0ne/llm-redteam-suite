# Adversarial LLM Red-Teaming & Security Evaluation Suite 🤖⚔️

**Automated Red-Teaming, Prompt Injection Testing, and Guardrail Benchmarking for Enterprise GenAI Systems**  
*Engineered by [Vasilis Tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![OWASP GenAI](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange.svg)](https://genai.owasp.org)
[![NVIDIA Garak](https://img.shields.io/badge/NVIDIA-Garak%20Compatible-76B900.svg)](https://github.com/NVIDIA/garak)
[![Promptfoo](https://img.shields.io/badge/CI%2FCD-Promptfoo%20Ready-purple.svg)](https://promptfoo.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Executive Overview

This repository provides an enterprise-grade **Adversarial LLM Red-Teaming & Security Evaluation Framework** designed to audit AI agents against the **OWASP Top 10 for Large Language Model Applications**.

The toolkit includes:
1. **Realistic Enterprise Target Agent (`target_app/`):** A simulated banking assistant with confidential business instructions, canary tokens, and privileged tool integrations (`execute_sql`, `wipe_audit_logs`).
2. **Multi-Vector Adversarial Attack Suites (`redteam/payloads/`):** Test cases spanning Direct Prompt Injection, Jailbreaking (DAN), System Prompt Extraction, Indirect RAG Document Poisoning, Excessive Agency, and Markdown SSRF Exfiltration.
3. **Defense & Guardrail Engineering Layer (`guardrails/`):** Input signature inspection, context boundary encapsulation (`<user_input>`), Role-Based Access Control (RBAC) tool guardrails, and secret/canary output leak detection.
4. **Automated Evaluator & Reporter (`redteam/runner.py`):** Calculates Attack Success Rates (ASR), generates executive Markdown/HTML reports, and supports integration with **NVIDIA Garak** and **Promptfoo**.

---

## 🏗️ Architecture & Evaluation Flow

```
                     ┌──────────────────────────────────────────────────┐
                     │          Adversarial Red-Team Runner             │
                     │  (Direct Injections, Ingestion Poisoning, Tools) │
                     └────────────────────────┬─────────────────────────┘
                                              │
                                              ▼
                        ┌───────────────────────────────────────────┐
                        │      Target Application Request Flow      │
                        │                                           │
                        │    1. Input Guardrail & Delimiter Boxing  │
                        │    2. Enterprise LLM System Prompt        │
                        │    3. RBAC Tool Invocation Guard          │
                        │    4. Output Canary & Leak Scanner        │
                        └─────────────────────┬─────────────────────┘
                                              │
                                              ▼
                        ┌───────────────────────────────────────────┐
                        │     Automated Vulnerability Evaluator     │
                        │ (Scoring: BYPASS vs. NEUTRALIZED vs. LEAK)│
                        └─────────────────────┬─────────────────────┘
                                              │
                         ┌────────────────────┴────────────────────┐
                         ▼                                         ▼
            ┌───────────────────────────┐             ┌───────────────────────────┐
            │   Terminal Rich Tables    │             │   Markdown / HTML Report  │
            │  (Before vs After ASR %)  │             │   (OWASP Top 10 Metrics)  │
            └───────────────────────────┘             └───────────────────────────┘
```

---

## 🛡️ OWASP LLM Top 10 Coverage

| Category ID | Vulnerability Focus | Attack Probes Implemented | Defense Mechanism |
| :--- | :--- | :--- | :--- |
| **LLM01** | Prompt Injection | Instruction ignore, DAN mode, tag breakout, Base64 token smuggling | Input signature regex + XML delimiter bounding |
| **LLM02** | Sensitive Info Disclosure | Verbatim system extraction, canary token theft, API key harvesting | Output guardrail secret & canary scanner |
| **LLM03** | Insecure Output Handling | Markdown image rendering SSRF, unauthorized external link generation | Output parser blocking unverified image syntax |
| **LLM06** | Excessive Agency | Coercing agent into calling `execute_sql` or `wipe_audit_logs` | RBAC Tool Execution Guardrail |
| **INDIRECT** | Indirect Prompt Injection | Malicious instructions hidden in ingested resumes & emails | Dual-context inspection & input sanitization |

---

## 📊 Benchmark Results: Defense Impact

Running the automated benchmark against the target yields immediate measurable risk reduction:

| Metric | Unprotected Agent (Zero Defenses) | Hardened Agent (Defense Layer Active) | Security Impact |
| :--- | :---: | :---: | :---: |
| **Total Adversarial Probes** | 12 | 12 | Baseline verified |
| **Vulnerabilities Exploited** | **8** | **0** | **-8 critical flaws neutralized** |
| **Attacks Blocked / Defended** | 4 | 12 | +8 attacks mitigated |
| **Attack Success Rate (ASR)** | **66.67%** | **0.0%** | **66.7% Vulnerability Reduction** |

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
git clone https://github.com/your-username/llm-redteam-suite.git
cd llm-redteam-suite

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the End-to-End Evaluation Benchmark

Launch the automated benchmark to assess the target agent in both unprotected and hardened configurations:
```bash
./run_benchmark.py
```
This will:
1. Start the target agent on a local thread.
2. Execute all adversarial probe suites against both defense tiers.
3. Print real-time Rich comparison tables in the console.
4. Export the complete benchmark to `reports/benchmark_report.md` and `reports/benchmark_results.json`.

### 3. Run Target Server for External Tools (Garak / Promptfoo)

Start the standalone API server:
```bash
./run_benchmark.py --serve --port 8000
```

Run Promptfoo regression tests:
```bash
npx promptfoo@latest eval -c integrations/promptfoo.yaml
```

---

## 📁 Repository Structure

```
llm-redteam-suite/
├── config.yaml                    # Evaluation settings & thresholds
├── requirements.txt               # Dependencies
├── run_benchmark.py               # Main CLI benchmark runner
├── target_app/
│   ├── app.py                     # FastAPI agent implementation (unprotected vs. hardened)
│   ├── system_prompt.txt          # Confidential corporate instructions & canary tokens
│   └── tools.py                   # Simulated privileged agent tools (SQL, Log Purge)
├── guardrails/
│   ├── input_guard.py             # Pattern matching & structural delimiter encapsulation
│   ├── output_guard.py            # Canary token & API secret leakage scanner
│   └── tool_guard.py              # RBAC least-privilege tool execution policy
├── redteam/
│   ├── runner.py                  # HTTP probe dispatcher & test harness
│   ├── evaluator.py               # Automated vulnerability & bypass scoring
│   ├── reporter.py                # Markdown & JSON report generator
│   └── payloads/
│       ├── direct_injection.json  # DAN, ignore rules, token smuggling
│       ├── system_leakage.json    # Canary token & system prompt extraction
│       ├── indirect_injection.json# RAG document poisoning probes
│       ├── excessive_agency.json  # Tool manipulation attacks
│       └── data_exfiltration.json # Markdown image SSRF probes
├── integrations/
│   ├── promptfoo.yaml             # Promptfoo CI/CD integration
│   └── garak_config.yaml          # NVIDIA Garak scanning profile
└── reports/
    └── benchmark_report.md        # Exported evaluation deliverables
```

---

## 👤 Author

**Vasilis Tsiamouras**  
- LinkedIn: [linkedin.com/in/vasilis-tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)  
- Track: Offensive Security & Penetration Testing | Computer Science, University of Thessaly
