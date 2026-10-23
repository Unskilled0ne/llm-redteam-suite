# Adversarial LLM Red-Teaming & Security Evaluation Suite

**Automated Red-Teaming, Prompt Injection Testing, and Guardrail Benchmarking**  

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OWASP GenAI](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange.svg)](https://genai.owasp.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Overview

This repository provides an **Adversarial LLM Red-Teaming & Security Evaluation Framework** designed to audit AI agents against the **OWASP Top 10 for Large Language Model Applications**.

The suite includes two primary components:
1. **Realistic Target Agent (`target_app/`):** A simulated banking assistant with confidential business instructions, canary tokens, and privileged tool integrations (`execute_sql`, `wipe_audit_logs`).
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
git clone https://github.com/Unskilled0ne/llm-redteam-suite.git
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

## 🚀 Deployment & Setup Guides

### 👤 Option A: Personal Setup (For Researchers & Developers)

Get running locally in less than 2 minutes to test prompts and explore the guardrails:

```bash
# 1. Clone and enter the repository
git clone https://github.com/Unskilled0ne/llm-redteam-suite.git
cd llm-redteam-suite

# 2. Set up virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Launch the Assistant Server
./run_benchmark.py --serve --port 8000
```

Now choose how you want to interact:
* **Interactive Web Chat:** Open **`http://127.0.0.1:8000`** in your browser to chat and test 1-click attack buttons.
* **Terminal Shell:** Open another terminal tab and run `./chat.py`.
* **Run the Automated OWASP Benchmark:** Run `./run_benchmark.py` to test all 12 adversarial probes and generate reports.

#### Connecting Your Personal AI API Key
Copy the environment template:
```bash
cp .env.example .env
```
Edit `.env` to plug in your chosen model:
* **Google Gemini:** `LLM_PROVIDER=gemini` and `GEMINI_API_KEY=your_key`
* **OpenAI (GPT-4o):** `LLM_PROVIDER=openai` and `OPENAI_API_KEY=your_key`
* **Local Meta Llama (Offline):** Run `ollama run llama3` and set `LLM_PROVIDER=ollama`

---

### 🏛️ Option B: Enterprise & Banking Deployment Guide

For banks, FinTechs, and institutions deploying LLM agents into customer-facing or internal workflows:

#### 1. Zero-Trust Architecture Blueprint
Deploy the assistant as a hardened **AI Gateway** in front of your core LLM provider:
```
[ Untrusted User / Customer ]
              │
              ▼
    ┌──────────────────┐
    │ Web Reverse Proxy│ (TLS Termination & Rate Limiting)
    └─────────┬────────┘
              │
              ▼
    ┌──────────────────────────────────────────┐
    │  FinCorp AI Security Gateway (FastAPI)    │
    │  ├── 1. Input Guard (Unicode & B64 Scan) │
    │  ├── 2. AI Guard (Semantic LLM-as-a-Judge)
    │  ├── 3. Tool Guard (RBAC & DDL Blocker)  │
    │  └── 4. Output Guard (Secret & PII Filter)
    └──────────────────┬───────────────────────┘
                       │ (Sanitized Context & Delimited Prompts)
                       ▼
    ┌──────────────────────────────────────────┐
    │ Enterprise LLM (Azure OpenAI / On-Prem)  │
    └──────────────────────────────────────────┘
```

#### 2. Production Hardening Configuration
Set these production environment variables in `.env` or your Kubernetes secrets:
```ini
# Enforce production isolation
APP_ENV=production
DEFAULT_DEFENSE_MODE=hardened
ALLOW_INSECURE_MODE=false

# Corporate Canary Token (Used to detect unauthorized prompt leaks in outputs)
CANARY_TOKEN=FINCORP_CORP_CANARY_X99814_SECRET

# Dual-Layer AI Guardrail Model
AI_GUARD_PROVIDER=gemini  # or openai, azure, ollama
AI_GUARD_MODEL=gemini-1.5-flash
```

#### 3. Database Least-Privilege & RBAC
In enterprise banking, agent tools must follow strict least privilege:
* **Driver-Level DDL Rejection:** [`AgentTools.execute_sql`](file:///home/unskilledone/Desktop/Herman/llm-redteam-suite/target_app/tools.py) automatically blocks destructive statements (`DROP`, `TRUNCATE`, `ALTER`) at the Python driver level.
* **Database Connection Credentials:** Configure your database connector with a read-only role (`SELECT` only on authorized views, no write access to `customer_accounts`).
* **Tool Authorization:** Public customer callers are restricted to `check_balance`. Privileged tools require authenticated JWT roles (`admin` or `manager`).

#### 4. Container & Kubernetes Orchestration
The included [`Dockerfile`](file:///home/unskilledone/Desktop/Herman/llm-redteam-suite/Dockerfile) runs under an unprivileged user (`appuser`) with built-in health probes:
```bash
# Launch with Docker Compose
docker compose up -d

# Inspect live container health
docker compose ps
```

* **Kubernetes Liveness Probe:** `GET /health` (Port 8000)
* **Kubernetes Readiness Probe:** `GET /ready` (Verifies guardrails and model connectivity)
* **Prometheus / SIEM Metrics:** `GET /metrics` (Streams blocked attacks and violation counts)

#### 5. Regulatory & Compliance Alignment
* **OWASP Top 10 for LLMs (2025/2026):** Fully addresses LLM01, LLM02, LLM03, LLM06, and Indirect Injections.
* **EU Digital Operational Resilience Act (DORA):** Audit logging on privileged tool executions and continuous security monitoring.
* **PCI-DSS v4.0:** Output Guardrail validates payment card numbers with the Luhn algorithm to prevent credit card leakage.
---

## 💻 Web & Terminal Interfaces

The platform includes two zero-friction interfaces:

### 1. Unified Web Security Console (`http://127.0.0.1:8000`)
A responsive, multi-tab operations center featuring:
* **💬 Live Assistant & RAG Simulator:** Real-time conversational banking chat with 1-click adversarial probe shortcuts and poisoned RAG document injection chips (Poisoned Resume, Poisoned Email Ticket).
* **📊 1-Click OWASP Benchmark:** Execute full before/after red-team evaluations directly from the browser with live visual progress bars, category breakdown cards, and direct markdown report downloads.
* **🧬 Adaptive Adversarial Fuzzer:** Test prompt resilience against 6 automated mutation vectors (Synonym substitution, Roleplay framing, Base64 smuggling, Zero-width stealth, and XML breakout).
* **📡 SOC / SOAR Incident Feed:** Real-time stream of security containment alerts dispatched to the incident response platform (`soar-incident-response` / Aegis-SOAR).
* **⚙️ Pluggable Model Selector:** Instant modal switcher between Local Dynamic Simulation, Google Gemini, OpenAI GPT-4o, and Meta Llama via Ollama.

### 2. Standalone Terminal Shell (`./chat.py`)
A fast, zero-dependency interactive CLI chat client for rapid testing from any terminal.

---

## 🔄 DevSecOps CI/CD Pipeline

The framework includes an automated GitHub Actions workflow ([`.github/workflows/ai-security.yml`](file:///home/unskilledone/Desktop/Herman/llm-redteam-suite/.github/workflows/ai-security.yml)) providing automated security gating for AI deployments:
* **Automated Unit & Integration Testing:** Executes test suites validating all input, output, tool, and semantic AI guardrails.
* **Automated Red-Teaming Benchmark:** Runs the 12-vector OWASP audit on every push and pull request.
* **0.0% Hardened ASR Quality Gate:** Fails the build pipeline if any adversarial attack bypasses the hardened defense layer.
* **Artifact Archival:** Automatically uploads the generated `FinCorp_OWASP_RedTeam_Report.md` and JSON results.

---

## 📁 Repository Structure

```
llm-redteam-suite/
├── .github/workflows/
│   └── ai-security.yml            # Automated DevSecOps CI/CD pipeline & ASR gate
├── config.yaml                    # Evaluation settings & thresholds
├── requirements.txt               # Dependencies
├── run_benchmark.py               # Main CLI benchmark runner
├── chat.py                        # Standalone interactive terminal chat client
├── Dockerfile                     # Non-root production container specification
├── docker-compose.yml             # Container orchestration
├── target_app/
│   ├── app.py                     # FastAPI security gateway with live probes & endpoints
│   ├── llm_client.py              # Unified LLMEngine (Gemini, OpenAI, Ollama, Local)
│   ├── system_prompt.txt          # Confidential corporate instructions & canary tokens
│   └── tools.py                   # Privileged agent tools (SQL with DDL block, Log Purge)
├── guardrails/
│   ├── input_guard.py             # Unicode sanitization, Base64 decoding, XML boxing
│   ├── ai_guard.py                # Dual-layer LLM-as-a-Judge semantic classifier
│   ├── output_guard.py            # Canary token, API key, PII & Markdown SSRF scanner
│   ├── tool_guard.py              # RBAC least-privilege tool invocation guard
│   └── soar_bridge.py             # Webhook dispatcher to Aegis-SOAR & JSONL logger
├── redteam/
│   ├── runner.py                  # HTTP probe dispatcher & test harness
│   ├── evaluator.py               # Automated vulnerability & bypass scoring
│   ├── reporter.py                # Markdown & JSON report generator
│   ├── fuzzer.py                  # 6-strategy adaptive adversarial mutation engine
│   └── payloads/
│       ├── direct_injection.json  # DAN, ignore rules, token smuggling
│       ├── system_leakage.json    # Canary token & system prompt extraction
│       ├── indirect_injection.json# RAG document poisoning probes
│       ├── excessive_agency.json  # Tool manipulation attacks
│       └── data_exfiltration.json # Markdown image SSRF probes
├── static/
│   └── index.html                 # Multi-tab responsive web interface
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
