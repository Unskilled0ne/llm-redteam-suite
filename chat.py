#!/usr/bin/env python3
"""
FinCorp AI Assistant — Simple Interactive CLI
A clean, friendly command-line chat to test prompts against the live guardrails.
Works out of the box with zero extra dependencies.
"""
import sys
import json
import urllib.request
import urllib.error

SERVER_URL = "http://127.0.0.1:8000/chat"
HEALTH_URL = "http://127.0.0.1:8000/health"

CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

def send_message(prompt: str):
    data = json.dumps({"prompt": prompt}).encode("utf-8")
    req = urllib.request.Request(
        SERVER_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as e:
        return {"error": str(e)}

def check_server():
    try:
        req = urllib.request.Request(HEALTH_URL)
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False

def main():
    print(f"\n{CYAN}{'═' * 56}{RESET}")
    print(f" {BOLD}FinCorp AI Assistant{RESET} — {GREEN}Live Security Guardrails{RESET}")
    print(f" {DIM}Type your message below. Type 'exit' to quit.{RESET}")
    print(f"{CYAN}{'═' * 56}{RESET}\n")

    if not check_server():
        print(f"{RED}Error:{RESET} Server is not running on http://127.0.0.1:8000.")
        print(f"Run {CYAN}./run_benchmark.py --serve --port 8000{RESET} in another terminal first.\n")
        sys.exit(1)

    while True:
        try:
            prompt = input(f"{CYAN}{BOLD}💬 You > {RESET}").strip()
            if not prompt:
                continue
            if prompt.lower() in ["exit", "quit", "q"]:
                print(f"\n{DIM}Goodbye!{RESET}\n")
                break

            data = send_message(prompt)

            if "error" in data:
                print(f"{RED}Connection error:{RESET} {data['error']}\n")
                continue

            status = data.get("status")
            guardrail = data.get("guardrail_triggered")
            answer = data.get("response", "")

            if status == "blocked":
                print(f"{RED}{BOLD}🛡️ Blocked:{RESET} {YELLOW}{guardrail or 'Violates security policy'}{RESET}")
                print(f"   {DIM}{answer}{RESET}\n")
            else:
                print(f"{GREEN}{BOLD}🤖 Assistant:{RESET} {answer}\n")

        except KeyboardInterrupt:
            print(f"\n{DIM}Session closed.{RESET}\n")
            break

if __name__ == "__main__":
    main()
