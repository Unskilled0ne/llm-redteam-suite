#!/usr/bin/env python3
import argparse
import os
import sys
import threading
import time
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from target_app.app import app
from redteam.runner import RedTeamRunner
from redteam.reporter import BenchmarkReporter

console = Console()

def start_server_in_thread(host: str = "127.0.0.1", port: int = 8000):
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(1.5)  # Wait for server to bind
    return server

def print_rich_summary(unprotected: dict, hardened: dict, report_path: str):
    console.print()
    console.print(Panel.fit(
        "[bold cyan]LLM Red-Teaming & Security Evaluation Benchmark[/bold cyan]\n"
        "[dim]Standard: OWASP Top 10 for LLM Applications (2025/2026)[/dim]",
        border_style="cyan"
    ))

    table = Table(title="Security Posture Comparison (Before vs After Hardening)", border_style="dim")
    table.add_column("Metric", style="bold white")
    table.add_column("Unprotected", justify="center", style="bold red")
    table.add_column("Hardened Layer", justify="center", style="bold green")
    table.add_column("Impact", justify="center", style="cyan")

    u_sum = unprotected["summary"]
    h_sum = hardened["summary"]

    table.add_row("Total Adversarial Probes", str(u_sum["total_tests"]), str(h_sum["total_tests"]), "-")
    table.add_row("Bypasses / Vulnerabilities", str(u_sum["vulnerabilities"]), str(h_sum["vulnerabilities"]), f"-{u_sum['vulnerabilities'] - h_sum['vulnerabilities']} vulns")
    table.add_row("Defended / Blocked", str(u_sum["defended"]), str(h_sum["defended"]), f"+{h_sum['defended'] - u_sum['defended']} defended")
    table.add_row(
        "Attack Success Rate (ASR)",
        f"{u_sum['attack_success_rate_percent']}%",
        f"{h_sum['attack_success_rate_percent']}%",
        f"[bold cyan]{round(u_sum['attack_success_rate_percent'] - h_sum['attack_success_rate_percent'], 1)}% Drop[/bold cyan]"
    )
    console.print(table)

    # Category breakdown table
    cat_table = Table(title="OWASP Category Breakdown", border_style="dim")
    cat_table.add_column("Category", style="bold white")
    cat_table.add_column("Tests", justify="center")
    cat_table.add_column("Unprotected ASR", justify="center", style="red")
    cat_table.add_column("Hardened ASR", justify="center", style="green")
    cat_table.add_column("Status", justify="center")

    for cat, u_stat in unprotected.get("category_breakdown", {}).items():
        h_stat = hardened.get("category_breakdown", {}).get(cat, {"asr": 0.0, "vulnerable": 0})
        status = "[bold green]SECURED[/bold green]" if h_stat["vulnerable"] == 0 else "[bold yellow]PARTIAL[/bold yellow]"
        cat_table.add_row(cat, str(u_stat["total"]), f"{u_stat['asr']}%", f"{h_stat['asr']}%", status)

    console.print(cat_table)
    console.print(f"\n[bold green]✓ Benchmark complete![/bold green] Detailed report saved to: [underline cyan]{report_path}[/underline cyan]\n")

def main():
    parser = argparse.ArgumentParser(description="LLM Red-Team & Security Evaluation Benchmark")
    parser.add_argument("--serve", action="store_true", help="Run the target agent server only")
    parser.add_argument("--port", type=int, default=8000, help="Target server port (default: 8000)")
    parser.add_argument("--target-url", default="http://127.0.0.1:8000/chat", help="Target API endpoint")
    args = parser.parse_args()

    if args.serve:
        console.print(f"[bold cyan]Starting FinCorp AI Target Agent on http://0.0.0.0:{args.port}...[/bold cyan]")
        uvicorn.run(app, host="0.0.0.0", port=args.port)
        return

    # Start target app in background thread
    console.print("[dim]Starting local target agent...[/dim]")
    server = start_server_in_thread(port=args.port)

    runner = RedTeamRunner(target_url=args.target_url)

    console.print("[bold yellow][*] Executing Suite 1: Unprotected Target (Zero Guardrails)...[/bold yellow]")
    unprotected_results = runner.run_suite(defense_mode="none")

    console.print("[bold cyan][*] Executing Suite 2: Hardened Target (Input & Output Guardrails)...[/bold cyan]")
    hardened_results = runner.run_suite(defense_mode="hardened")

    reporter = BenchmarkReporter(output_dir="reports")
    report_path = reporter.generate_markdown_report(unprotected_results, hardened_results)

    print_rich_summary(unprotected_results, hardened_results, report_path)
    server.should_exit = True

if __name__ == "__main__":
    main()
