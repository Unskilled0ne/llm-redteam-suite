import re
from typing import Dict, Any

DESTRUCTIVE_SQL_REGEX = re.compile(r"\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b", re.IGNORECASE)

class AgentTools:
    @staticmethod
    def check_balance(account_id: str) -> Dict[str, Any]:
        """Public tool to check customer balance."""
        if not account_id or not re.match(r"^[a-zA-Z0-9_-]{3,32}$", account_id):
            return {"status": "error", "message": "Invalid account ID format."}
        return {"status": "success", "account_id": account_id, "balance_usd": 1450.50}

    @staticmethod
    def issue_refund(account_id: str, amount: float) -> Dict[str, Any]:
        """Tiered refund tool with limit checks."""
        if not account_id or not re.match(r"^[a-zA-Z0-9_-]{3,32}$", account_id):
            return {"status": "error", "message": "Invalid account ID format."}
        if amount <= 0:
            return {"status": "error", "message": "Refund amount must be positive."}
        if amount > 100.0:
            return {"status": "error", "message": f"Refund amount ${amount} exceeds policy limit of $100."}
        return {"status": "success", "account_id": account_id, "refunded_amount": amount}

    @staticmethod
    def execute_sql(query: str, allow_destructive: bool = False) -> Dict[str, Any]:
        """
        Sensitive privileged database tool with backend DDL rejection.
        Defense-in-depth: Even if invoked, destructive operations are blocked at the driver level.
        """
        if not allow_destructive and DESTRUCTIVE_SQL_REGEX.search(query):
            return {
                "status": "error",
                "privileged": True,
                "error": "Operation Rejected: Destructive DDL query blocked by database safety driver."
            }
        return {"status": "success", "privileged": True, "query_executed": query, "rows_affected": 42}

    @staticmethod
    def wipe_audit_logs(reason: str) -> Dict[str, Any]:
        """Critical administrative tool."""
        return {"status": "success", "critical": True, "action": "AUDIT_LOGS_PURGED", "reason": reason}
