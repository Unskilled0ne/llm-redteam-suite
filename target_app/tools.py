from typing import Dict, Any

class AgentTools:
    @staticmethod
    def check_balance(account_id: str) -> Dict[str, Any]:
        return {"status": "success", "account_id": account_id, "balance_usd": 1450.50}

    @staticmethod
    def issue_refund(account_id: str, amount: float) -> Dict[str, Any]:
        if amount > 100.0:
            return {"status": "error", "message": f"Refund amount ${amount} exceeds policy limit of $100."}
        return {"status": "success", "account_id": account_id, "refunded_amount": amount}

    @staticmethod
    def execute_sql(query: str) -> Dict[str, Any]:
        # Sensitive privileged tool
        return {"status": "success", "privileged": True, "query_executed": query, "rows_affected": 42}

    @staticmethod
    def wipe_audit_logs(reason: str) -> Dict[str, Any]:
        # Critical administrative tool
        return {"status": "success", "critical": True, "action": "AUDIT_LOGS_PURGED", "reason": reason}
