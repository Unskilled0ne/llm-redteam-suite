import re
from typing import Tuple, Optional, Dict, Any, Set

ALLOWED_PUBLIC_TOOLS: Set[str] = {"check_balance"}
RESTRICTED_ADMIN_TOOLS: Set[str] = {"execute_sql", "wipe_audit_logs"}

DESTRUCTIVE_SQL_PATTERN = re.compile(r"\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b", re.IGNORECASE)

class ToolGuardrail:
    @staticmethod
    def authorize(tool_name: str, args: Dict[str, Any], caller_role: str = "customer") -> Tuple[bool, Optional[str]]:
        """
        Enforces Role-Based Access Control (RBAC) and least privilege on LLM agent tools.
        """
        if not isinstance(args, dict):
            args = {}
        role = (caller_role or "customer").lower().strip()

        if tool_name in RESTRICTED_ADMIN_TOOLS:
            if role != "admin":
                return False, f"Unauthorized Tool Invocation: '{tool_name}' requires privileged role 'admin'. Caller has role '{caller_role}'."

        if tool_name == "issue_refund":
            amount = args.get("amount", 0)
            try:
                amount_val = float(amount)
            except (ValueError, TypeError):
                return False, "Policy Violation: Invalid refund amount format."

            if amount_val <= 0:
                return False, "Policy Violation: Refund amount must be strictly greater than $0.00."

            if amount_val > 100.0 and role not in ["admin", "manager"]:
                return False, f"Policy Violation: Refund amount ${amount_val} exceeds unmanaged limit ($100)."

        if tool_name == "execute_sql":
            query = str(args.get("query", ""))
            if DESTRUCTIVE_SQL_PATTERN.search(query):
                return False, "Policy Violation: Destructive DDL statement blocked by tool security policy."

        if tool_name not in ALLOWED_PUBLIC_TOOLS and tool_name not in RESTRICTED_ADMIN_TOOLS and tool_name != "issue_refund":
            return False, f"Policy Violation: Unregistered tool '{tool_name}'."

        return True, None
