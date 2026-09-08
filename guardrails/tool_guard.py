import re
from typing import Tuple, Optional, Dict, Any, Set

# RBAC Tool Permissions
ALLOWED_PUBLIC_TOOLS: Set[str] = {"check_balance"}
RESTRICTED_ADMIN_TOOLS: Set[str] = {"execute_sql", "wipe_audit_logs"}

# Dangerous SQL statements forbidden even in privileged context without explicit override
DESTRUCTIVE_SQL_PATTERN = re.compile(r"\b(DROP|TRUNCATE|ALTER|GRANT|REVOKE)\b", re.IGNORECASE)

class ToolGuardrail:
    @staticmethod
    def authorize(tool_name: str, args: Dict[str, Any], caller_role: str = "customer") -> Tuple[bool, Optional[str]]:
        """
        Enforces Role-Based Access Control (RBAC) and least privilege on LLM agent tools.
        """
        # 1. Role-Based Access Control
        if tool_name in RESTRICTED_ADMIN_TOOLS:
            if caller_role != "admin":
                return False, f"Unauthorized Tool Invocation: '{tool_name}' requires privileged role 'admin'. Caller has role '{caller_role}'."

        # 2. Tool Parameter Validation: issue_refund
        if tool_name == "issue_refund":
            amount = args.get("amount", 0)
            try:
                amount_val = float(amount)
            except (ValueError, TypeError):
                return False, "Policy Violation: Invalid refund amount format."

            if amount_val > 100.0 and caller_role not in ["admin", "manager"]:
                return False, f"Policy Violation: Refund amount ${amount_val} exceeds unmanaged limit ($100)."

        # 3. Tool Parameter Validation: execute_sql (SQL Injection & DDL Prevention)
        if tool_name == "execute_sql":
            query = str(args.get("query", ""))
            if DESTRUCTIVE_SQL_PATTERN.search(query):
                if not args.get("allow_destructive_ddl", False):
                    return False, "Policy Violation: Destructive DDL statement blocked by tool security policy."

        # 4. Unknown tool check
        if tool_name not in ALLOWED_PUBLIC_TOOLS and tool_name not in RESTRICTED_ADMIN_TOOLS and tool_name != "issue_refund":
            return False, f"Policy Violation: Unregistered tool '{tool_name}'."

        return True, None
