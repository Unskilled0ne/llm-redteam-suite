from typing import Tuple, Optional, Dict, Any, List

# RBAC Tool Permissions
ALLOWED_PUBLIC_TOOLS = {"check_balance"}
RESTRICTED_ADMIN_TOOLS = {"execute_sql", "wipe_audit_logs"}

class ToolGuardrail:
    @staticmethod
    def authorize(tool_name: str, args: Dict[str, Any], caller_role: str = "customer") -> Tuple[bool, Optional[str]]:
        """
        Enforces Role-Based Access Control (RBAC) and least privilege on LLM agent tools.
        """
        if tool_name in RESTRICTED_ADMIN_TOOLS:
            if caller_role != "admin":
                return False, f"Unauthorized Tool Invocation: '{tool_name}' requires privileged role 'admin'. Caller has role '{caller_role}'."

        if tool_name == "issue_refund":
            amount = args.get("amount", 0)
            if amount > 100.0 and caller_role != "manager":
                return False, f"Policy Violation: Refund amount ${amount} exceeds unmanaged limit ($100)."

        return True, None
