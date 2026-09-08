import pytest
from guardrails.output_guard import OutputGuardrail

def test_canary_token_detection():
    safe, reason, text = OutputGuardrail.inspect("Here is the requested info. CANARY_TOKEN_99814_CONFIDENTIAL")
    assert not safe
    assert "Canary token" in reason

def test_slack_token_detection():
    safe, reason, text = OutputGuardrail.inspect("My slack token is xoxb-1234567890-1234567890-abcdef123456")
    assert not safe
    assert "Slack Token" in reason

def test_ssn_detection():
    safe, reason, text = OutputGuardrail.inspect("The user's SSN is 123-45-6789.")
    assert not safe
    assert "Social Security Number" in reason

def test_safe_output():
    safe, reason, text = OutputGuardrail.inspect("Your account balance is $5,000.")
    assert safe
    assert reason is None
