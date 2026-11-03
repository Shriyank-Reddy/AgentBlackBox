"""AgentBlackBox: a tamper-evident flight recorder and policy firewall for AI agents."""

from .guard import Guard, PolicyViolation
from .policy import PolicyError, load_policy, parse_policy
from .recorder import Recorder, verify_trace

__version__ = "0.1.0"
__all__ = [
    "Guard",
    "PolicyError",
    "PolicyViolation",
    "Recorder",
    "load_policy",
    "parse_policy",
    "verify_trace",
]
