"""LeakFence: explicit disclosure contracts for bounded JSON responses."""
from .guard import Context, Denied, Guard, Policy, inspect

__all__ = ["Context", "Denied", "Guard", "Policy", "inspect"]
