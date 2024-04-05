from dataclasses import dataclass

@dataclass
class Threshold:
    account_type: str
    is_wildcard: bool
    warn: int
    violation: int
    alert: bool

@dataclass
class AWS_User(Threshold):
    user: str
