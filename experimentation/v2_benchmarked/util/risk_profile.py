from enum import Enum

from typing import List


class RiskLevel(Enum):
    NONE = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    VERY_HIGH = 4


class RiskProfile:
    def __init__(self):
        self._count = 0
        self._callables = {
            RiskLevel.NONE: [],
            RiskLevel.LOW: [],
            RiskLevel.MODERATE: [],
            RiskLevel.HIGH: [],
            RiskLevel.VERY_HIGH: [],
        }

    def add_callable(self, callable, risk_level: RiskLevel):
        self._callables[risk_level].append(callable)
        self._count += 1

    def get_ratio(self, risk_level: RiskLevel) -> float:
        return len(self._callables[risk_level])/self._count

    def __str__(self):
        return self._callables.__str__()
