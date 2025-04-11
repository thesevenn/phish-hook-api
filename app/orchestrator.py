from typing import Literal

from app.parser import EmailParser
from app.filters import filters
from app.scores.builder import ThreatScoreBuilder

class Orchestrator:
    def __init__(self, raw_data:bytes ):
        self.__features = EmailParser(raw_data).features
        self.__builder = ThreatScoreBuilder()

    def orchestrate(self, mode:Literal["f","c","fc"] = "fc"):
        if "f" in mode:
            runner = filters.RuleFilters(self.__features, self.__builder)
            runner.runner()
        if "c" in mode:
            pass
        if mode not in "fc":
            raise ValueError("Valid mode value only in - ['f','c','fc']")
        return self.__builder.build()
