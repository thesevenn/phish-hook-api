from typing import Literal

from app.parser import EmailParser
from app.filters import filters
from app.classifier import classifier
from app.scores.builder import ThreatScoreBuilder

class Orchestrator:
    def __init__(self, raw_data:bytes ):
        self.__features = EmailParser(raw_data).features
        self.__builder = ThreatScoreBuilder()

    def orchestrate(self, mode:Literal["f","c","fc"] = "fc"):
        runner = filters.RuleFilters(self.__features, self.__builder)
        runner.runner()
        self.__builder.calculate_score()
        score = self.__builder.score()
        if score and 5 < score < 20:
            run = classifier.Classifier(self.__features)
            result = run.classify()
            self.__builder.add_classifier_score(result)
        return self.__builder.build()


