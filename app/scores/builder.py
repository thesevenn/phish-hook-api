from typing import List

from app.config.utils import Utils
from app.config.consts import Consts
from app.scores.threat import ThreatScore


class ThreatScoreBuilder:
    def __init__(self):
        self.__threat_sheet:List[ThreatScore] = []
        self.__score = 0

    def score(self):
        return self.__score

    def add_threat_score(self, threat_score: ThreatScore):
        if not isinstance(threat_score,ThreatScore):
            raise TypeError("Invalid ThreatScore instance")
        if threat_score.threat_score > 0:
            self.__threat_sheet.append(threat_score)

    def calculate_score(self):
        score = 0
        for threat_score in self.__threat_sheet:
            score += threat_score.to_dict()["score"]
        self.__score = score

    def remove_risk_scores(self):
        """
        Removes score from all risk score entries in threat_sheet
        Returns: Analysis ready to be sent

        """
    @staticmethod
    def calculate_score_verdict(score):
        score = min(score,Consts.SCORE_CAP)
        if score <= Consts.SAFE_CAP:
            mapped_score =  Utils.lerp(score,0,Consts.SAFE_CAP,0,30)
            verdict = Consts.VERDICTS[0]
        elif score <= Consts.CAUTION_CAP:
            mapped_score = Utils.lerp(score, Consts.SAFE_CAP,Consts.CAUTION_CAP,31,54)
            verdict = Consts.VERDICTS[1]
        elif score <= Consts.SUS_CAP:
            mapped_score = Utils.lerp(score, Consts.CAUTION_CAP,Consts.SUS_CAP,55,69)
            verdict = Consts.VERDICTS[2]
        else:
            mapped_score = Utils.lerp(score,Consts.SUS_CAP,Consts.SCORE_CAP,70,100)
            verdict = Consts.VERDICTS[3]

        return int(round(mapped_score,0)), verdict

    @staticmethod
    def calculate_confidence(score: int) -> float:
        """
        Directional confidence based on rule context.
        - High for clean emails (0–5)
        - Drops for low-score ambiguity (6–10)
        - Rises again as rules stack up (11–16)
        - High confidence in phishing for 17+
        """
        score = max(0, min(score, 60))  # Clamp to max

        if score <= 5:
            # Clean: Confidence decreases slightly from 0.98 to 0.8
            return round(0.8 + 0.18 * (1 - score / 5), 2)
        elif 6 <= score <= 10:
            # Caution zone: Uncertainty, lowest confidence
            return round(0.8 - 0.1 * ((score - 6) / 4), 2)  # down to 0.7
        elif 11 <= score <= 16:
            # Suspicious zone: more evidence = more confidence
            return round(0.7 + 0.08 * ((score - 11) / 5), 2)  # up to ~0.78
        else:
            # Critical phishing: confidence shoots up
            return round(0.78 + 0.2 * ((score - 17) / (60 - 17)), 2)  # up to 0.98

    @staticmethod
    def calculate_nudge_score(proba: float) -> int:
        if proba >= 0.9:
            return 10 # confident phishing
        elif proba >= 0.75:
            return 7  # strong phishing
        elif proba >= 0.6:
            return 3  # likely phishing
        elif proba >= 0.4:
            return 0  # uncertain - no nudge
        elif proba >= 0.25:
            return -5  # Likely clean
        else:
            return -7 # clean

    def add_classifier_score(self,entries:List):
        for entry in entries:
            nudge =  self.calculate_nudge_score(entry["proba"][0][1])
            self.__score += nudge
            self.__threat_sheet.append(
                ThreatScore(entry["type"],
                            nudge,
                            "",
                            "classifier",
                            [],
                            [entry["remarks"]]))



    def build(self):
        normalized_score, verdict = ThreatScoreBuilder.calculate_score_verdict(self.__score)
        return {
            "verdict":verdict,
            "score":normalized_score,
            "filters":[threat.to_dict() for threat in self.__threat_sheet],
            "confidence":ThreatScoreBuilder.calculate_confidence(self.__score),
            "critical":[]
        }