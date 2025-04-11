from typing import Dict, List

class RiskScore:
    """
    RiskScore class provides blueprint for Standardized score to Rules( filter or ML ).
    Enforcing a standard across different rules and ml approach to return same score format
    """

    def __init__(self, risk_name:str, risk_score:int = 0, risk_factors:List[str] = None, risk_clue:str = None):
        if risk_factors is None:
            risk_factors = []
        self.__risk_name = risk_name
        self.__risk_score = risk_score
        self.__risk_factors = risk_factors
        self.__risk_clue = risk_clue

    @staticmethod
    def empty():
        return {}

    def to_dict(self):
        return {
            "risk":self.__risk_name,
            "score":self.__risk_score,
            "factors":self.__risk_factors,
            "clue":self.__parse_clue()
        }

    @staticmethod
    def extract_score(score_as_dict, threat_clues:List[Dict], threat_factors:List[Dict]):
        threat_clues.append({score_as_dict["risk"]:score_as_dict["clue"]})
        threat_factors.append({score_as_dict["risk"]:score_as_dict["factors"]})
        return score_as_dict["score"]


    def __parse_clue(self):
        if self.__risk_clue:
            return self.__risk_clue.format(",".join(self.__risk_factors))
        elif self.__risk_factors:
            return f"{self.__risk_name}(s): {','.join(self.__risk_factors)}"
        else: return ""

