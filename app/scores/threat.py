from typing import Dict, List, Optional

from app.types import Analysis

class ThreatScore:
    def __init__(self,
                 threat_name:str,
                 threat_score:int|None,
                 original_value:str,
                 analysis_type:Optional[Analysis],
                 threat_factors:List[Dict|List|str|None],
                 threat_clues:List[Dict[str,str]]):

            self.threat_name = threat_name
            self.threat_score = threat_score
            self.threat_factors = threat_factors
            self.analysis_type = analysis_type
            self.original_value = original_value
            self.threat_clues = threat_clues


    def to_dict(self):
        return {
            "name": self.threat_name,
            "preview": self.original_value[:150],
            "score": self.threat_score,
            "factors": self.threat_factors,
            "clues":self.threat_clues,
            "type": self.analysis_type
        }

    @classmethod
    def empty(cls):
        return cls("",0,"",None,[],[])

