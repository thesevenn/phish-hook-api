from typing import Tuple
from app.types import Verdict

class Consts:
    CRITICAL = 20
    SEVERE = 15
    HIGH = 10
    MODERATE = 5
    LOW = 2

    # Score ranges for verdicts
    SCORE_CAP = 60
    SAFE_CAP = 5
    CAUTION_CAP = 11
    SUS_CAP = 19

    # Verdicts
    VERDICTS:Tuple[Verdict] = ("safe","caution","suspicious","critical")

