"""Decision Agent -- maps a flagged event to the CIA pillar it threatens."""


class DecisionAgent:
    def classify(self, category, reason, message):
        if category == "availability":
            pillar, inject = "availability", False
        elif category in ("confidentiality", "integrity"):
            pillar, inject = category, True
        else:                              # anomaly (count threshold)
            pillar, inject = "confidentiality", True
        return {"pillar": pillar, "reason": reason, "inject_honeydata": inject}
