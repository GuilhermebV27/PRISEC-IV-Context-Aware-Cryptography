"""
security_fit.py

requirement = weighted sum of security_level/confidentiality/data_lifetime
security_fit(cipher) = capped offer-vs-requirement rule

See security-needs-profile.md for the full design rationale.
"""

PENALTY_FACTOR = 0.75

SECURITY_LEVEL_SCORE = {"Guest": 0.25, "Basic": 0.5, "Advanced": 0.75, "Admin": 1.0}
CONF_LIFETIME_SCORE = {"Low": 0.2, "Medium": 0.6, "High": 1.0,
                        "Short-term": 0.2, "Medium-term": 0.6, "Long-term": 1.0}

REQ_WEIGHTS = {"security_level": 0.4, "confidentiality": 0.4, "data_lifetime": 0.2}


def compute_requirement(security_level: str, data_confidentiality: str, data_lifetime: str) -> float:
    return (
        REQ_WEIGHTS["security_level"] * SECURITY_LEVEL_SCORE[security_level]
        + REQ_WEIGHTS["confidentiality"] * CONF_LIFETIME_SCORE[data_confidentiality]
        + REQ_WEIGHTS["data_lifetime"] * CONF_LIFETIME_SCORE[data_lifetime]
    )


def security_fit(cipher_entry, requirement: float) -> dict:
    offer = cipher_entry.security_strength
    if offer >= requirement:
        fit = min(offer, requirement)
    else:
        fit = offer * PENALTY_FACTOR
    return {"score": fit, "breakdown": {"security_strength": offer, "requirement": requirement}}
