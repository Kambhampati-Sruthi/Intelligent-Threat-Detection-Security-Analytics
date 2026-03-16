def predict_attack(failed_logins):

    if failed_logins > 6:
        return "HIGH RISK ATTACK"

    if failed_logins > 3:
        return "SUSPICIOUS"

    return "NORMAL"