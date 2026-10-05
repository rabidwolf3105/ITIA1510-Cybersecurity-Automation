policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}

# Policy is outside main so all functions and tests can use the same rules.
# This keeps the policy available when the module is imported for testing.

def known_breached():
    return ("password", 
            "password123", 
            "123456", 
            "qwerty", 
            "letmein", 
            "welcome", 
            "monkey", 
            "dragon", 
            "master", 
            "sunshine"
            )

def check_breached(password):
    return password not in known_breached()

def check_length(password, policy):
    #Checks password length. Takes a password string and returns a Boolean and verdict tuple.
    password_length = len(password)

    if password_length < policy["min_length"]:
        length_verdict = "CRITICAL -- below minimum length"
        length_ok = False
    elif password_length >= policy["strong_length"]:
        length_verdict = "STRONG -- meets NIST recommendations"
        length_ok = True
    else:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
        length_ok = True

    return length_ok, length_verdict


def check_digit(password):
    #Checks for a digit. Takes a password string and returns whether it contains one.
    for character in password:
        if character.isdigit():
            return True
    return False


def check_username(password, username):
    #Checks username reuse. Takes password and username strings and returns whether they differ.
    return password != username


def check_rotation(rotation_interval, policy):
    #Checks rotation policy. Takes an interval integer and returns a Boolean and verdict tuple.

    if rotation_interval > policy["max_rotation_months"]:
        rotation_ok = False
        rotation_verdict = "CRITICAL -- rotation interval exceeds maximum"
    elif rotation_interval <= policy["good_rotation_months"]:
        rotation_ok = True
        rotation_verdict = "GOOD -- rotation interval is within recommended range"
    else:
        rotation_ok = True
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"

    return rotation_ok, rotation_verdict


def print_audit_report(account, username, password_length, length_score, rotation_interval, rotation_count, length_verdict, has_digit, not_username, rotation_verdict, not_breached, overall_pass):
    #Print the formatted password-audit report.
    print("===============================")
    print("    PASSWORD AUDIT REPORT")
    print("===============================")
    print("Account: " + account)
    print("Username: " + username)
    print("Password Length: " + str(password_length) + " characters")
    print("Length Score: " + str(length_score) + " points")
    print("Rotation Interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr): " + str(rotation_count))
    print("--------------------------------")
    print("Length Verdict: " + length_verdict)
    print("Digit Found: YES" if has_digit else "Digit Found: NO")
    print(
        "Username Match: NO" 
        if not_username 
        else "Username Match: CRITICAL — password must not match username.")
    print("Breach Check: " + ("CRITICAL -- password found in known breach list" if not not_breached else "PASS -- password is not in known breach list"))
    print("Rotation Verdict: " + rotation_verdict)
    print("--------------------------------")
    print("OVERALL: PASS  — password meets all checked criteria" if overall_pass else "OVERALL: FAIL — see findings above")
    print("================================")


def audit_password(account, username, password, rotation_interval, known_breached, policy):
    #Prints an audit report and returns passed, failed, and critical counters.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    # The breach function must be called with the password being checked.
    not_breached_ok = password not in known_breached()
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Reading the limits from policy avoids repeating magic numbers in functions.
    overall_pass = (
        length_ok
        and has_digit
        and not_username
        and rotation_ok
        and not_breached_ok
    )

    critical = (
        (not length_ok and password_length < policy["min_length"])
        or (not rotation_ok and rotation_interval > policy["max_rotation_months"])
        or (not not_username)
        or (not not_breached_ok)
    )

    print_audit_report(
        account,
        username,
        password_length,
        length_score,
        rotation_interval,
        rotation_count,
        length_verdict,
        has_digit,
        not_username,
        rotation_verdict,
        not_breached_ok,
        overall_pass
    )

    return (
        1 if overall_pass else 0,
        0 if overall_pass else 1,
        1 if critical else 0
    )

if __name__ == '__main__':

    credentials = [
    {"account": "Gmail", "username": "jsmith", "password": "password123", "rotation_interval": 12},
    {"account": "SSH Server", "username": "jsmith", "password": "jsmith", "rotation_interval": 24},
    {"account": "VPN", "username": "jsmith", "password": "Tr0ub4dor&3correct", "rotation_interval": 3},
    {"account": "Company Email", "username": "jsmith", "password": "summer2024!", "rotation_interval": 6},
    {"account": "GitHub", "username": "jsmith", "password": "Blue-Harbor-72-Lantern", "rotation_interval": 6},
    ]

    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    for cred in credentials:
        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy
        )

        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])

        if critical:
            summary["critical_accounts"].append(cred["account"])

    print()
    print("========================================")
    print("       BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(summary.get("total", 0)))
    print("Passed:              " + str(summary.get("passed", 0)))
    print("Failed:              " + str(summary.get("failed", 0)))
    print("----------------------------------------")

    print(
        "Failed accounts:     "
        + ", ".join(summary.get("failed_accounts", []))
    )

    print("Critical flags:      " + str(summary.get("critical", 0)))

    print(
        "Critical accounts:   "
        + ", ".join(summary.get("critical_accounts", []))
    )

    print("----------------------------------------")
    print("NOTE: Credentials and breach list are hardcoded -- file reading coming in Week 07.")
    print("========================================")