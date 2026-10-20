import json

def save_summary(summary, filepath):
    with open(filepath, "w") as file:
        json.dump(summary, file, indent=2)

def load_summary(filepath):
    with open(filepath, "r") as file:
        return json.load(file)

policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def load_credentials(filepath):
    """Read credentials and return a list of dictionaries."""
    credentials = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0].strip(),
                "username": fields[1].strip(),
                "password": fields[2].strip(),
                "rotation_interval": int(fields[3].strip())
            })

    return credentials


def load_breached(filepath):
    """Read the breached password file and return a list of passwords."""
    known_breached = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            if line != "":
                known_breached.append(line)

    return known_breached


def check_breach(password, known_breached):
    """Return True if the password is not in the breach list."""
    return password not in known_breached


def check_length(password, policy):
    """Check password length and return a Boolean and verdict."""
    password_length = len(password)

    if password_length < policy["min_length"]:
        length_verdict = "CRITICAL -- below minimum length"
        length_ok = False
    elif password_length >= policy["strong_length"]:
        length_verdict = "STRONG -- meets NIST recommendations"
        length_ok = True
    else:
        length_verdict = (
            "MODERATE -- meets minimum but falls short of "
            "NIST recommendations"
        )
        length_ok = True

    return length_ok, length_verdict


def check_digit(password):
    """Return True if the password contains a digit."""
    for character in password:
        if character.isdigit():
            return True

    return False


def check_username(password, username):
    """Return True if the password differs from the username."""
    return password != username


def check_rotation(rotation_interval, policy):
    """Check the rotation interval and return a Boolean and verdict."""

    if rotation_interval <= 0:
        return False, "CRITICAL -- rotation interval must be positive"

    if rotation_interval > policy["max_rotation_months"]:
        rotation_ok = False
        rotation_verdict = (
            "CRITICAL -- rotation interval exceeds maximum"
        )
    elif rotation_interval <= policy["good_rotation_months"]:
        rotation_ok = True
        rotation_verdict = (
            "GOOD -- rotation interval is within recommended range"
        )
    else:
        rotation_ok = True
        rotation_verdict = (
            "ACCEPTABLE -- rotation interval within recommended range"
        )

    return rotation_ok, rotation_verdict


def print_audit_report(
    account, username, password_length, length_score,
    rotation_interval, rotation_count, length_verdict,
    has_digit, not_username, rotation_verdict,
    not_breached, overall_pass, report_lines
):
    """Add the formatted password-audit report to report_lines."""

    report_lines.append("===============================")
    report_lines.append("    PASSWORD AUDIT REPORT")
    report_lines.append("===============================")
    report_lines.append("Account: " + account)
    report_lines.append("Username: " + username)
    report_lines.append(
        "Password Length: " + str(password_length) + " characters"
    )
    report_lines.append("Length Score: " + str(length_score) + " points")
    report_lines.append(
        "Rotation Interval: " + str(rotation_interval) + " months"
    )
    report_lines.append("Rotations (3 yr): " + str(rotation_count))
    report_lines.append("--------------------------------")
    report_lines.append("Length Verdict: " + length_verdict)
    report_lines.append(
        "Digit Found: YES" if has_digit else "Digit Found: NO"
    )
    report_lines.append(
        "Username Match: NO"
        if not_username
        else "Username Match: CRITICAL -- password must not match username"
    )
    report_lines.append(
        "Breach Check: "
        + (
            "PASS -- password is not in known breach list"
            if not_breached
            else "CRITICAL -- password found in known breach list"
        )
    )
    report_lines.append("Rotation Verdict: " + rotation_verdict)
    report_lines.append("--------------------------------")
    report_lines.append(
        "OVERALL: PASS -- password meets all checked criteria"
        if overall_pass
        else "OVERALL: FAIL -- see findings above"
    )
    report_lines.append("================================")


def audit_password(
    account, username, password, rotation_interval,
    known_breached, policy, report_lines
):
    """Build an audit report and return passed, failed, and critical counters."""

    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(
        rotation_interval, policy
    )

    # Check if the password is in the known breach list, if that check is enabled in the policy.
    if policy["check_breach_list"]:
        not_breached_ok = check_breach(password, known_breached)
    else:
        not_breached_ok = True

    password_length = len(password)
    length_score = password_length * 10

    if rotation_interval > 0:
        rotation_count = 36 // rotation_interval
    else:
        rotation_count = 0

    digit_ok = has_digit or not policy["require_digit"]

    overall_pass = (
        length_ok
        and digit_ok
        and not_username
        and rotation_ok
        and not_breached_ok
    )

    critical = (
        (not length_ok and password_length < policy["min_length"])
        or rotation_interval <= 0
        or (
            not rotation_ok
            and rotation_interval > policy["max_rotation_months"]
        )
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
        overall_pass,
        report_lines
    )

    return (
        1 if overall_pass else 0,
        0 if overall_pass else 1,
        1 if critical else 0
    )




if __name__ == "__main__":
    import os

    # Find the folder containing this Python script.
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Load the input files.
    credentials_path = os.path.join(base_dir, "credentials.txt")
    breached_path = os.path.join(base_dir, "breached.txt")

    credentials = load_credentials(credentials_path)
    known_breached = load_breached(breached_path)

    # Create the list that stores the report.
    report_lines = []

    print("DEBUG - Credentials loaded:", len(credentials))
    print("DEBUG - Credentials:", credentials)

    # Initialize the batch summary counters.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # Audit each credential and collect its report.
    for cred in credentials:
        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            report_lines
        )

        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])

        if critical:
            summary["critical_accounts"].append(cred["account"])

    # Add the batch summary to the same report.
    report_lines.append("")
    report_lines.append("========================================")
    report_lines.append("       BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append(
        "Credentials audited: " + str(summary["total"])
    )
    report_lines.append("Passed:              " + str(summary["passed"]))
    report_lines.append("Failed:              " + str(summary["failed"]))
    report_lines.append("----------------------------------------")
    report_lines.append(
        "Failed accounts:     " + ", ".join(summary["failed_accounts"])
    )
    report_lines.append(
        "Critical flags:      " + str(summary["critical"])
    )
    report_lines.append(
        "Critical accounts:   " + ", ".join(summary["critical_accounts"])
    )
    report_lines.append("========================================")

    # Print and save the same report lines.
    for line in report_lines:
        print(line)

    # Save the report in the same folder as this script.
    write_report(report_lines, os.path.join(base_dir, "report.txt"))
    save_summary(summary, "audit_summary.json")