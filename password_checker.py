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

def check_length(password):
    """Checks password length. Takes a password string and returns a Boolean and verdict tuple."""
    password_length = len(password)
    length_ok = password_length >= 15
    length_verdict = (
        "WEAK — does not meet minimum length requirements" if password_length <= 8
        else "MODERATE — meets minimum but falls short of NIST recommendations" if password_length <= 11
        else "GOOD — acceptable length for most systems" if password_length < 14
        else "STRONG — meets NIST SP 800-63B recommendations"
    )
    return length_ok, length_verdict


def check_digit(password):
    """Checks for a digit. Takes a password string and returns whether it contains one."""
    for character in password:
        if character.isdigit():
            return True
    return False


def check_username(password, username):
    """Checks username reuse. Takes password and username strings and returns whether they differ."""
    return password != username


def check_rotation(rotation_interval):
    """Checks rotation policy. Takes an interval integer and returns a Boolean and verdict tuple."""
    rotation_ok = rotation_interval <= 12
    rotation_verdict = (
        "WARNING — rotation interval exceeds recommended maximum of 12 months" if rotation_interval > 12
        else "ACCEPTABLE — rotation interval is within recommended range" if rotation_interval >= 6
        else "EXCELLENT — frequent rotation policy detected"
    )
    return rotation_ok, rotation_verdict


def print_audit_report(account, username, password_length, length_score, rotation_interval, rotation_count, length_verdict, has_digit, not_username, rotation_verdict, not_breached, overall_pass):
    """Print the formatted password-audit report."""
    print("===============================")
    print("    PASSWORD AUDIT REPORT")
    print("===============================")
    print("Account: " + account)
    print("Username: " + username)
    print("Password Length: " + str(password_length))
    print("Length Score: " + str(length_score))
    print("Rotation Interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr): " + str(rotation_count))
    print("--------------------------------")
    print("Length Verdict: " + length_verdict)
    print("Digit Found: YES" if has_digit else "Digit Found: NO")
    print("Username Match: NO" if not_username else "Username Match: CRITICAL — password must not match username.")
    print("Rotation Verdict: " + rotation_verdict)
    print("Breach Check: " + ("CRITICAL -- password found in known breach list" if not not_breached else "PASS -- password is not in known breach list"))
    print("--------------------------------")
    print("OVERALL: PASS  — password meets all checked criteria" if overall_pass else "OVERALL: FAIL — see findings above")
    print("================================")


def audit_password(account, username, password, rotation_interval):
    """Prints an audit report and returns passed, failed, and critical counters."""
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached_ok = check_breached(password)
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval
    overall_pass = length_ok and has_digit and not_username and rotation_ok and check_breached

    print_audit_report(
        account, username, password_length, length_score, rotation_interval,
        rotation_count, length_verdict, has_digit, not_username,
        rotation_verdict, not_breached_ok, overall_pass
    )
    return (1 if overall_pass else 0, 0 if overall_pass else 1, 1 if not not_username else 0, 1 if check_breached else 0)


if __name__ == '__main__':

    credentials = [
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    failed_accounts = []
    critical_accounts = []

    for credential in credentials:
        account = credential[0]
        username = credential[1]
        password = credential[2]
        rotation_interval = credential[3]

        total_pass, total_fail, critical_count, breach_count = audit_password(
            account,
            username,
            password,
            rotation_interval
        )

        if total_fail:
            failed_accounts.append(account)

        if critical_count or breach_count:
            critical_accounts.append(account)

    print("--------------------------------")
    print("SUMMARY")
    print("--------------------------------")

    print("Failed Accounts: " + str(len(failed_accounts)))
    print("Critical Accounts: " + str(len(critical_accounts)))

    print("Failed Account Names:")
    for account in failed_accounts:
        print("- " + account)

    print("Critical Account Names:")
    for account in critical_accounts:
        print("- " + account)

    print("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.")