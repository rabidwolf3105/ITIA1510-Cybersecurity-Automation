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


def audit_password(account, username, password, rotation_interval):
    """Prints an audit report and returns passed, failed, and critical counters."""
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval
    overall_pass = length_ok and has_digit and not_username and rotation_ok

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
    print("--------------------------------")
    print("OVERALL: PASS  — password meets all checked criteria" if overall_pass else "OVERALL: FAIL — see findings above")
    print("================================")
    return (1 if overall_pass else 0, 0 if overall_pass else 1, 1 if not not_username else 0)


if __name__ == '__main__':  # Prevents prompts from running when tests import this module.
    account = input("Enter the account you are trying to log into: ")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    rotation_interval = int(input("Enter the rotational interval (in months): "))
    total_pass, total_fail, critical_count = audit_password(account, username, password, rotation_interval)
