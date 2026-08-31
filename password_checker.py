account = input("Enter the account you are trying to log into: ")
username = input("Enter your username: ")
password = input("Enter your password: ")
rotation_interval = int(input("Enter the rotational interval (in months): "))
password_length = len(password)
length_score = password_length * 10
rotation_count = 36 // rotation_interval
length_verdict = (
    "WEAK — does not meet minimum length requirements" if password_length <= 8
    else "MODERATE — meets minimum but falls short of NIST recommendations" if 8 < password_length <= 11
    else "GOOD — acceptable length for most systems" if 12 <= password_length < 14
    else "STRONG — meets NIST SP 800-63B recommendations"
    #checks if the password length is less than or equal to 8, between 9 and 11, between 12 and 13, or greater than or equal to 14
)
has_digit = '0' in password or '1' in password or '2' in password or '3' in password or '4' in password or '5' in password or '6' in password or '7' in password or '8' in password or '9' in password
not_username = password != username
rotational_verdict = (
    "WARNING — rotation interval exceeds recommended maximum of 12 months" if rotation_interval > 12
    else "ACCEPTABLE — rotation interval is within recommended range" if 6 <= rotation_interval <= 12
    else "EXCELLENT — frequent rotation policy detected"
    #checks if the rotational interval is greater than 12 months, between 6 and 12 months, or less than 6 months
)
length_ok = password_length >= 15
overall_pass = length_ok and has_digit and not_username

#prints the password audit report with the account, username, password length, length score, rotational interval, rotations in 3 years, length verdict, digit found status, username match status, rotational verdict, and overall pass/fail status
print("===============================")
print("    PASSWORD AUDIT REPORT")
print("===============================")
print("Account: " + account)
print("Username: " + username)
print("Password Length: " + str(password_length))
print("Length Score: " + str(length_score))
print("Rotational Interval: " + str(rotation_interval) + " months")
print("Rotations (3 yr): " + str(rotation_count))
print("--------------------------------")
print("Length Verdict: " + length_verdict)
print("Digit Found: YES" if has_digit == True else "Digit Found: NO")
#checks if digit is found in the password and prints the appropriate message
print("Username Match: NO" if not_username == True else "Username Match: CRITICAL — password must not match username.")
#checks if the username matches the password and prints the appropriate message
print("Rotational Verdict: " + rotational_verdict)
print("--------------------------------")
print("OVERALL: PASS  — password meets all checked criteria" if overall_pass == True else "OVERALL: FAIL — see findings above")
#prints the overall pass/fail status based on the criteria checked above
print("================================")