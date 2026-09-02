batch_size = 3
count = 0
 #number of passwords that meet the criteria
total_pass = 0
#number of passwords that do not meet the criteria
total_fail = 0
#number of passwords that are critical (username matches password)
critical_count = 0

while count < batch_size:
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

    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

    not_username = password != username
    rotation_verdict = (
        "WARNING — rotation interval exceeds recommended maximum of 12 months" if rotation_interval > 12
        else "ACCEPTABLE — rotation interval is within recommended range" if 6 <= rotation_interval <= 12
        else "EXCELLENT — frequent rotation policy detected"
        #checks if the rotational interval is greater than 12 months, between 6 and 12 months, or less than 6 months
    )
    length_ok = password_length >= 15
    overall_pass = length_ok and has_digit and not_username


    #prints the password audit report with the account, username, password length, length score, rotational interval, rotations in 3 years, length verdict, digit found status, username match status, rotational verdict, and overall pass/fail status
    print("========================================")
    print("    PASSWORD AUDIT REPORT " + "1 of " + str(batch_size)) 
    print("========================================")
    print("Account: " + account)
    print("Username: " + username)
    print("Password Length: " + str(password_length))
    print("Length Score: " + str(length_score))
    print("Rotation Interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr): " + str(rotation_count))
    print("----------------------------------------")
    print("Length Verdict: " + length_verdict)
    print("Digit Found: YES" if has_digit == True else "Digit Found: NO")
    #checks if digit is found in the password and prints the appropriate message
    print("Username Match: NO" if not_username == True else "Username Match: CRITICAL — password must not match username.")
    #checks if the username matches the password and prints the appropriate message
    print("Rotation Verdict: " + rotation_verdict)
    print("----------------------------------------")
    print("OVERALL: PASS  — password meets all checked criteria" if overall_pass == True else "OVERALL: FAIL — see findings above")
    #prints the overall pass/fail status based on the criteria checked above
    print("========================================")
    print(" ")
    count = count + 1
    if overall_pass:
        total_pass += 1
    else:
        total_fail += 1
    if not_username == False:
        critical_count += 1
print("========================================")
print("    BATCH AUDIT SUMMARY")
print("========================================")
print("Passwords Audited: " + str(batch_size))
print("Passed: " + str(total_pass))
print("Failed: " + str(total_fail))
print("Critical Flags: " + str(critical_count))
print("-----------------------------------------")
print("NOTE: Input is still hardcoded -- file reading coming in week 8")
print("========================================")
