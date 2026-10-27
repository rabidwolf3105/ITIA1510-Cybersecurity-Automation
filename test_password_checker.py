import os
import tempfile

from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    load_summary,
    save_summary,
    write_report,
    policy,
    load_history,
    add_to_history,
    save_history,
)

known_breached = load_breached("breached.txt")


# check_length tests
length_ok, _ = check_length("abcd", policy)
assert length_ok == False
print("PASS: check_length correctly rejected 4-character password")

length_ok, _ = check_length("abcdefghijklmnop", policy)
assert length_ok == True
print("PASS: check_length correctly accepted 16-character password")


# check_digit tests
assert check_digit("password") == False
print("PASS: check_digit correctly rejected password with no digits")

assert check_digit("password1") == True
print("PASS: check_digit correctly accepted password with a digit")


# check_username tests
assert check_username("john", "john") == False
print("PASS: check_username correctly rejected password matching username")

assert check_username("password", "john") == True
print("PASS: check_username correctly accepted password different from username")


# check_breach tests
assert check_breach("password", known_breached) == False
print("PASS: check_breach correctly rejected known breached password")

assert check_breach("mysecretpassword", known_breached) == True
print("PASS: check_breach correctly accepted unique password")


# check_rotation tests
rotation_ok, _ = check_rotation(18, policy)
assert rotation_ok == False
print("PASS: check_rotation correctly rejected 18-month interval")

rotation_ok, _ = check_rotation(6, policy)
assert rotation_ok == True
print("PASS: check_rotation correctly accepted 6-month interval")


# policy tests
assert policy["strong_length"] == 15
print("PASS: policy strong_length is 15")

assert "require_digit" in policy
print("PASS: policy contains require_digit")


# load_credentials tests
credentials = load_credentials("credentials.txt")

assert isinstance(credentials, list)
print("PASS: load_credentials returns a list")

assert "account" in credentials[0]
print("PASS: first credential contains an account key")


# load_breached tests
breached = load_breached("breached.txt")

assert isinstance(breached, list)
print("PASS: load_breached returns a list")

assert "password123" in breached
print("PASS: load_breached contains password123")


# write_report test
test_lines = ["First report line", "Second report line"]

write_report(test_lines, "test_report.txt")

with open("test_report.txt", "r") as f:
    report_text = f.read()

assert report_text == "First report line\nSecond report line\n"
print("PASS: write_report correctly wrote both lines")


# Test 1: Saved summary matches the original dictionary
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"]
}

save_summary(sample, "test_summary.json")
assert load_summary("test_summary.json") == sample
print("PASS: save_summary and load_summary gave back the same dictionary")


# Test 2: failed_accounts is a list, not a string
loaded = load_summary("test_summary.json")
assert isinstance(loaded["failed_accounts"], list)
print("PASS: failed_accounts is a list")


# Test 3: No passwords appear in the saved summary
with open("credentials.txt", "r") as file:
    credentials_text = file.read()

with open("test_summary.json", "r") as file:
    saved_text = file.read()

# Check each password from credentials.txt
for line in credentials_text.splitlines():
    parts = line.strip().split(":")
    if len(parts) >= 2:
        password = parts[1].strip()
        if password:
            assert password not in saved_text

print("PASS: No passwords appear in the saved summary")


# History Test 1: Missing file returns an empty list
with tempfile.TemporaryDirectory() as temp_dir:
    missing_path = os.path.join(temp_dir, "missing_history.json")
    assert load_history(missing_path) == []

print("PASS: load_history returns an empty list for a missing file")


# History Test 2: First run number is 1
sample_history_summary = {
    "passed": 2,
    "failed": 3,
    "critical_accounts": ["Gmail", "SSH Server"]
}

history = add_to_history([], sample_history_summary, 3)

assert history[0]["run"] == 1
assert history[0]["passed"] == 2
assert history[0]["failed"] == 3
assert history[0]["critical_accounts"] == ["Gmail", "SSH Server"]

print("PASS: add_to_history creates the first run correctly")


# History Test 3: Only the newest runs are kept
history = []
history = add_to_history(history, sample_history_summary, 3)
history = add_to_history(history, sample_history_summary, 3)
history = add_to_history(history, sample_history_summary, 2)

assert [entry["run"] for entry in history] == [2, 3]

print("PASS: add_to_history keeps the newest runs")


# History Test 4: Saved history matches the original
with tempfile.TemporaryDirectory() as temp_dir:
    history_path = os.path.join(temp_dir, "audit_history.json")

    save_history(history, history_path)
    loaded_history = load_history(history_path)

    assert loaded_history == history

print("PASS: save_history and load_history preserve history")