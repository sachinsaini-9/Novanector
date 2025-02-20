import re

def check_password_strength(password):
    strength = 0
    
    # Check length
    if len(password) >= 8:
        strength += 1
    if len(password) >= 12:
        strength += 1

    # Check character types
    if re.search(r"[A-Z]", password):  # Uppercase
        strength += 1
    if re.search(r"[a-z]", password):  # Lowercase 
        strength += 1
    if re.search(r"[0-9]", password):  # Digit
        strength += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Special character
        strength += 1

    # Determine password strength
    if strength <= 2:
        return "Weak Password! ❌ Use at least 8 characters, including letters, numbers, and symbols."
    elif 3 <= strength <= 4:
        return "Medium Password! ⚠️ Consider adding more characters & special symbols."
    else:
        return "Strong Password! ✅ Your password is secure."

# Test cases
password = input("Enter your password: ")
print(check_password_strength(password))