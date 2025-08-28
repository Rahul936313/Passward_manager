import streamlit as st
import secrets
import re
import string
import os
import json
from cryptography.fernet import Fernet

# ========== Password Generator ==========
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(length))
    return password

# ========== Password Strength Checker ==========
def check_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[^\w]", password) is None  # Any non-word char

    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]

    if all(not e for e in errors):
        return "✅ Strong 💪"
    elif length_error or sum(errors) > 2:
        return "❌ Weak"
    else:
        return "⚡ Moderate"

# ========== Encryption Setup ==========
KEY_FILE = "secret.key"
DATA_FILE = "passwords.json"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_key()

# ========== Save / Load / Delete Passwords ==========
def save_password(site, username, password):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
    else:
        data = {}
    encrypted_pwd = fernet.encrypt(password.encode()).decode()
    if site not in data:
        data[site] = []
    data[site].append({"username": username, "password": encrypted_pwd})
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_passwords():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def decrypt_password(enc_pwd):
    return fernet.decrypt(enc_pwd.encode()).decode()

def delete_password(site, username):
    if not os.path.exists(DATA_FILE):
        return
    with open(DATA_FILE, "r") as f:
        data = json.load(f)
    if site in data:
        data[site] = [entry for entry in data[site] if entry["username"] != username]
        if not data[site]:
            del data[site]
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)

# ========== Streamlit UI ==========
st.title("🔐 Password Generator + Strength Checker + Manager")

st.warning(
    "⚠️ Passwords are securely encrypted and stored locally using Fernet, but anyone with access to both the `secret.key` and `passwords.json` files can decrypt them."
)

# Sidebar Options
st.sidebar.header("Options")
length = st.sidebar.slider("Password Length", 6, 32, 12)

# Password Generator
if st.button("Generate Password"):
    pwd = generate_password(length)
    st.success(f"Generated Password: `{pwd}`")
    st.write("Strength:", check_strength(pwd))

# Strength Checker
st.subheader("🔎 Check Your Own Password")
user_pwd = st.text_input("Enter a password:", type="password")
if user_pwd:
    st.write("Strength:", check_strength(user_pwd))

st.write("---")

# Password Manager
st.subheader("📂 Password Manager")

with st.form("save_form"):
    site = st.text_input("Website / App")
    username = st.text_input("Username / Email")
    pwd_to_save = st.text_input("Password", type="password")
    save_btn = st.form_submit_button("💾 Save Password")

    if save_btn and site and username and pwd_to_save:
        save_password(site, username, pwd_to_save)
        st.success("Password saved securely ✅")
        st.rerun()

st.write("### 🔍 Stored Passwords")
data = load_passwords()
if data:
    for site, entries in data.items():
        st.write(f"**{site}**")
        for idx, entry in enumerate(entries):
            decrypted_pwd = decrypt_password(entry['password'])
            with st.expander(f"👤 {entry['username']}"):
                st.code(decrypted_pwd, language="text")
                if st.button(f"🗑 Delete", key=f"del-{site}-{entry['username']}-{idx}"):
                    delete_password(site, entry['username'])
                    st.warning(f"Deleted entry for {site} ({entry['username']})")
                    st.rerun()
else:
    st.info("No passwords saved yet.")
