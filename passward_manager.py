import streamlit as st
import secrets
import re
import string
import json
from cryptography.fernet import Fernet

# ================= Session Password Storage =================
if "session_passwords" not in st.session_state:
    st.session_state.session_passwords = {}  # key = site, value = list of {username, password}

# Rerun flag to safely refresh after form submission
if "refresh" not in st.session_state:
    st.session_state.refresh = False

if st.session_state.refresh:
    st.session_state.refresh = False
    st.experimental_rerun()

# ================= Password Generator =================
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

# ================= Password Strength Checker =================
def check_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[^\w]", password) is None

    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]

    if all(not e for e in errors):
        return "✅ Strong 💪"
    elif length_error or sum(errors) > 2:
        return "❌ Weak"
    else:
        return "⚡ Moderate"

# ================= Encryption (Session-Only) =================
session_key = Fernet.generate_key()
fernet = Fernet(session_key)

# ================= Save / Delete Passwords =================
def save_password(site, username, password):
    encrypted_pwd = fernet.encrypt(password.encode()).decode()
    if site not in st.session_state.session_passwords:
        st.session_state.session_passwords[site] = []
    st.session_state.session_passwords[site].append({"username": username, "password": encrypted_pwd})

def delete_password(site, username):
    if site in st.session_state.session_passwords:
        st.session_state.session_passwords[site] = [
            entry for entry in st.session_state.session_passwords[site] if entry["username"] != username
        ]
        if not st.session_state.session_passwords[site]:
            del st.session_state.session_passwords[site]

def decrypt_password(enc_pwd):
    return fernet.decrypt(enc_pwd.encode()).decode()

# ================= Streamlit UI =================
st.title("🔐 Password Generator + Strength Checker + Manager")

st.warning(
    "⚠️ Passwords are encrypted locally in your session. "
    "They are not stored on the server and disappear when the session ends."
)

# Sidebar: Password length
st.sidebar.header("Options")
length = st.sidebar.slider("Password Length", 6, 32, 12)

# Password Generator
if st.button("Generate Password"):
    pwd = generate_password(length)
    st.success(f"Generated Password: `{pwd}`")
    st.write("Strength:", check_strength(pwd))

# Password Strength Checker
st.subheader("🔎 Check Your Own Password")
user_pwd = st.text_input("Enter a password:", type="password")
if user_pwd:
    st.write("Strength:", check_strength(user_pwd))

st.write("---")

# Password Manager
st.subheader("📂 Saved Passwords")

# Save new password form
with st.form("save_form"):
    site = st.text_input("Website / App")
    username = st.text_input("Username / Email")
    pwd_to_save = st.text_input("Password", type="password")
    save_btn = st.form_submit_button("💾 Save Password")

    if save_btn and site and username and pwd_to_save:
        save_password(site, username, pwd_to_save)
        st.success("Password saved securely in your session ✅")
        st.session_state.refresh = True  # safely refresh after form

# Show stored passwords
if st.session_state.session_passwords:
    for site, entries in st.session_state.session_passwords.items():
        st.write(f"**{site}**")
        for idx, entry in enumerate(entries):
            decrypted_pwd = decrypt_password(entry['password'])
            with st.expander(f"👤 {entry['username']}"):
                st.text_input("🔑 Password", decrypted_pwd, key=f"pwd-{site}-{entry['username']}-{idx}")
                if st.button(f"🗑 Delete", key=f"del-{site}-{entry['username']}-{idx}"):
                    delete_password(site, entry['username'])
                    st.warning(f"Deleted entry for {site} ({entry['username']})")
                    st.session_state.refresh = True  # safely refresh after delete

    # Download button for user passwords
    st.download_button(
        label="💾 Download My Passwords",
        data=json.dumps(st.session_state.session_passwords, indent=4),
        file_name="my_passwords.json",
        mime="application/json"
    )
else:
    st.info("No passwords saved in this session yet.")
