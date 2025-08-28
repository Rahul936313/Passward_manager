# 🔐 Password Manager with Streamlit

A simple and secure **Password Manager** built with **Python** and **Streamlit**.  
This app allows you to **store, view, and delete passwords** safely using encryption.

---

## 🚀 Features
- Store account **email, website, and encrypted password**
- View saved credentials in a clean UI
- Delete saved credentials
- Secure encryption using a generated `secret.key`
- Passwords are stored locally (not uploaded to GitHub or cloud)
- `.gitignore` ensures sensitive files stay private

---

## 🛠️ Installation & Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/Rahul936313/password-manager.git
   cd password-manager

   
2. Create and activate a virtual environment (optional but recommended):

python -m venv venv
venv\Scripts\activate   # On Windows
source venv/bin/activate  # On Linux/Mac


3. Install dependencies:

pip install -r requirements.txt
(If you don’t have a requirements.txt, just install manually:)

pip install streamlit cryptography


4. Run the app:

streamlit run password_manager.py


password-manager/

│-- password_manager.py   # Main Streamlit app

│-- .gitignore            # Keeps sensitive files out of GitHub

│-- secret.key            # 🔒 Encryption key (ignored in Git)

│-- passwords.json        # 🔐 Stored encrypted passwords (ignored in Git)


⚠️ Security Notes

Keep your secret.key and passwords.json safe — without them, you can’t access your saved passwords.

These files are not uploaded to GitHub for your protection.

For extra safety, you can back them up in a secure location (e.g., encrypted drive).

✨ Future Improvements

Add a master password login

Export/import encrypted passwords

Password generator

Cloud sync (optional)
