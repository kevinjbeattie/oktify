# Oktify

Oktify is a Python-based CLI tool for tracking and exporting user-related changes from the Okta API. It helps IT administrators, security analysts, and support engineers audit changes in user roles, group memberships, app assignments, and user lifecycle status over a given time period.

---

## 🔧 Features
- **Role Changes:** Track changes in user role IDs.
- **User Lifecycle:** Track user account creations, suspensions, and deprovisioning.
- **Group Membership:** Detect when users are added to or removed from groups.
- **App Assignments:** Track when apps are assigned or revoked from users.
- **Output:** Export results to timestamped CSV files.
- **Bonus:** Optional `--show` flag to also print to the terminal.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Create a `.env` file with your Okta credentials:
```dotenv
OKTA_DOMAIN=https://your-okta-domain.okta.com
OKTA_API_TOKEN=your_api_token_here
```

### 3. Run the CLI tool using Python
```bash
python run.py roles --start 2024-01-01 --end 2024-12-31 --show
python run.py users --start 2024-01-01 --end 2024-12-31 --output users.csv
python run.py groups --start 2024-01-01 --end 2024-12-31
python run.py apps --start 2024-01-01 --end 2024-12-31 --show
```

### 4. (Optional) Install Oktify as a CLI
```bash
pip install -e .
```
This allows you to run the tool using the `oktify` command:
```bash
oktify roles --start 2024-01-01 --end 2024-12-31 --show
```

---

## 🧪 Run Tests
```bash
python -m unittest discover tests
```

---

## 📁 File Structure
```txt
oktify/
├── okta_utils.py          # All API logic and event parsers
├── run.py                 # CLI entrypoint using argparse + subcommands
├── requirements.txt       # Dependencies
├── .env                   # Okta credentials (ignored)
├── tests/                 # Unit tests for all subcommands
│   ├── test_user_lifecycle.py
│   ├── test_group_changes.py
│   └── test_app_assignments.py
├── LICENSE                # MIT License
├── setup.py               # CLI packaging config
├── README.md              # You're here!
└── docs/                  # (Optional) Extended usage examples
```

---

## ✅ Requirements
- Python 3.8+
- Okta API Token
- Developer account with access to Okta API

---

## 📄 License
MIT (you may reuse/extend freely with attribution)

---

## 💡 Author
Kevin J. Beattie  
https://kevinbeattie.com