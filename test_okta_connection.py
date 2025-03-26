import os
import requests
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

OKTA_API_URL = os.getenv("OKTA_API_URL")
API_TOKEN = os.getenv("OKTA_API_TOKEN")

headers = {
    "Authorization": f"SSWS {API_TOKEN}",
    "Accept": "application/json"
}

def test_okta_users():
    url = f"{OKTA_API_URL}/api/v1/users"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("✅ Success! Connected to Okta API.")
        users = response.json()
        print(f"👥 Found {len(users)} user(s). Here's one:\n")
        print(users[0] if users else "No users found.")
    else:
        print(f"❌ Failed to connect. Status: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    test_okta_users()