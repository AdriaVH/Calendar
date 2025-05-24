# Shift Uploader

Upload your roster PDF → keep Google Calendar in-sync.

## 1. Create a Google Cloud project
1. Enable **Calendar API**.
2. Add an **OAuth 2.0 Client (Web)**  
   - Authorised redirect URI: `https://<your-app>.streamlit.app/`  
3. Copy *Client ID* & *Client Secret*.

## 2. Deploy on Streamlit Community Cloud
1. Fork this repo to GitHub.
2. Go to https://streamlit.io/cloud → *“New app”* → pick the repo.
3. In **Secrets** add:

```toml
[google]
client_id = "YOUR_CLIENT_ID"
client_secret = "YOUR_CLIENT_SECRET"
redirect_uri = "https://<your-app>.streamlit.app/"
