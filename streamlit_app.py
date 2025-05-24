import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from dateutil.parser import parse as dtparse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError # Import HttpError for better error handling

# --- Configuration ---
# Your secrets are accessed correctly via st.secrets
SCOPES = ["https://www.googleapis.com/auth/calendar.events"]
CLIENT_ID     = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI  = st.secrets["google"]["redirect_uri"] # e.g. "https://your-app.streamlit.app/"

# --- OAuth Flow Setup ---
def get_flow():
    """Initializes and returns the Google OAuth Flow object."""
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=SCOPES,
    )
    flow.redirect_uri = REDIRECT_URI
    return flow

def creds_from_dict(data):
    """Converts a dictionary back into a Google OAuth Credentials object."""
    if not data:
        return None
    # Ensure all expected fields are present for Credentials object
    return Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        scopes=data.get("scopes"),
        # id_token might not always be present, so use .get()
        id_token=data.get("id_token")
    )

# --- Main Login Function ---
def login():
    """Handles the Google OAuth login process, including token refresh."""
    st.markdown("---") # Visual separator for logs
    print(f"--- login() function called at {dt.datetime.now()} ---")

    # 1. Check if user is already authenticated and tokens are valid
    if "creds" in st.session_state and st.session_state["creds"]:
        creds_dict = st.session_state["creds"]
        creds = creds_from_dict(creds_dict)

        # Check if credentials are valid (not expired or about to expire)
        if creds and creds.valid:
            print("Credentials found in session state and are valid.")
            return True
        elif creds and creds.expired and creds.refresh_token:
            # Token expired, try to refresh
            print("Credentials expired. Attempting to refresh token...")
            try:
                flow = get_flow()
                flow.credentials = creds # Attach the expired creds to the flow
                flow.refresh_credentials() # This attempts to use the refresh_token

                # Update session state with new token
                st.session_state["creds"] = {
                    "token": flow.credentials.token,
                    "refresh_token": flow.credentials.refresh_token, # Refresh token might also be updated
                    "token_uri": flow.credentials.token_uri,
                    "client_id": flow.credentials.client_id,
                    "client_secret": flow.credentials.client_secret,
                    "scopes": flow.credentials.scopes,
                    "id_token": flow.credentials.id_token,
                }
                st.success("Signed in! (Token refreshed)")
                print("Credentials refreshed successfully.")
                return True
            except Exception as e:
                # Refresh failed (e.g., refresh token revoked or expired)
                st.error(f"Failed to refresh token: {e}. Please sign in again.")
                print(f"ERROR: Failed to refresh token: {type(e).__name__}: {e}")
                if "creds" in st.session_state:
                    del st.session_state["creds"] # Clear invalid creds
                # Crucial: Clear query params to prevent re-using old 'code' if still in URL
                st.experimental_set_query_params()
                return False
        else:
            print("Credentials in session state are invalid or no refresh token. Forcing re-login.")
            if "creds" in st.session_state:
                del st.session_state["creds"] # Clear out any stale credentials

    # 2. Handle redirect from Google with authorization code
    query_params = st.query_params
    print(f"Current query_params: {query_params}")

    if "code" in query_params:
        auth_code = query_params["code"][0]
        print(f"Found 'code' in query_params. Attempting token exchange with code: {auth_code[:10]}...")

        try:
            flow = get_flow()
            # Debug: Print flow credentials before fetching token
            print("OAuth Client Configuration:", flow.client_config)

            # This is the line that previously caused InvalidGrantError
            flow.fetch_token(code=auth_code)

            # Store ALL necessary credential parts, including refresh_token
            st.session_state["creds"] = {
                "token": flow.credentials.token,
                "refresh_token": flow.credentials.refresh_token,
                "token_uri": flow.credentials.token_uri,
                "client_id": flow.credentials.client_id,
                "client_secret": flow.credentials.client_secret,
                "scopes": flow.credentials.scopes,
                "id_token": flow.credentials.id_token, # Include id_token if available/needed
            }
            st.success("Successfully signed in with Google!")
            print("Token fetched and credentials stored in session state.")

            # IMPORTANT: Clear the 'code' from the URL using Streamlit's API
            # This prevents the app from trying to reuse the same 'code' on refresh,
            # leading to 'Malformed auth code' errors.
            st.experimental_set_query_params()
            print("Query parameters cleared after successful login.")
            return True
        except Exception as e:
            print(f"ERROR: Exception during token fetch: {type(e).__name__}: {e}")
            st.error(f"Authentication failed: {type(e).__name__}: {e}. Please try again.")
            st.warning("Double-check your **Redirect URI** in Google Cloud Console matches exactly.")
            # Clear any potentially bad data or query params
            st.experimental_set_query_params() # Clear bad code from URL
            if "creds" in st.session_state:
                del st.session_state["creds"]
            return False
    else:
        # 3. If no code in URL and no valid creds, display login button
        print("No 'code' found in query_params and no valid credentials. Displaying login prompt.")
        flow = get_flow()
        if flow:
            auth_url, _ = flow.authorization_url(
                access_type="offline",          # Crucial to get a refresh token
                prompt="consent",               # Forces user to re-consent, ensures refresh token
                include_granted_scopes="true"
            )
            st.markdown(f"[**Sign in with Google**]({auth_url})", unsafe_allow_html=True)
        else:
            st.error("Cannot initialize Google login. Check client secrets.")
        return False

# ---------- PDF parser ----------
def parse_pdf(file_bytes):
    shifts = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        # Using a fallback for the year if Title is not available or doesn't contain a year
        year_match = re.search(r"(\d{4})", pdf.metadata.get("Title", ""))
        year = int(year_match.group(1)) if year_match else dt.datetime.now().year # Default to current year

        for page in pdf.pages:
            table = page.extract_table()
            if not table:
                print(f"No table found on page {page.page_number}")
                continue
            
            # Ensure table has enough rows/columns before creating DataFrame
            if len(table) < 2 or len(table[0]) == 0:
                print(f"Table on page {page.page_number} is malformed.")
                continue

            df = pd.DataFrame(table[1:], columns=table[0])

            if "Entrada" not in df.columns or "Sortida" not in df.columns:
                print(f"Missing 'Entrada' or 'Sortida' columns on page {page.page_number}")
                continue
            
            # Iterate through columns starting from the second one (assuming first is 'Entrada'/'Sortida' label)
            for col_name in df.columns[1:]:
                # Extract day number from the first row of the current column
                day_str = str(df.iloc[0][col_name]).strip()
                
                if not day_str.isdigit():
                    print(f"Skipping non-digit day string: '{day_str}' in column '{col_name}' on page {page.page_number}")
                    continue
                
                try:
                    # Attempt to create date object. Page number is assumed to be month.
                    # This might need adjustment if page number doesn't map directly to month.
                    date = dt.date(year, page.page_number, int(day_str))
                except ValueError as e:
                    print(f"Could not create date for day '{day_str}' on page {page.page_number} in year {year}: {e}")
                    continue

                # Ensure 'Entrada' and 'Sortida' rows exist for the current column
                start_rows = df.loc[df["Entrada"] == "Entrada"]
                end_rows = df.loc[df["Sortida"] == "Sortida"]

                if start_rows.empty or end_rows.empty:
                    print(f"Missing 'Entrada' or 'Sortida' rows for date {date} in column {col_name}")
                    continue

                start = str(start_rows[col_name].values[0]).strip()
                end   = str(end_rows[col_name].values[0]).strip()

                if re.fullmatch(r"\d{1,2}:\d{2}", start) and re.fullmatch(r"\d{1,2}:\d{2}", end):
                    key = f"{date:%Y%m%d}-{start.replace(':','')}"
                    shifts.append({"key": key, "date": date.isoformat(), "start": start, "end": end})
                else:
                    print(f"Skipping malformed time for {date}: Start='{start}', End='{end}'")
    return shifts


# ---------- Calendar sync ----------
def sync_shifts(creds, shifts, tz="Europe/Madrid"):
    service = build("calendar", "v3", credentials=creds, cache_discovery=False)
    now = dt.datetime.utcnow().isoformat() + "Z" # 'Z' indicates UTC time

    # Fetch existing events marked by this app
    existing_events = []
    page_token = None
    while True:
        try:
            events_result = service.events().list(
                calendarId="primary",
                timeMin=now,
                privateExtendedProperty="shiftUploader=1",
                pageToken=page_token
            ).execute()
            existing_events.extend(events_result.get("items", []))
            page_token = events_result.get('nextPageToken')
            if not page_token:
                break
        except HttpError as error:
            st.error(f"Error fetching existing calendar events: {error}")
            print(f"ERROR: Google Calendar API error fetching events: {error}")
            return 0, 0, 0 # Return zeros if fetching fails

    by_key = {e["extendedProperties"]["private"]["key"]: e for e in existing_events if "private" in e.get("extendedProperties", {}) and "key" in e["extendedProperties"]["private"]}

    inserts, updates, deletes = 0, 0, 0

    for s in shifts:
        # Construct ISO 8601 strings for event times
        # Handle cases where end time might be on the next day (e.g., 22:00-06:00)
        start_dt_obj = dt.datetime.fromisoformat(f"{s['date']}T{s['start']}")
        end_dt_obj = dt.datetime.fromisoformat(f"{s['date']}T{s['end']}")

        if end_dt_obj < start_dt_obj: # Shift crosses midnight
            end_dt_obj += dt.timedelta(days=1)

        start_iso = start_dt_obj.isoformat(timespec='seconds')
        end_iso   = end_dt_obj.isoformat(timespec='seconds')

        body = {
            "summary": f"P {s['start']}",
            "start": {"dateTime": start_iso, "timeZone": tz},
            "end":   {"dateTime": end_iso,   "timeZone": tz},
            "extendedProperties": {"private": {"shiftUploader": "1", "key": s["key"]}},
        }

        try:
            if s["key"] in by_key:
                ev_id = by_key[s["key"]]["id"]
                service.events().patch(calendarId="primary", eventId=ev_id, body=body).execute()
                updates += 1
                del by_key[s["key"]] # Mark as processed
            else:
                service.events().insert(calendarId="primary", body=body).execute()
                inserts += 1
        except HttpError as error:
            st.error(f"Error syncing event with key '{s['key']}': {error}")
            print(f"ERROR: Google Calendar API error syncing event: {error}")
            # Continue processing other shifts even if one fails

    # Delete remaining events in by_key (those not found in the new shifts)
    for ev in by_key.values():
        try:
            service.events().delete(calendarId="primary", eventId=ev["id"]).execute()
            deletes += 1
        except HttpError as error:
            st.error(f"Error deleting event with ID '{ev['id']}': {error}")
            print(f"ERROR: Google Calendar API error deleting event: {error}")

    return inserts, updates, deletes

# ---------- Streamlit UI ----------
st.set_page_config(page_title="Shift Uploader", page_icon="🗓️", layout="centered")
st.title("📤 Shift → Google Calendar")

# Initialize session state for 'creds' if it doesn't exist
if "creds" not in st.session_state:
    st.session_state["creds"] = None

# Attempt to log in or display login prompt
if login():
    # If login() returns True, it means we have valid credentials
    creds = creds_from_dict(st.session_state["creds"])
    # The success message is now handled within the login() function for clarity
    # st.success("Signed in!") # Removed as it's now internal to login() success paths

    st.write("---") # Separator for logged-in content

    file = st.file_uploader("Upload your PDF schedule", type="pdf")
    if file:
        with st.spinner("Reading PDF..."):
            shifts = parse_pdf(file.read())
        if not shifts:
            st.error("No shifts found. Check if ENTRADA/SORTIDA columns are correctly labeled or if PDF format changed.")
        else:
            st.info(f"Found **{len(shifts)}** shifts. Preview:")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True)
            if st.button("Sync to Google Calendar"):
                with st.spinner("Syncing..."):
                    try:
                        ins, upd, dele = sync_shifts(creds, shifts)
                        st.success(f"✅ Inserted: {ins}, Updated: {upd}, Deleted: {dele}")
                        st.balloons() # Visual celebration!
                    except Exception as e:
                        st.error(f"An unexpected error occurred during sync: {e}")
                        print(f"ERROR: Unexpected error during sync: {e}")
else:
    # If login() returns False, it means the login process is not complete
    # The login() function itself will display the "Sign in with Google" button
    st.info("Please sign in with Google to upload your shifts.")
