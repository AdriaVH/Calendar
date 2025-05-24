import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from dateutil.parser import parse as dtparse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError # Import HttpError for better API error handling
import traceback # To print full tracebacks in logs

# --- Configuration (Read from Streamlit Secrets) ---
# IMPORTANT: Ensure your .streamlit/secrets.toml looks like this:
# [google]
# client_id = "YOUR_GOOGLE_CLIENT_ID"
# client_secret = "YOUR_GOOGLE_CLIENT_SECRET"
# redirect_uri = "https://makecalendar.streamlit.app" # NO TRAILING SLASH HERE, unless you want it

SCOPES = [
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar", # Add full calendar access just in case, can narrow later
    "openid", # Often useful for basic user info
    "https://www.googleapis.com/auth/userinfo.email" # To get user's email if needed
]

# Access secrets
CLIENT_ID     = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI  = st.secrets["google"]["redirect_uri"]

# Print configuration details to Streamlit Cloud logs for debugging
print(f"\n--- App Initialization ({dt.datetime.now()}) ---")
print(f"DEBUG: Configured CLIENT_ID: {CLIENT_ID}")
print(f"DEBUG: Configured REDIRECT_URI: {REDIRECT_URI}")
print(f"DEBUG: Configured SCOPES: {SCOPES}")


# --- OAuth Flow Setup Functions ---

def get_flow():
    """Initializes and returns the Google OAuth Flow object."""
    print(f"DEBUG: get_flow() called. Setting redirect_uri to: {REDIRECT_URI}")
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI], # This is the redirect URI sent during initial authorization
            }
        },
        scopes=SCOPES,
    )
    flow.redirect_uri = REDIRECT_URI # This sets the redirect URI for the token exchange
    print(f"DEBUG: Flow object created. flow.redirect_uri: {flow.redirect_uri}")
    return flow

def creds_from_dict(data):
    """Converts a dictionary back into a Google OAuth Credentials object."""
    if not data:
        print("DEBUG: creds_from_dict received empty data.")
        return None
    # Ensure all expected fields are present for Credentials object constructor
    creds = Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        scopes=data.get("scopes"),
        id_token=data.get("id_token") # Include id_token if available/needed
    )
    print(f"DEBUG: Credentials object created. Valid: {creds.valid}, Expired: {creds.expired}, Refreshable: {bool(creds.refresh_token)}")
    return creds

# --- Main Login Function ---
def login():
    """
    Handles the Google OAuth login process, including initial authentication,
    token exchange, and refresh token handling.
    """
    st.markdown("---") # Visual separator for logs
    print(f"\n--- login() function called at {dt.datetime.now()} ---")

    # 1. Check if user is already authenticated and tokens are valid/refreshable
    if "creds" in st.session_state and st.session_state["creds"]:
        creds_dict = st.session_state["creds"]
        creds = creds_from_dict(creds_dict)

        if creds and creds.valid:
            print("DEBUG: Credentials found in session state and are currently valid.")
            return True
        elif creds and creds.expired and creds.refresh_token:
            # Token expired, try to refresh using the stored refresh_token
            print("DEBUG: Credentials expired. Attempting to refresh token...")
            try:
                flow = get_flow()
                flow.credentials = creds # Attach the expired creds to the flow for refreshing
                flow.refresh_credentials() # This attempts to use the refresh_token

                # Update session state with new token (refresh token might also be updated by Google)
                st.session_state["creds"] = {
                    "token": flow.credentials.token,
                    "refresh_token": flow.credentials.refresh_token,
                    "token_uri": flow.credentials.token_uri,
                    "client_id": flow.credentials.client_id,
                    "client_secret": flow.credentials.client_secret,
                    "scopes": flow.credentials.scopes,
                    "id_token": flow.credentials.id_token,
                }
                st.success("Signed in! (Token refreshed successfully.)")
                print("DEBUG: Credentials refreshed and updated in session state.")
                return True
            except Exception as e:
                # Refresh failed (e.g., refresh token revoked or expired by Google)
                error_type = type(e).__name__
                print(f"ERROR: Failed to refresh token: {error_type}: {e}")
                traceback.print_exc() # Print full traceback to logs
                st.error(f"Failed to refresh token: {error_type}: {e}. Please sign in again.")
                if "creds" in st.session_state:
                    del st.session_state["creds"] # Clear invalid creds
                # Crucial: Clear query params to prevent re-using old 'code' if still in URL
                st.experimental_set_query_params()
                return False
        else:
            print("DEBUG: Credentials in session state are invalid or unrefreshable. Clearing and forcing re-login.")
            if "creds" in st.session_state:
                del st.session_state["creds"] # Clear out any stale/unusable credentials

    # 2. Handle redirect from Google with authorization code (after user grants permission)
    query_params = st.query_params
    print(f"DEBUG: Current query_params from browser URL: {query_params}")

    if "code" in query_params:
        auth_code = query_params["code"][0]
        # For security, you'd typically check 'state' here if you're using it
        # state = query_params.get("state", [None])[0]
        # if state != st.session_state.get("oauth_state_verifier"):
        #     st.error("Authentication failed: State mismatch. Possible CSRF attack.")
        #     print("ERROR: CSRF state mismatch detected!")
        #     st.experimental_set_query_params() # Clear bad query params
        #     return False
        # del st.session_state["oauth_state_verifier"] # Clear state after use

        print(f"DEBUG: Found 'code' in query_params. Attempting token exchange with code: {auth_code[:10]}... (first 10 chars)")

        try:
            flow = get_flow()
            if not flow:
                st.error("OAuth flow could not be initialized. Check application configuration.")
                print("ERROR: get_flow() failed in login() before token fetch.")
                return False

            # This is the line that will likely raise InvalidGrantError if there's a mismatch
            print(f"DEBUG: Calling flow.fetch_token() with code and flow.redirect_uri: {flow.redirect_uri}")
            flow.fetch_token(code=auth_code)

            # Store ALL necessary credential parts in session state
            st.session_state["creds"] = {
                "token": flow.credentials.token,
                "refresh_token": flow.credentials.refresh_token, # CRUCIAL for long-lived access
                "token_uri": flow.credentials.token_uri,
                "client_id": flow.credentials.client_id,
                "client_secret": flow.credentials.client_secret,
                "scopes": flow.credentials.scopes,
                "id_token": flow.credentials.id_token,
            }
            st.success("Successfully signed in with Google!")
            print("DEBUG: Token fetched and credentials stored in session state.")

            # IMPORTANT: Clear the 'code' from the URL using Streamlit's API.
            # This prevents the app from trying to reuse the same 'code' on page refresh,
            # which commonly leads to 'Malformed auth code' errors.
            st.experimental_set_query_params()
            print("DEBUG: Query parameters cleared from URL after successful token exchange.")
            return True
        except Exception as e:
            error_type = type(e).__name__
            print(f"ERROR: Exception during token fetch: {error_type}: {e}")
            traceback.print_exc() # Print full traceback to logs for detailed error
            st.error(f"Authentication failed: {error_type}: {e}. Please try again.")
            st.warning("Double-check your **Redirect URI** in Google Cloud Console matches exactly.")
            # Clear any potentially bad data or query params on failure
            st.experimental_set_query_params()
            if "creds" in st.session_state:
                del st.session_state["creds"]
            return False
    else:
        # 3. If no 'code' in URL and no valid creds, display login button
        print("DEBUG: No 'code' found in query_params and no valid credentials. Displaying login prompt.")
        flow = get_flow()
        if flow:
            authorization_url, state = flow.authorization_url(
                access_type="offline",          # CRUCIAL: To obtain a refresh token
                prompt="consent",               # CRUCIAL: Forces user to re-consent, ensures refresh token is issued
                include_granted_scopes="true"
            )
            # Store 'state' to prevent CSRF attacks if you implement state checking
            # st.session_state["oauth_state_verifier"] = state
            print(f"DEBUG: Generated Google authorization URL: {authorization_url}")
            st.markdown(f"[**Sign in with Google**]({authorization_url})", unsafe_allow_html=True)
        else:
            st.error("Cannot initialize Google login. Please check `client_secrets` configuration.")
        return False

# ---------- PDF parser ----------
def parse_pdf(file_bytes):
    """Parses shifts from a PDF file."""
    shifts = []
    print("DEBUG: parse_pdf called.")
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            # Try to extract year from metadata or default to current year
            year_match = re.search(r"(\d{4})", pdf.metadata.get("Title", ""))
            year = int(year_match.group(1)) if year_match else dt.datetime.now().year
            print(f"DEBUG: PDF metadata year: {year}")

            for page_num, page in enumerate(pdf.pages, start=1):
                print(f"DEBUG: Processing page {page_num}.")
                table = page.extract_table()
                if not table:
                    print(f"DEBUG: No table found on page {page_num}. Skipping.")
                    continue

                if len(table) < 2 or len(table[0]) == 0:
                    print(f"DEBUG: Table on page {page_num} is malformed (not enough rows/cols). Skipping.")
                    continue

                df = pd.DataFrame(table[1:], columns=table[0])

                if "Entrada" not in df.columns or "Sortida" not in df.columns:
                    print(f"DEBUG: Missing 'Entrada' or 'Sortida' columns on page {page_num}. Skipping.")
                    continue
                
                # Iterate through columns assumed to contain shift data (excluding the first label column)
                for col_name in df.columns[1:]:
                    day_str = str(df.iloc[0][col_name]).strip()
                    
                    if not day_str.isdigit():
                        # print(f"DEBUG: Skipping non-digit day string: '{day_str}' in column '{col_name}' on page {page_num}")
                        continue # Not a valid day number, skip column

                    try:
                        # Assume page_num corresponds to month. This is a common pattern for schedules.
                        date = dt.date(year, page_num, int(day_str))
                    except ValueError as e:
                        print(f"DEBUG: Could not form valid date for day '{day_str}', month '{page_num}', year '{year}': {e}. Skipping.")
                        continue # Invalid date (e.g., Feb 30th)

                    # Safely get start and end times, handling potential missing values
                    start_val = df.loc[df["Entrada"] == "Entrada", col_name].values
                    end_val   = df.loc[df["Sortida"] == "Sortida", col_name].values
                    
                    if start_val.size == 0 or end_val.size == 0:
                        # print(f"DEBUG: Missing Entrada/Sortida data for {date} in column {col_name}. Skipping.")
                        continue # No entry for Entrada/Sortida for this day

                    start = str(start_val[0]).strip()
                    end   = str(end_val[0]).strip()

                    if re.fullmatch(r"(\d{1,2}):(\d{2})", start) and re.fullmatch(r"(\d{1,2}):(\d{2})", end):
                        key = f"{date:%Y%m%d}-{start.replace(':','')}-{end.replace(':','')}" # Added end time to key for uniqueness
                        shifts.append({"key": key, "date": date.isoformat(), "start": start, "end": end})
                    # else:
                        # print(f"DEBUG: Skipping malformed time format for {date}: Start='{start}', End='{end}'")
        print(f"DEBUG: Finished PDF parsing. Found {len(shifts)} shifts.")
        return shifts
    except Exception as e:
        print(f"ERROR: Unexpected error during PDF parsing: {type(e).__name__}: {e}")
        traceback.print_exc()
        st.error(f"An error occurred while parsing the PDF: {e}")
        return []

# ---------- Calendar sync ----------
def sync_shifts(creds, shifts, tz="Europe/Madrid"):
    """Syncs the parsed shifts to Google Calendar."""
    print(f"DEBUG: sync_shifts called. Timezone: {tz}.")
    try:
        service = build("calendar", "v3", credentials=creds, cache_discovery=False)
        now = dt.datetime.utcnow().isoformat() + "Z" # 'Z' indicates UTC time

        # Fetch existing events created by this app to avoid duplicates and handle updates/deletes
        existing_events = []
        page_token = None
        while True:
            try:
                events_result = service.events().list(
                    calendarId="primary",
                    timeMin=now, # Only get events from now onwards
                    privateExtendedProperty="shiftUploader=1", # Custom property to identify our events
                    pageToken=page_token
                ).execute()
                existing_events.extend(events_result.get("items", []))
                page_token = events_result.get('nextPageToken')
                if not page_token:
                    break
            except HttpError as error:
                print(f"ERROR: Google Calendar API error fetching existing events: {error}")
                st.error(f"Error fetching existing calendar events: {error.status_code} - {error.reason}")
                return 0, 0, 0 # Return zeros if fetching fails
        
        # Map existing events by their unique key for easy lookup
        # Ensure 'private' extended properties exist and 'key' is in them
        by_key = {}
        for e in existing_events:
            if "extendedProperties" in e and "private" in e["extendedProperties"] and "key" in e["extendedProperties"]["private"]:
                by_key[e["extendedProperties"]["private"]["key"]] = e
        print(f"DEBUG: Found {len(by_key)} existing events from calendar.")

        inserts, updates, deletes = 0, 0, 0

        for s in shifts:
            # Handle shifts that cross midnight (e.g., 22:00-06:00)
            start_dt_obj = dt.datetime.fromisoformat(f"{s['date']}T{s['start']}")
            end_dt_obj = dt.datetime.fromisoformat(f"{s['date']}T{s['end']}")

            if end_dt_obj < start_dt_obj: # If end time is earlier than start time on same day
                end_dt_obj += dt.timedelta(days=1) # Assume it's the next day

            start_iso = start_dt_obj.isoformat(timespec='seconds') # Include seconds for full ISO format
            end_iso   = end_dt_obj.isoformat(timespec='seconds')

            body = {
                "summary": f"P {s['start']}-{s['end']}", # More descriptive summary
                "start": {"dateTime": start_iso, "timeZone": tz},
                "end":   {"dateTime": end_iso,   "timeZone": tz},
                "extendedProperties": {"private": {"shiftUploader": "1", "key": s["key"]}},
            }

            try:
                if s["key"] in by_key:
                    # Update existing event
                    ev_id = by_key[s["key"]]["id"]
                    service.events().patch(calendarId="primary", eventId=ev_id, body=body).execute()
                    updates += 1
                    del by_key[s["key"]] # Mark as processed, remaining in by_key will be deleted
                    print(f"DEBUG: Updated event with key: {s['key']}")
                else:
                    # Insert new event
                    service.events().insert(calendarId="primary", body=body).execute()
                    inserts += 1
                    print(f"DEBUG: Inserted new event with key: {s['key']}")
            except HttpError as error:
                print(f"ERROR: Google Calendar API error syncing event {s['key']}: {error}")
                st.error(f"Error syncing event '{s['key']}': {error.status_code} - {error.reason}")
                # Continue processing other shifts even if one fails

        # Delete any remaining events in by_key (these were in calendar but not in new PDF)
        for ev in by_key.values():
            try:
                service.events().delete(calendarId="primary", eventId=ev["id"]).execute()
                deletes += 1
                print(f"DEBUG: Deleted event with ID: {ev['id']}")
            except HttpError as error:
                print(f"ERROR: Google Calendar API error deleting event {ev['id']}: {error}")
                st.error(f"Error deleting event with ID '{ev['id']}': {error.status_code} - {error.reason}")

        print(f"DEBUG: Sync complete. Inserts: {inserts}, Updates: {updates}, Deletes: {deletes}")
        return inserts, updates, deletes

    except Exception as e:
        print(f"ERROR: An unexpected error occurred during sync_shifts: {type(e).__name__}: {e}")
        traceback.print_exc()
        st.error(f"An unexpected error occurred during calendar sync: {e}")
        return 0, 0, 0


# ---------- Streamlit UI ----------
st.set_page_config(page_title="Shift Uploader", page_icon="🗓️", layout="centered")
st.title("📤 Shift → Google Calendar")

# Initialize session state for 'creds' if it doesn't exist
if "creds" not in st.session_state:
    st.session_state["creds"] = None

# Attempt to log in or display login prompt
# The login() function will return True if successful (already logged in, or just logged in)
# It will display the login button if not logged in.
if login():
    # If login() returns True, it means we have valid credentials to proceed
    creds = creds_from_dict(st.session_state["creds"]) # Re-create credentials object from dict

    st.write("---") # Separator for logged-in content

    file = st.file_uploader("Upload your PDF schedule", type="pdf", help="Please upload a PDF file containing your work schedule.")
    if file:
        with st.spinner("Reading PDF... This may take a moment..."):
            shifts = parse_pdf(file.read())
        
        if not shifts:
            st.error("No shifts found in the PDF. Please check the PDF format, especially 'Entrada' and 'Sortida' column labels, and the year in the document title.")
            st.info("Ensure the PDF is a standard tabular schedule.")
        else:
            st.info(f"Successfully found **{len(shifts)}** shifts from the PDF. Preview:")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True) # Display parsed shifts

            st.write("---")
            st.subheader("Sync to Google Calendar")
            st.warning("Before syncing, ensure your Google Calendar is selected as 'primary' or the correct calendar ID is used in the code.")
            
            # Add a confirmation checkbox
            confirm_sync = st.checkbox("I understand shifts will be added/updated/deleted in my primary Google Calendar.")
            
            if confirm_sync and st.button("Sync Shifts Now"):
                with st.spinner("Syncing shifts to Google Calendar..."):
                    try:
                        ins, upd, dele = sync_shifts(creds, shifts)
                        st.success(f"✅ Sync Complete: Inserted {ins}, Updated {upd}, Deleted {dele} shifts.")
                        st.balloons() # Visual celebration!
                    except Exception as e:
                        st.error(f"An unexpected error occurred during calendar synchronization: {e}")
                        print(f"ERROR: Unhandled exception during sync: {e}")
                        traceback.print_exc()
    else:
        st.info("Upload a PDF to begin.")
else:
    # If login() returns False, the login process is not complete.
    # The login() function itself will display the "Sign in with Google" button.
    st.info("Please sign in with your Google account to upload your shifts.")
