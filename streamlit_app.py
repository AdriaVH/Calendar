import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError # Import HttpError for Google API errors
import traceback # Import traceback for detailed error logs

# ---------- CONFIG ----------
SCOPES = [
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar", # General calendar access
    "openid", # Basic user info
    "https://www.googleapis.com/auth/userinfo.email" # User's email
]

# Access secrets
CLIENT_ID = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI = st.secrets["google"]["redirect_uri"]

# Print configuration details to Streamlit Cloud logs for debugging
print(f"\n--- App Initialization ({dt.datetime.now()}) ---")
print(f"DEBUG: Configured CLIENT_ID (first 5 chars): {CLIENT_ID[:5] if CLIENT_ID else 'None/Empty'}")
print(f"DEBUG: Configured CLIENT_SECRET (first 5 chars): {CLIENT_SECRET[:5] if CLIENT_SECRET else 'None/Empty'}")
print(f"DEBUG: Configured REDIRECT_URI: {REDIRECT_URI}")
print(f"DEBUG: Configured SCOPES: {SCOPES}")


# ---------- OAUTH FLOW ----------
def make_flow(state=None):
    """Initializes and returns the Google OAuth Flow object."""
    print(f"DEBUG: make_flow() called with state: {state}")
    flow = None
    try:
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
            state=state # Pass state if provided
        )
        flow.redirect_uri = REDIRECT_URI # Ensure redirect_uri is set on the flow object for token exchange
        print(f"DEBUG: Flow object created. flow.redirect_uri set to: {flow.redirect_uri}")

        # Only print the 'web' section of client_config for brevity
        if hasattr(flow, 'client_config') and 'web' in flow.client_config:
            print(f"DEBUG: Flow client_config (web section): {flow.client_config['web']}")
        else:
            print("ERROR: flow.client_config or its 'web' section not found after Flow.from_client_config.")

    except Exception as e:
        print(f"ERROR: Exception during Flow.from_client_config: {type(e).__name__}: {e}")
        traceback.print_exc()
        st.error(f"Failed to initialize Google login. Check your CLIENT_ID and CLIENT_SECRET in Streamlit secrets. Error: {e}")
        return None # Return None if flow creation fails
    return flow

def creds_from_dict(d):
    """Converts a dictionary back into a Google OAuth Credentials object."""
    if not d:
        print("DEBUG: creds_from_dict received empty data.")
        return None
    try:
        creds = Credentials(**d)
        print(f"DEBUG: Credentials object created. Valid: {creds.valid}, Expired: {creds.expired}, Refreshable: {bool(creds.refresh_token)}")
        return creds
    except Exception as e:
        print(f"ERROR: Exception creating Credentials from dict: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None

def google_login():
    """
    Handles the Google OAuth login process, including initial authentication,
    token exchange, and refresh token handling.
    """
    st.markdown("---") # Visual separator for logs
    print(f"\n--- google_login() function called at {dt.datetime.now()} ---")

    query_params = st.query_params
    print(f"DEBUG: Current query_params from browser URL (at start of google_login): {query_params}")

    # 1. Already signed in? Check if user is authenticated and tokens are valid/refreshable
    creds = creds_from_dict(st.session_state.get("creds"))
    if creds and creds.valid:
        print("DEBUG: Credentials found in session state and are currently valid.")
        return True
    elif creds and creds.expired and creds.refresh_token:
        print("DEBUG: Credentials expired. Attempting to refresh token...")
        try:
            flow = make_flow() # For refreshing, state is not typically needed here
            if not flow:
                return False
            flow.credentials = creds
            flow.refresh_credentials()

            # Update session state with refreshed credentials
            c = flow.credentials
            st.session_state["creds"] = {
                "token": c.token,
                "refresh_token": c.refresh_token,
                "token_uri": c.token_uri,
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "scopes": c.scopes,
                "id_token": c.id_token, # Add id_token for completeness if present
            }
            st.success("Signed in! (Token refreshed successfully.)")
            print("DEBUG: Credentials refreshed and updated in session state.")
            return True
        except Exception as e:
            error_type = type(e).__name__
            print(f"ERROR: Failed to refresh token: {error_type}: {e}")
            traceback.print_exc()
            st.error(f"Failed to refresh token: {error_type}: {e}. Please sign in again.")
            if "creds" in st.session_state:
                del st.session_state["creds"]
            st.query_params.clear() # Clear any potentially bad data or query params on failure
            print("DEBUG: Query parameters cleared after token refresh failure.")
            return False
    elif creds and (not creds.valid or not creds.refresh_token): # Explicitly handle invalid but unrefreshable
        print("DEBUG: Credentials in session state are invalid or unrefreshable. Clearing and forcing re-login.")
        if "creds" in st.session_state:
            del st.session_state["creds"]


    # 2. Back from Google with ?code=
    # Re-fetch query_params here as Streamlit might have reran for other reasons.
    query_params = st.query_params
    print(f"DEBUG: Re-checking query_params (before 'code' check): {query_params}")

    # Check for 'code' and ensure it hasn't been handled yet (prevents double-processing)
    if "code" in query_params and not st.session_state.get("auth_code_handled", False):
        print(f"DEBUG: 'code' found in query_params. auth_code_handled status: {st.session_state.get('auth_code_handled', False)}")
        st.session_state["auth_code_handled"] = True # Set flag immediately to prevent re-use on next rerun

        auth_code = query_params["code"][0]
        state = st.session_state.get("oauth_state") # Retrieve the state from session state

        print(f"DEBUG: Found 'code' in query_params. Attempting token exchange with code: {auth_code[:10]}... (first 10 chars) and state: {state}")

        # Build Flow WITH state if we still have it, otherwise a brand-new Flow (no state check)
        # The 'state' is crucial for security (CSRF protection) and should be used consistently.
        flow = make_flow(state) # Always pass the retrieved state here if it exists

        if not flow:
            st.error("OAuth flow could not be initialized. Check application configuration.")
            print("ERROR: make_flow() failed in google_login() before token fetch.")
            st.query_params.clear()
            print("DEBUG: Query parameters cleared after make_flow() failure.")
            return False

        try:
            # --- CRITICAL DEBUG PRINTS RIGHT BEFORE fetch_token ---
            print(f"DEBUG: Final check - auth_code (first 10): {auth_code[:10]}...")
            print(f"DEBUG: Final check - flow.redirect_uri for token exchange: {flow.redirect_uri}")
            print(f"DEBUG: Calling flow.fetch_token()...")
            # --- END CRITICAL DEBUG PRINTS ---

            flow.fetch_token(code=auth_code) # Exchange the authorization code for tokens

            # Store credentials in session state
            c = flow.credentials
            st.session_state["creds"] = {
                "token": c.token,
                "refresh_token": c.refresh_token,
                "token_uri": c.token_uri,
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "scopes": c.scopes,
                "id_token": c.id_token, # Add id_token for completeness if present
            }
            st.success("Successfully signed in with Google!")
            print("DEBUG: Token fetched and credentials stored in session state.")

            # Clear query parameters immediately after successful token exchange
            st.query_params.clear()
            print("DEBUG: Query parameters cleared from URL after successful token exchange.")
            return True
        except Exception as e:
            error_type = type(e).__name__
            print(f"ERROR: Exception during token fetch: {error_type}: {e}")
            traceback.print_exc()
            st.error(f"Authentication failed: {error_type}: {e}. Please try again.")
            st.warning("Double-check your **Redirect URI** in Google Cloud Console matches exactly `https://makecalendar.streamlit.app`.")

            # Clear query parameters immediately after failed token exchange
            st.query_params.clear()
            print("DEBUG: Query parameters cleared after token fetch failure.")
            if "creds" in st.session_state:
                del st.session_state["creds"] # Clear potentially bad credentials
            return False
    elif "code" in query_params and st.session_state.get("auth_code_handled", False):
        print("DEBUG: 'code' found in query_params, but it has already been handled. Clearing query params.")
        st.query_params.clear() # Clear the code if we've already tried to handle it
        return False # Stay on login screen or indicate handling

    # 3. If no 'code' in URL and no valid creds, display login button
    print("DEBUG: No 'code' found in query_params (or already handled) and no valid credentials. Displaying login prompt.")
    flow = make_flow()
    if flow:
        authorization_url, state = flow.authorization_url(
            access_type="offline", # Request refresh token
            prompt="consent", # Force consent screen to get refresh token on first login
            include_granted_scopes="true" # Include previously granted scopes in consent
        )
        st.session_state["oauth_state"] = state # Store the state for verification
        print(f"DEBUG: Generated Google authorization URL: {authorization_url}")
        st.markdown(f"[**Sign in with Google**]({authorization_url})", unsafe_allow_html=True)
    else:
        st.error("Cannot initialize Google login. Please check `client_secrets` configuration.")
    return False


# ---------- PDF PARSER ----------
def parse_pdf(data):
    """Parses shifts from a PDF file."""
    shifts = []
    print("DEBUG: parse_pdf called.")
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            # Try to extract year from metadata or default to current year
            year_match = re.search(r"(\d{4})", pdf.metadata.get("Title", ""))
            year = int(year_match.group(1)) if year_match else dt.datetime.now().year
            print(f"DEBUG: PDF metadata year: {year}")

            for page_num, page in enumerate(pdf.pages, 1):
                print(f"DEBUG: Processing page {page_num}.")
                table = page.extract_table()
                if not table:
                    print(f"DEBUG: No table found on page {page_num}. Skipping.")
                    continue
                
                # Original checks from your code
                if len(table) < 2 or len(table[0]) == 0:
                    print(f"DEBUG: Table on page {page_num} is malformed (not enough rows/cols). Skipping.")
                    continue
                df = pd.DataFrame(table[1:], columns=table[0])
                if "Entrada" not in df.columns or "Sortida" not in df.columns:
                    print(f"DEBUG: Missing 'Entrada' or 'Sortida' columns on page {page_num}. Skipping.")
                    continue

                for col_name in df.columns[1:]: # Iterate through columns assumed to contain shift data
                    day_str = str(df.iloc[0][col_name]).strip()
                    if not day_str.isdigit():
                        continue # Not a valid day number, skip column

                    try:
                        # Assume page_num corresponds to month. This is a common pattern for schedules.
                        date = dt.date(year, page_num, int(day_str))
                    except ValueError as e:
                        print(f"DEBUG: Could not form valid date for day '{day_str}', month '{page_num}', year '{year}': {e}. Skipping.")
                        continue # Invalid date (e.g., Feb 30th)

                    start_val = df.loc[df["Entrada"] == "Entrada", col_name].values
                    end_val   = df.loc[df["Sortida"] == "Sortida", col_name].values

                    if start_val.size and end_val.size and \
                       re.fullmatch(r"(\d{1,2}):(\d{2})", start_val[0]) and \
                       re.fullmatch(r"(\d{1,2}):(\d{2})", end_val[0]):
                        
                        start_time = str(start_val[0]).strip()
                        end_time = str(end_val[0]).strip()

                        # Ensure end_time is on the next day if it's earlier than start_time
                        start_dt_obj = dt.datetime.fromisoformat(f"{date.isoformat()}T{start_time}")
                        end_dt_obj = dt.datetime.fromisoformat(f"{date.isoformat()}T{end_time}")
                        if end_dt_obj < start_dt_obj:
                            end_dt_obj += dt.timedelta(days=1)
                        
                        # Use the correct end_time for the key to ensure uniqueness over different shift durations on same day
                        key = f"{date:%Y%m%d}-{start_time.replace(':','')}-{end_time.replace(':','')}"
                        shifts.append({"key": key, "date": date.isoformat(), "start": start_time, "end": end_time})
        print(f"DEBUG: Finished PDF parsing. Found {len(shifts)} shifts.")
        return shifts
    except Exception as e:
        print(f"ERROR: Unexpected error during PDF parsing: {type(e).__name__}: {e}")
        traceback.print_exc()
        st.error(f"An error occurred while parsing the PDF: {e}")
        return []

# ---------- CALENDAR SYNC ----------
def sync(creds, shifts, tz="Europe/Madrid"):
    """Syncs the parsed shifts to Google Calendar."""
    print(f"DEBUG: sync() called. Timezone: {tz}.")
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
                "summary": f"P {s['start']}-{s['end']}", # More descriptive summary (added end time)
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
                st.error(f"Error deleting event with ID '{ev["id"]}': {error.status_code} - {error.reason}")

        print(f"DEBUG: Sync complete. Inserts: {inserts}, Updates: {updates}, Deletes: {deletes}")
        return inserts, updates, deletes

    except Exception as e:
        print(f"ERROR: An unexpected error occurred during sync: {type(e).__name__}: {e}")
        traceback.print_exc()
        st.error(f"An unexpected error occurred during calendar sync: {e}")
        return 0, 0, 0


# ---------- STREAMLIT UI ----------
st.set_page_config(page_title="Shift Uploader", page_icon="📅", layout="centered")
st.title("📤 Shift → Google Calendar")

# Initialize session state for 'creds' and 'auth_code_handled' if they don't exist
if "creds" not in st.session_state:
    st.session_state["creds"] = None
if "auth_code_handled" not in st.session_state:
    st.session_state["auth_code_handled"] = False

if google_login():
    creds = creds_from_dict(st.session_state["creds"]) # Re-create creds object for use
    if not creds: # If creds_from_dict failed, force re-login
        st.error("Error retrieving credentials. Please sign in again.")
        st.session_state["creds"] = None
        st.session_state["auth_code_handled"] = False
        st.experimental_rerun()
    
    st.write("---") # Separator after successful login

    pdf = st.file_uploader("Upload PDF with Entrada/Sortida schedule", type="pdf", help="Please upload a PDF file containing your work schedule with 'Entrada' (Start) and 'Sortida' (End) columns.")
    if pdf:
        with st.spinner("Parsing PDF... This may take a moment..."):
            shifts = parse_pdf(pdf.read())
        
        if not shifts:
            st.error("No shifts found in the PDF. Please check the PDF format, especially 'Entrada' and 'Sortida' column labels, and the year in the document title.")
            st.info("Ensure the PDF is a standard tabular schedule, one month per page, with a row for 'Entrada' and 'Sortida' times.")
        else:
            st.info(f"Successfully found **{len(shifts)}** shifts from the PDF. Preview:")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True)

            st.write("---")
            st.subheader("Sync to Google Calendar")
            st.warning("Before syncing, ensure your Google Calendar is selected as 'primary' or the correct calendar ID is used in the code. Events will be added, updated, or deleted based on the PDF.")
            
            confirm_sync = st.checkbox("I understand shifts will be added/updated/deleted in my primary Google Calendar.")
            
            if confirm_sync and st.button("Sync Shifts Now"):
                with st.spinner("Syncing shifts to Google Calendar..."):
                    try:
                        ins, upd, dele = sync(creds, shifts)
                        st.success(f"✅ Sync Complete: Inserted {ins}, Updated {upd}, Deleted {dele} shifts.")
                        st.balloons()
                    except Exception as e:
                        st.error(f"An unexpected error occurred during calendar synchronization: {e}")
                        print(f"ERROR: Unhandled exception during sync: {e}")
                        traceback.print_exc()
    else:
        st.info("Upload a PDF to begin.")
else:
    st.info("Please sign in with your Google account to upload your shifts.")
