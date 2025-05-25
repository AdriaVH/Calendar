import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import traceback

# ---------- STREAMLIT UI CONFIG (MUST BE FIRST) ----------
st.set_page_config(page_title="Shift Uploader", page_icon="📅", layout="centered")

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

# --- UI Debugging: Display config at the start ---
st.sidebar.subheader("App Config (Debug)")
st.sidebar.info(f"Client ID (first 5): {CLIENT_ID[:5] if CLIENT_ID else 'None'}")
st.sidebar.info(f"Redirect URI: {REDIRECT_URI}")
st.sidebar.info(f"Scopes: {', '.join(SCOPES)}")


# ---------- OAUTH FLOW ----------
def make_flow(state=None):
    """Initializes and returns the Google OAuth Flow object."""
    # print(f"DEBUG: make_flow() called with state: {state}") # Keeping print for internal logs
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
            state=state
        )
        flow.redirect_uri = REDIRECT_URI
        # print(f"DEBUG: Flow object created. flow.redirect_uri set to: {flow.redirect_uri}") # Keeping print

        # Display important flow config in UI
        st.sidebar.info(f"Flow redirect_uri set: {flow.redirect_uri}")
        if hasattr(flow, 'client_config') and 'web' in flow.client_config:
            st.sidebar.json({"Flow Client Config (Web)": flow.client_config['web']})

    except Exception as e:
        # print(f"ERROR: Exception during Flow.from_client_config: {type(e).__name__}: {e}") # Keeping print
        # traceback.print_exc() # Keeping print
        st.error(f"Failed to initialize Google login. Error: {e}")
        st.stop() # Stop app if flow cannot be created
    return flow

def creds_from_dict(d):
    """Converts a dictionary back into a Google OAuth Credentials object."""
    if not d:
        # print("DEBUG: creds_from_dict received empty data.") # Keeping print
        return None
    try:
        creds = Credentials(**d)
        # print(f"DEBUG: Credentials object created. Valid: {creds.valid}, Expired: {creds.expired}, Refreshable: {bool(creds.refresh_token)}") # Keeping print
        return creds
    except Exception as e:
        # print(f"ERROR: Exception creating Credentials from dict: {type(e).__name__}: {e}") # Keeping print
        # traceback.print_exc() # Keeping print
        st.error(f"Error restoring credentials: {e}")
        return None

def google_login():
    """
    Handles the Google OAuth login process, including initial authentication,
    token exchange, and refresh token handling.
    """
    st.markdown("---") # Visual separator

    query_params = st.query_params
    st.sidebar.subheader("Current Query Params (Debug)")
    st.sidebar.json(dict(query_params)) # Display all query parameters in UI

    # print(f"\n--- google_login() function called at {dt.datetime.now()} ---") # Keeping print
    # print(f"DEBUG: Current query_params from browser URL (at start of google_login): {query_params}") # Keeping print

    # 1. Already signed in? Check if user is authenticated and tokens are valid/refreshable
    creds = creds_from_dict(st.session_state.get("creds"))
    if creds and creds.valid:
        st.success("You are already signed in with Google!")
        return True
    elif creds and creds.expired and creds.refresh_token:
        st.info("Your Google session has expired. Attempting to refresh token...")
        try:
            flow = make_flow()
            if not flow: return False
            flow.credentials = creds
            flow.refresh_credentials()

            c = flow.credentials
            st.session_state["creds"] = {
                "token": c.token,
                "refresh_token": c.refresh_token,
                "token_uri": c.token_uri,
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "scopes": c.scopes,
                "id_token": c.id_token,
            }
            st.success("Signed in! (Token refreshed successfully.)")
            return True
        except Exception as e:
            error_type = type(e).__name__
            st.error(f"Failed to refresh token: {error_type}: {e}. Please sign in again.")
            # traceback.print_exc() # Keeping print
            if "creds" in st.session_state:
                del st.session_state["creds"]
            st.query_params.clear()
            st.experimental_rerun()
            return False
    elif creds and (not creds.valid or not creds.refresh_token):
        st.warning("Your existing Google credentials are invalid or unrefreshable. Please sign in again.")
        if "creds" in st.session_state:
            del st.session_state["creds"]


    # 2. Back from Google with ?code=
    st.sidebar.info(f"auth_code_handled: {st.session_state.get('auth_code_handled', False)}")

    if "code" in query_params and not st.session_state.get("auth_code_handled", False):
        st.info("Code detected in URL. Attempting to sign in...")
        st.session_state["auth_code_handled"] = True # Set flag immediately

        auth_code = query_params["code"][0]
        state = st.session_state.get("oauth_state")

        st.sidebar.info(f"Authorization code (first 10 chars): {auth_code[:10]}...")
        st.sidebar.info(f"OAuth state from session: {state}")

        flow = make_flow(state)
        if not flow: return False

        try:
            st.sidebar.info(f"Redirect URI used for token exchange: {flow.redirect_uri}") # CRITICAL UI DEBUG
            flow.fetch_token(code=auth_code)

            c = flow.credentials
            st.session_state["creds"] = {
                "token": c.token,
                "refresh_token": c.refresh_token,
                "token_uri": c.token_uri,
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "scopes": c.scopes,
                "id_token": c.id_token,
            }
            st.success("Successfully signed in with Google!")
            st.query_params.clear()
            st.experimental_rerun()
            return True
        except Exception as e:
            error_type = type(e).__name__
            st.error(f"Authentication failed: {error_type}: {e}. Please try again.")
            st.warning("Double-check your **Redirect URI** in Google Cloud Console matches exactly `https://makecalendar.streamlit.app`.")
            st.info("Error details (debug): " + str(e)) # Display error message in UI

            st.query_params.clear()
            if "creds" in st.session_state:
                del st.session_state["creds"]
            st.experimental_rerun()
            return False
    elif "code" in query_params and st.session_state.get("auth_code_handled", False):
        st.warning("Code already processed. Clearing URL and redirecting...")
        st.query_params.clear()
        st.experimental_rerun()
        return False

    # 3. If no 'code' in URL and no valid creds, display login button
    flow = make_flow()
    if flow:
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true"
        )
        st.session_state["oauth_state"] = state
        st.markdown(f"[**Sign in with Google**]({authorization_url})", unsafe_allow_html=True)
    else:
        st.error("Cannot initialize Google login. Please check `client_secrets` configuration.")
    return False


# ---------- PDF PARSER ----------
def parse_pdf(data):
    shifts = []
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            year_match = re.search(r"(\d{4})", pdf.metadata.get("Title", ""))
            year = int(year_match.group(1)) if year_match else dt.datetime.now().year

            for page_num, page in enumerate(pdf.pages, 1):
                table = page.extract_table()
                if not table: continue
                
                if len(table) < 2 or len(table[0]) == 0: continue
                df = pd.DataFrame(table[1:], columns=table[0])
                if "Entrada" not in df.columns or "Sortida" not in df.columns: continue

                for col_name in df.columns[1:]:
                    day_str = str(df.iloc[0][col_name]).strip()
                    if not day_str.isdigit(): continue
                    try: date = dt.date(year, page_num, int(day_str))
                    except ValueError: continue

                    start_val = df.loc[df["Entrada"] == "Entrada", col_name].values
                    end_val   = df.loc[df["Sortida"] == "Sortida", col_name].values

                    if start_val.size and end_val.size and \
                       re.fullmatch(r"(\d{1,2}):(\d{2})", start_val[0]) and \
                       re.fullmatch(r"(\d{1,2}):(\d{2})", end_val[0]):
                        
                        start_time = str(start_val[0]).strip()
                        end_time = str(end_val[0]).strip()

                        start_dt_obj = dt.datetime.fromisoformat(f"{date.isoformat()}T{start_time}")
                        end_dt_obj = dt.datetime.fromisoformat(f"{date.isoformat()}T{end_time}")
                        if end_dt_obj < start_dt_obj:
                            end_dt_obj += dt.timedelta(days=1)
                        
                        key = f"{date:%Y%m%d}-{start_time.replace(':','')}-{end_time.replace(':','')}"
                        shifts.append({"key": key, "date": date.isoformat(), "start": start_time, "end": end_time})
        return shifts
    except Exception as e:
        st.error(f"An error occurred while parsing the PDF: {e}")
        traceback.print_exc()
        return []

# ---------- CALENDAR SYNC ----------
def sync(creds, shifts, tz="Europe/Madrid"):
    try:
        service = build("calendar", "v3", credentials=creds, cache_discovery=False)
        now = dt.datetime.utcnow().isoformat() + "Z"

        existing_events = []
        page_token = None
        while True:
            try:
                events_result = service.events().list(
                    calendarId="primary", timeMin=now, privateExtendedProperty="shiftUploader=1", pageToken=page_token
                ).execute()
                existing_events.extend(events_result.get("items", []))
                page_token = events_result.get('nextPageToken')
                if not page_token: break
            except HttpError as error:
                st.error(f"Error fetching existing calendar events: {error.status_code} - {error.reason}")
                return 0, 0, 0
        
        by_key = {}
        for e in existing_events:
            if "extendedProperties" in e and "private" in e["extendedProperties"] and "key" in e["extendedProperties"]["private"]:
                by_key[e["extendedProperties"]["private"]["key"]] = e

        inserts, updates, deletes = 0, 0, 0

        for s in shifts:
            start_dt_obj = dt.datetime.fromisoformat(f"{s['date']}T{s['start']}")
            end_dt_obj = dt.datetime.fromisoformat(f"{s['date']}T{s['end']}")
            if end_dt_obj < start_dt_obj:
                end_dt_obj += dt.timedelta(days=1)
            start_iso = start_dt_obj.isoformat(timespec='seconds')
            end_iso   = end_dt_obj.isoformat(timespec='seconds')

            body = {
                "summary": f"P {s['start']}-{s['end']}",
                "start": {"dateTime": start_iso, "timeZone": tz},
                "end":   {"dateTime": end_iso,   "timeZone": tz},
                "extendedProperties": {"private": {"shiftUploader": "1", "key": s["key"]}},
            }

            try:
                if s["key"] in by_key:
                    ev_id = by_key[s["key"]]["id"]
                    service.events().patch(calendarId="primary", eventId=ev_id, body=body).execute()
                    updates += 1
                    del by_key[s["key"]]
                else:
                    service.events().insert(calendarId="primary", body=body).execute()
                    inserts += 1
            except HttpError as error:
                st.error(f"Error syncing event '{s['key']}': {error.status_code} - {error.reason}")

        for ev in by_key.values():
            try:
                service.events().delete(calendarId="primary", eventId=ev["id"]).execute()
                deletes += 1
            except HttpError as error:
                st.error(f"Error deleting event with ID '{ev["id"]}': {error.status_code} - {error.reason}")

        return inserts, updates, deletes

    except Exception as e:
        st.error(f"An unexpected error occurred during calendar sync: {e}")
        traceback.print_exc()
        return 0, 0, 0


# ---------- STREAMLIT UI (MAIN APP LOGIC) ----------
st.title("📤 Shift → Google Calendar")

if "creds" not in st.session_state:
    st.session_state["creds"] = None
if "auth_code_handled" not in st.session_state:
    st.session_state["auth_code_handled"] = False

if google_login():
    creds = creds_from_dict(st.session_state["creds"])
    if not creds:
        st.error("Error retrieving credentials. Please sign in again.")
        st.session_state["creds"] = None
        st.session_state["auth_code_handled"] = False
        st.experimental_rerun()
    
    st.write("---")

    pdf = st.file_uploader("Upload PDF with Entrada/Sortida schedule", type="pdf", help="Please upload a PDF file containing your work schedule.")
    if pdf:
        with st.spinner("Parsing PDF..."):
            shifts = parse_pdf(pdf.read())
        
        if not shifts:
            st.error("No shifts found in the PDF. Please check the PDF format, especially 'Entrada' and 'Sortida' column labels, and the year in the document title.")
            st.info("Ensure the PDF is a standard tabular schedule.")
        else:
            st.info(f"Successfully found **{len(shifts)}** shifts from the PDF. Preview:")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True)

            st.write("---")
            st.subheader("Sync to Google Calendar")
            st.warning("Before syncing, ensure your Google Calendar is selected as 'primary' or the correct calendar ID is used in the code.")
            
            confirm_sync = st.checkbox("I understand shifts will be added/updated/deleted in my primary Google Calendar.")
            
            if confirm_sync and st.button("Sync Shifts Now"):
                with st.spinner("Syncing shifts to Google Calendar..."):
                    try:
                        ins, upd, dele = sync(creds, shifts)
                        st.success(f"✅ Sync Complete: Inserted {ins}, Updated {upd}, Deleted {dele} shifts.")
                        st.balloons()
                    except Exception as e:
                        st.error(f"An unexpected error occurred during calendar synchronization: {e}")
                        traceback.print_exc()
    else:
        st.info("Upload a PDF to begin.")
else:
    st.info("Please sign in with your Google account to upload your shifts.")
