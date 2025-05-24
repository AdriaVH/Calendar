import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from dateutil.parser import parse as dtparse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow

# ---------- Google OAuth helpers ----------
SCOPES = ["https://www.googleapis.com/auth/calendar.events"]
CLIENT_ID     = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI  = st.secrets["google"]["redirect_uri"]  # e.g. "https://your-app.streamlit.app/"

def get_flow():
    return Flow(
        client_config={
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )

def login():
    if "creds" in st.session_state:
        return True
    query_params = st.experimental_get_query_params()
    if "code" in query_params:
        flow = get_flow()
        flow.fetch_token(code=query_params["code"][0])
        st.session_state["creds"] = flow.credentials_to_dict()
        st.experimental_set_query_params()          # clean url
        return True
    auth_url, _ = get_flow().authorization_url(
        access_type="offline",
        prompt="consent", include_granted_scopes="true")
    st.markdown(f"[**Sign in with Google**]({auth_url})", unsafe_allow_html=True)
    return False

def flow_credentials_to_dict(flow_creds):
    return {
        "token": flow_creds.token,
        "refresh_token": flow_creds.refresh_token,
        "token_uri": flow_creds.token_uri,
        "client_id": flow_creds.client_id,
        "client_secret": flow_creds.client_secret,
        "scopes": flow_creds.scopes,
    }

def creds_from_dict(data):
    return Credentials(**data)

# ---------- PDF → shifts ----------
def parse_pdf(file_bytes):
    shifts = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        year = re.search(r"(\d{4})", pdf.metadata.get("Title","2025")).group(1)  # fallback 2025
        for page in pdf.pages:
            table = page.extract_table()
            if not table:
                continue
            df = pd.DataFrame(table[1:], columns=table[0])
            # find Entrada / Sortida rows (sometimes repeated)
            if "Entrada" not in df.columns or "Sortida" not in df.columns:
                continue
            for col in df.columns[1:]:                      # first column is day number
                day_str = str(df.at[0, col]).strip()
                if not day_str.isdigit():
                    continue
                try:
                    date = dt.date(int(year), page.page_number, int(day_str))
                except ValueError:
                    continue
                start = str(df.at[df["Entrada"] == "Entrada"].iat[0, df.columns.get_loc(col)]).strip()
                end   = str(df.at[df["Sortida"] == "Sortida"].iat[0, df.columns.get_loc(col)]).strip()
                if re.fullmatch(r"\d{1,2}:\d{2}", start) and re.fullmatch(r"\d{1,2}:\d{2}", end):
                    key = f"{date:%Y%m%d}-{start.replace(':','')}"
                    shifts.append({"key": key, "date": date.isoformat(), "start": start, "end": end})
    return shifts

# ---------- Calendar sync ----------
def sync_shifts(creds, shifts, tz="Europe/Madrid"):
    service = build("calendar", "v3", credentials=creds, cache_discovery=False)
    now = dt.datetime.utcnow().isoformat() + "Z"
    existing = service.events().list(
        calendarId="primary",
        timeMin=now,
        privateExtendedProperty="shiftUploader=1"
    ).execute().get("items", [])
    by_key = {e["extendedProperties"]["private"]["key"]: e for e in existing}

    inserts, updates, deletes = 0, 0, 0

    for s in shifts:
        start_iso = f"{s['date']}T{s['start']}:00"
        end_iso   = f"{s['date']}T{s['end']}:00"
        body = {
            "summary": f"P {s['start']}",
            "start": {"dateTime": start_iso, "timeZone": tz},
            "end":   {"dateTime": end_iso,   "timeZone": tz},
            "extendedProperties": {"private": {"shiftUploader": "1", "key": s["key"]}},
        }

        if s["key"] in by_key:                     # update
            ev_id = by_key[s["key"]]["id"]
            service.events().patch(calendarId="primary", eventId=ev_id, body=body).execute()
            updates += 1
            del by_key[s["key"]]
        else:                                      # insert
            service.events().insert(calendarId="primary", body=body).execute()
            inserts += 1

    for ev in by_key.values():                     # delete removed shifts
        service.events().delete(calendarId="primary", eventId=ev["id"]).execute()
        deletes += 1

    return inserts, updates, deletes

# ---------- Streamlit UI ----------
st.set_page_config(page_title="Shift Uploader", page_icon="🗓️", layout="centered")
st.title("📤 Shift → Google Calendar")

if login():
    creds = creds_from_dict(st.session_state["creds"])
    st.success("Signed in!")

    file = st.file_uploader("Upload the roster PDF", type="pdf")
    if file:
        with st.spinner("Parsing…"):
            shifts = parse_pdf(file.read())
        if not shifts:
            st.error("No shifts found. Are ENTRADA/SORTIDA columns present?")
        else:
            st.info(f"Detected **{len(shifts)}** shifts. Preview below:")
            st.dataframe(pd.DataFrame(shifts).head(20), hide_index=True)
            if st.button("Sync to Google Calendar"):
                with st.spinner("Syncing…"):
                    ins, upd, dele = sync_shifts(creds, shifts)
                st.success(f"Inserted {ins}, updated {upd}, deleted {dele} events ✅")
