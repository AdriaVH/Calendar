import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from dateutil.parser import parse as dtparse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow

# ---------- OAuth setup ----------
SCOPES = ["https://www.googleapis.com/auth/calendar.events"]
CLIENT_ID     = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI  = st.secrets["google"]["redirect_uri"]  # e.g. "https://your-app.streamlit.app/"

def get_flow():
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

def login():
    if "creds" in st.session_state:
        return True
    query_params = st.query_params
    if "code" in query_params:
        flow = get_flow()
        flow.fetch_token(code=query_params["code"][0])
        st.session_state["creds"] = {
            "token": flow.credentials.token,
            "refresh_token": flow.credentials.refresh_token,
            "token_uri": flow.credentials.token_uri,
            "client_id": flow.credentials.client_id,
            "client_secret": flow.credentials.client_secret,
            "scopes": flow.credentials.scopes,
        }
        st.query_params.clear()  # Clean the URL
        return True
    auth_url, _ = get_flow().authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true")
    st.markdown(f"[**Sign in with Google**]({auth_url})", unsafe_allow_html=True)
    return False

def creds_from_dict(data):
    return Credentials(**data)

# ---------- PDF parser ----------
def parse_pdf(file_bytes):
    shifts = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        year = re.search(r"(\d{4})", pdf.metadata.get("Title", "2025")).group(1)
        for page in pdf.pages:
            table = page.extract_table()
            if not table:
                continue
            df = pd.DataFrame(table[1:], columns=table[0])
            if "Entrada" not in df.columns or "Sortida" not in df.columns:
                continue
            for col in df.columns[1:]:
                day_str = str(df.iloc[0][col]).strip()
                if not day_str.isdigit():
                    continue
                try:
                    date = dt.date(int(year), page.page_number, int(day_str))
                except ValueError:
                    continue
                start = str(df.loc[df["Entrada"] == "Entrada"][col].values[0]).strip()
                end   = str(df.loc[df["Sortida"] == "Sortida"][col].values[0]).strip()
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

        if s["key"] in by_key:
            ev_id = by_key[s["key"]]["id"]
            service.events().patch(calendarId="primary", eventId=ev_id, body=body).execute()
            updates += 1
            del by_key[s["key"]]
        else:
            service.events().insert(calendarId="primary", body=body).execute()
            inserts += 1

    for ev in by_key.values():
        service.events().delete(calendarId="primary", eventId=ev["id"]).execute()
        deletes += 1

    return inserts, updates, deletes

# ---------- Streamlit UI ----------
st.set_page_config(page_title="Shift Uploader", page_icon="🗓️", layout="centered")
st.title("📤 Shift → Google Calendar")

if login():
    creds = creds_from_dict(st.session_state["creds"])
    st.success("Signed in!")

    file = st.file_uploader("Upload your PDF schedule", type="pdf")
    if file:
        with st.spinner("Reading PDF..."):
            shifts = parse_pdf(file.read())
        if not shifts:
            st.error("No shifts found. Check if ENTRADA/SORTIDA columns are correctly labeled.")
        else:
            st.info(f"Found **{len(shifts)}** shifts. Preview:")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True)
            if st.button("Sync to Google Calendar"):
                with st.spinner("Syncing..."):
                    ins, upd, dele = sync_shifts(creds, shifts)
                st.success(f"✅ Inserted: {ins}, Updated: {upd}, Deleted: {dele}")
