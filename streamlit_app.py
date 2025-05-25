import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from dateutil.parser import parse as dtparse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError
import traceback

SCOPES = ["https://www.googleapis.com/auth/calendar.events"]

CLIENT_ID     = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI  = st.secrets["google"]["redirect_uri"]

def get_flow(state: str | None = None):
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
    return flow

def creds_from_dict(data):
    return Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        scopes=data.get("scopes"),
    )

def login():
    query_params = st.query_params
    if "creds" in st.session_state and st.session_state["creds"]:
        creds = creds_from_dict(st.session_state["creds"])
        if creds and creds.valid:
            return True

    if "code" in query_params:
        code = query_params["code"][0]
        state = st.session_state.get("oauth_state")
        try:
            flow = get_flow(state=state)
            flow.fetch_token(code=code)
            creds = flow.credentials
            st.session_state["creds"] = {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": creds.token_uri,
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scopes": creds.scopes,
            }
            st.query_params.clear()
            return True
        except Exception as e:
            st.error(f"OAuth Error: {e}")
            st.query_params.clear()
            return False

    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true"
    )
    st.session_state["oauth_state"] = state
    st.markdown(f"[**Sign in with Google**]({auth_url})", unsafe_allow_html=True)
    return False

def parse_pdf(file_bytes):
    shifts = []
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            year_match = re.search(r"(\d{4})", pdf.metadata.get("Title", ""))
            year = int(year_match.group(1)) if year_match else dt.datetime.now().year
            for page_num, page in enumerate(pdf.pages, start=1):
                table = page.extract_table()
                if not table: continue
                df = pd.DataFrame(table[1:], columns=table[0])
                if "Entrada" not in df.columns or "Sortida" not in df.columns:
                    continue
                for col_name in df.columns[1:]:
                    day_str = str(df.iloc[0][col_name]).strip()
                    if not day_str.isdigit(): continue
                    try:
                        date = dt.date(year, page_num, int(day_str))
                    except ValueError:
                        continue
                    start_val = df.loc[df["Entrada"] == "Entrada", col_name].values
                    end_val   = df.loc[df["Sortida"] == "Sortida", col_name].values
                    if start_val.size == 0 or end_val.size == 0:
                        continue
                    start = str(start_val[0]).strip()
                    end   = str(end_val[0]).strip()
                    if re.fullmatch(r"\d{1,2}:\d{2}", start) and re.fullmatch(r"\d{1,2}:\d{2}", end):
                        key = f"{date:%Y%m%d}-{start.replace(':','')}"
                        shifts.append({"key": key, "date": date.isoformat(), "start": start, "end": end})
        return shifts
    except Exception as e:
        st.error(f"PDF Parse Error: {e}")
        return []

def sync_shifts(creds, shifts, tz="Europe/Madrid"):
    try:
        service = build("calendar", "v3", credentials=creds, cache_discovery=False)
        now = dt.datetime.utcnow().isoformat() + "Z"
        existing = service.events().list(
            calendarId="primary",
            timeMin=now,
            privateExtendedProperty="shiftUploader=1"
        ).execute().get("items", [])
        by_key = {}
        for e in existing:
            key = e.get("extendedProperties", {}).get("private", {}).get("key")
            if key:
                by_key[key] = e

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
    except Exception as e:
        st.error(f"Calendar sync error: {e}")
        return 0, 0, 0

# ---------- Streamlit UI ----------

st.set_page_config(page_title="Shift Uploader", page_icon="🗓️", layout="centered")
st.title("📤 Shift → Google Calendar")

if "creds" not in st.session_state:
    st.session_state["creds"] = None

if login():
    creds = creds_from_dict(st.session_state["creds"])

    file = st.file_uploader("Upload your PDF schedule", type="pdf")
    if file:
        with st.spinner("Reading your PDF..."):
            shifts = parse_pdf(file.read())
        if not shifts:
            st.error("No shifts found. Make sure 'Entrada' and 'Sortida' rows are present.")
        else:
            st.info(f"Found {len(shifts)} shifts. Preview:")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True)
            st.write("---")
            if st.button("Sync to Google Calendar"):
                with st.spinner("Syncing..."):
                    ins, upd, dele = sync_shifts(creds, shifts)
                st.success(f"✅ Done: {ins} inserted, {upd} updated, {dele} deleted.")
else:
    st.info("Sign in to upload and sync your shifts.")
