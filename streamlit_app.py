import io, re, datetime as dt
import streamlit as st
import pdfplumber, pandas as pd
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# ---------- CONFIG ----------
SCOPES = ["https://www.googleapis.com/auth/calendar.events"]
CLIENT_ID     = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI  = st.secrets["google"]["redirect_uri"]

# ---------- OAUTH FLOW ----------
def make_flow(state=None):
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

def creds_from_dict(d): return Credentials(**d) if d else None

# ---------- LOGIN ----------
def google_login():
    q = st.query_params
    # 1. Already signed in
    if "creds" in st.session_state:
        if creds_from_dict(st.session_state["creds"]).valid:
            return True

    # 2. Return from Google with ?code=
    if "code" in q and not st.session_state.get("auth_code_handled"):
        st.session_state["auth_code_handled"] = True  # prevent re-use
        code = q["code"][0]
        state = st.session_state.get("oauth_state")
        try:
            flow = make_flow(state)
            flow.fetch_token(code=code)
            c = flow.credentials
            st.session_state["creds"] = {
                "token": c.token,
                "refresh_token": c.refresh_token,
                "token_uri": c.token_uri,
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "scopes": c.scopes,
            }
            st.query_params.clear()
            return True
        except Exception as e:
            st.error(f"OAuth error: {e}")
            st.query_params.clear()
            return False

    # 3. Start login
    flow = make_flow()
    auth_url, state = flow.authorization_url(
        access_type="offline", prompt="consent", include_granted_scopes="true"
    )
    st.session_state["oauth_state"] = state
    st.markdown(f"[**Sign in with Google**]({auth_url})", unsafe_allow_html=True)
    return False

# ---------- PDF PARSER ----------
def parse_pdf(data):
    shifts = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        year = int(re.search(r"\d{4}", pdf.metadata.get("Title", "2025")).group(0))
        for p, page in enumerate(pdf.pages, 1):
            table = page.extract_table()
            if not table: continue
            df = pd.DataFrame(table[1:], columns=table[0])
            if "Entrada" not in df or "Sortida" not in df: continue
            for col in df.columns[1:]:
                d = str(df.iloc[0][col]).strip()
                if not d.isdigit(): continue
                try: date = dt.date(year, p, int(d))
                except: continue
                s = df.loc[df["Entrada"] == "Entrada", col].values
                e = df.loc[df["Sortida"] == "Sortida", col].values
                if s.size and e.size and re.fullmatch(r"\d{1,2}:\d{2}", s[0]) and re.fullmatch(r"\d{1,2}:\d{2}", e[0]):
                    key = f"{date:%Y%m%d}-{s[0].replace(':','')}"
                    shifts.append({"key": key, "date": date.isoformat(), "start": s[0], "end": e[0]})
    return shifts

# ---------- CALENDAR SYNC ----------
def sync(creds, shifts, tz="Europe/Madrid"):
    service = build("calendar", "v3", credentials=creds, cache_discovery=False)
    now = dt.datetime.utcnow().isoformat() + "Z"
    existing = service.events().list(
        calendarId="primary",
        timeMin=now,
        privateExtendedProperty="shiftUploader=1"
    ).execute().get("items", [])
    by_key = {e["extendedProperties"]["private"]["key"]: e for e in existing if "extendedProperties" in e}
    ins = upd = dele = 0
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
            service.events().patch(calendarId="primary", eventId=by_key[s["key"]]["id"], body=body).execute()
            upd += 1
            del by_key[s["key"]]
        else:
            service.events().insert(calendarId="primary", body=body).execute()
            ins += 1
    for e in by_key.values():
        service.events().delete(calendarId="primary", eventId=e["id"]).execute()
        dele += 1
    return ins, upd, dele

# ---------- STREAMLIT UI ----------
st.set_page_config("Shift Uploader", "📅", layout="centered")
st.title("📤 Shift → Google Calendar")

if "creds" not in st.session_state:
    st.session_state["creds"] = None

if google_login():
    creds = creds_from_dict(st.session_state["creds"])
    pdf = st.file_uploader("Upload PDF with Entrada/Sortida schedule", type="pdf")
    if pdf:
        with st.spinner("Parsing PDF..."):
            shifts = parse_pdf(pdf.read())
        if not shifts:
            st.error("No shifts found. Ensure correct Entrada/Sortida structure.")
        else:
            st.success(f"Parsed {len(shifts)} shifts.")
            st.dataframe(pd.DataFrame(shifts), use_container_width=True)
            if st.button("Sync to Calendar"):
                with st.spinner("Syncing to Google Calendar..."):
                    i, u, d = sync(creds, shifts)
                st.success(f"✅ Done. Inserted {i}, updated {u}, deleted {d}.")
else:
    st.info("Sign in to continue.")
