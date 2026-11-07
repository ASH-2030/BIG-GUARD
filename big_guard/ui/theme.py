"""Dark SOC theme (palette carried over from the v1.1 dashboard)."""

COLORS = {
    "bg": "#0b1220", "panel": "#101b2b", "border": "#263b55", "text": "#e8eef8", "muted": "#91a6c0",
    "teal": "#2dd4bf", "blue": "#3b82f6", "red": "#fb7185", "amber": "#fbbf24", "violet": "#a78bfa",
    "green": "#34d399", "grid": "#1f3049",
}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: radial-gradient(circle at 15% 0%, #14243b 0, #0b1220 38%, #080d17 100%); color: #e8eef8; }
[data-testid="stHeader"] { background: transparent; }
footer { visibility: hidden; height: 0; }
.block-container { padding-top: 1.4rem; padding-bottom: 1.5rem; max-width: 1500px; }
[data-testid="stSidebar"] { background: #0c1524; border-right: 1px solid #203149; }
[data-testid="stSidebar"] .block-container { padding-top: 1rem; }
[data-testid="stSidebar"] [role="radiogroup"] { gap: 2px; }
[data-testid="stSidebar"] [role="radiogroup"] label { padding: 7px 10px; border-radius: 9px; width: 100%; }
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: #14243a; }
.brand { font-size: 20px; font-weight: 800; color: #f8fbff; letter-spacing: .5px; }
.brand-sub { color: #5eead4; font-size: 10px; letter-spacing: 2px; font-weight: 700; margin-bottom: 8px; }
.hero { padding: 22px 28px; border: 1px solid #263b58; border-radius: 18px;
        background: linear-gradient(120deg, rgba(23,48,78,.95), rgba(15,27,45,.92));
        box-shadow: 0 12px 35px rgba(0,0,0,.22); margin-bottom: 16px; }
.hero-kicker { color: #5eead4; text-transform: uppercase; letter-spacing: 2px; font-size: 11px; font-weight: 800; }
.hero h1 { color: #f8fbff; font-size: 30px; margin: 6px 0 4px; font-weight: 800; padding: 0; }
.hero p { color: #a9bad0; margin: 0; font-size: 14px; }
.section-title { color: #e7efff; font-size: 17px; font-weight: 700; margin: 14px 0 8px; }
.metric-card { background: linear-gradient(145deg,#14243a,#101b2b); border: 1px solid #263b55; border-radius: 14px;
               padding: 14px 16px; min-height: 100px; border-top: 3px solid var(--accent, #2dd4bf); }
.metric-label { color: #91a6c0; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }
.metric-value { color: #f5f9ff; font-size: 28px; font-weight: 800; margin-top: 6px; line-height: 1.1; }
.metric-note { color: #8fa4bd; font-size: 11px; margin-top: 4px; }
.callout { border-radius: 10px; padding: 10px 14px; margin: 6px 0 12px; font-size: 13px; border: 1px solid; }
.callout.info { background: rgba(59,130,246,.10); border-color: #2b4f86; color: #bcd3f5; }
.callout.warn { background: rgba(251,191,36,.09); border-color: #6b5a22; color: #f3dfa0; }
.callout.ok { background: rgba(45,212,191,.09); border-color: #1f6b62; color: #aef0e6; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; border: 1px solid; }
.alert-card { border-left: 4px solid var(--sev, #fbbf24); background: #131f31; border-radius: 10px; padding: 10px 14px; margin: 7px 0; }
.alert-card .meta { color: #91a6c0; font-size: 12px; }
.small-muted { color: #91a6c0; font-size: 12px; }
[data-testid="stVerticalBlockBorderWrapper"] { border-color: #263b55 !important; border-radius: 14px; background: rgba(16,28,45,.55); }
div.stButton > button, div.stDownloadButton > button { border-radius: 10px; border: 1px solid #345274; font-weight: 700; }
[data-testid="stDataFrame"] { border: 1px solid #263b55; border-radius: 12px; overflow: hidden; }
.stTabs [data-baseweb="tab"] { color: #a9bad0; font-weight: 700; }
.stTabs [aria-selected="true"] { color: #5eead4 !important; }
hr { border-color: #263b55; margin: .8rem 0; }
</style>
"""
