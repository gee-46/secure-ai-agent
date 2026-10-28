"""Shared CSS for the dashboard's dark navy / cyan security theme."""

CUSTOM_CSS = """
<style>
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}
section[data-testid="stSidebar"] {
    background-color: #0f172a;
    border-right: 1px solid #1e293b;
}
h1, h2, h3, h4 {
    color: #e2e8f0 !important;
    font-weight: 600 !important;
}
.ppaa-card {
    background-color: #111827;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 14px;
}
.ppaa-metric {
    background-color: #111827;
    border: 1px solid #164e63;
    border-left: 4px solid #22d3ee;
    border-radius: 8px;
    padding: 14px 18px;
}
.ppaa-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.02em;
}
.badge-public { background-color: #064e3b; color: #6ee7b7; }
.badge-confidential { background-color: #78350f; color: #fcd34d; }
.badge-highly { background-color: #7f1d1d; color: #fca5a5; }
.badge-success { background-color: #064e3b; color: #6ee7b7; }
.badge-denied { background-color: #7f1d1d; color: #fca5a5; }
.ppaa-divider {
    border-top: 1px solid #1e293b;
    margin: 18px 0;
}
.stButton>button {
    background-color: #0891b2;
    color: #f0fdfa;
    border: none;
    border-radius: 6px;
    font-weight: 600;
}
.stButton>button:hover {
    background-color: #06b6d4;
    color: #022c22;
}
code {
    color: #67e8f9 !important;
}
</style>
"""


def badge(label: str) -> str:
    css_class = {
        "Public": "badge-public",
        "Confidential": "badge-confidential",
        "Highly Confidential": "badge-highly",
        "SUCCESS": "badge-success",
        "DENIED": "badge-denied",
        "FAILURE": "badge-denied",
    }.get(label, "badge-confidential")
    return f'<span class="ppaa-badge {css_class}">{label}</span>'
