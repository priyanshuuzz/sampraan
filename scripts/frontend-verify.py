"""SAMPRAAN workspace verification: enter the secure workspace and check pages."""
import json
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3000"

with open(sys.argv[1], "r", encoding="utf-8-sig") as f:
    admin = json.load(f)
token = admin["token"]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context()
    page = ctx.new_page()
    # The client expects a cookie-pair string: app_session_id=<token>
    cookie_value = f"app_session_id={token}"
    page.add_init_script(
        f"sessionStorage.setItem('sampraan-session', {json.dumps(cookie_value)});"
    )
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(BASE + "/?view=workspace", wait_until="networkidle", timeout=60000)
    print("landing title:", page.title())
    page.wait_for_timeout(2500)
    print("workspace url:", page.url)

    print("workspace url:", page.url)
    body = page.inner_text("body")
    print("body length:", len(body))

    # Workspace nav
    labels = page.eval_on_selector_all(
        "nav a, nav button, aside a, aside button, [role=navigation] *, button",
        "els => els.map(e => (e.textContent || '').trim()).filter(t => t && t.length < 40)",
    )
    print("workspace nav labels:", labels[:40])

    for label in ["Command Center", "Identity", "Access Control", "Assets", "Audit Evidence", "Intelligence", "Alerts", "Administration", "Settings"]:
        try:
            page.click(f"text=\"{label}\"", timeout=4000)
            page.wait_for_timeout(1500)
            txt = page.inner_text("body")
            print(f"PAGE '{label}': {len(txt)} chars")
        except Exception:
            print(f"PAGE '{label}': not found/click failed")

    # Deep-verify the two evidence-critical pages
    print("=== AUDIT EVIDENCE page content ===")
    try:
        page.click("text=\"Audit Evidence\"", timeout=4000)
        page.wait_for_timeout(2000)
        audit_txt = page.inner_text("body")
        print(audit_txt[400:2400])
    except Exception as e:
        print("audit page failed:", e)

    print("=== ASSETS page content ===")
    try:
        page.click("text=\"Assets\"", timeout=4000)
        page.wait_for_timeout(2000)
        assets_txt = page.inner_text("body")
        print(assets_txt[400:1600])
    except Exception as e:
        print("assets page failed:", e)

    print("=== page errors ===")
    for e in errors[:10]:
        print("PAGEERROR:", e[:200])
    if not errors:
        print("none")
    browser.close()
print("DONE")
