"""SAMPRAAN welcome-hero role verification (UI-only, production build).

For each seeded role: real UI login -> workspace -> assert
  * "Welcome, <name>" hero (compact, not the old COMMAND CENTER hero)
  * correct role badge
  * role-specific quick actions
  * System/Security Status telemetry area present (data preserved)
  * no horizontal layout overflow
  * refresh preserves the session
  * logout works
and no console errors / failed requests for any role.

Usage: python scripts/e2e-welcome-roles.py [BASE]  (default http://127.0.0.1:8321)
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8321").rstrip("/")

ROLES = [
    ("admin@sampraan.dev", "SampraanAdmin#2026", "ADMIN",
     ["Users", "Assets", "Governance", "Audit"], "Dev Admin"),
    ("manager@sampraan.dev", "SampraanManager#2026", "MANAGER",
     ["Users", "Assets", "Mint Requests", "Transfers"], "Dev Manager"),
    ("auditor@sampraan.dev", "SampraanAuditor#2026", "AUDITOR",
     ["Verify", "Provenance", "Audit", "Disputes"], "Dev Auditor"),
    ("user@sampraan.dev", "SampraanUser#2026", "USER",
     ["My Assets", "Transfers", "DID & Security"], "Dev User"),
]

results = []
def check(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{' — ' + detail if detail else ''}")

def login(page, email, password):
    page.goto(BASE + "/?view=auth", wait_until="networkidle", timeout=60000)
    page.wait_for_timeout(700)
    for el in page.locator("input").all():
        t = (el.get_attribute("type") or "").lower()
        if t == "email":
            el.fill(email)
        elif t == "password":
            el.fill(password)
    page.locator('button[type=submit]').first.click()
    page.wait_for_timeout(2500)
    cont = page.locator('button:has-text("Continue as")')
    if cont.count():
        cont.first.click()
        page.wait_for_timeout(2500)

def logout(page):
    page.locator('.gov-logout').first.click()
    page.wait_for_timeout(1500)

def no_overflow(page):
    return page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    for email, password, role, actions, name in ROLES:
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        console_errors, failed_requests, page_errors = [], [], []
        page.on("pageerror", lambda e: page_errors.append(str(e)))
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
        page.on("requestfailed", lambda r: failed_requests.append(r.url))
        print(f"\n== {role} ({email}) ==")
        login(page, email, password)
        body = page.inner_text("body")

        check(f"{role}: compact welcome hero", "Welcome," in body and "COMMAND CENTER" not in body)
        check(f"{role}: welcome shows expected name", name.split()[0].lower() in body.lower())
        check(f"{role}: role badge", f"ROLE" not in body[:200] and role in body)
        for action in actions:
            check(f"{role}: action '{action}'", action in body)
        check(f"{role}: system/security status area", "SYSTEM / SECURITY STATUS" in body)
        check(f"{role}: telemetry preserved (identities/assets/audit/block)",
              any(k in body for k in ["REGISTERED"]) and any(k in body for k in ["ASSETS", "BLOCK"]))
        check(f"{role}: no horizontal overflow", no_overflow(page))
        page.reload(wait_until="networkidle"); page.wait_for_timeout(1200)
        check(f"{role}: refresh keeps session + hero", "Welcome," in page.inner_text("body"))
        # role-specific quick action navigates for real
        first = page.locator(".welcome-action").first
        first.click(); page.wait_for_timeout(1200)
        check(f"{role}: quick action navigates (page heading changes)",
              page.locator(".special-heading").count() > 0 or "Welcome," not in page.inner_text("body"))
        page.goto(BASE + "/", wait_until="networkidle"); page.wait_for_timeout(800)
        logout(page)
        check(f"{role}: logout returns to public site", "Sign In" in page.inner_text("body"))
        check(f"{role}: no page errors", not page_errors, "; ".join(page_errors[:2]))
        check(f"{role}: no console errors", not console_errors, "; ".join(console_errors[:2]))
        real = [f for f in failed_requests if "favicon" not in f]
        check(f"{role}: no failed requests", not real, "; ".join(real[:2]))
        ctx.close()
    browser.close()

fails = [r for r in results if not r[1]]
print(f"\nWELCOME-ROLE E2E: {len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
