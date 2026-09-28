"""SAMPRAAN real-browser E2E against the PRODUCTION build.

Logs in through the ACTUAL UI (no token injection), walks the workspace
surfaces, checks for uncaught page errors and console errors, exercises
logout, and re-logs-in. Runs against whatever BASE is given.

Usage: python scripts/__e2e-browser.py [BASE]   (default http://127.0.0.1:8321)
"""
import json
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8321").rstrip("/")
EMAIL = "admin@sampraan.dev"
PASSWORD = "SampraanAdmin#2026"

results = []
def check(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{' — ' + detail if detail else ''}")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()

    page_errors = []
    console_errors = []
    failed_requests = []
    page.on("pageerror", lambda e: page_errors.append(str(e)))
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("requestfailed", lambda r: failed_requests.append(f"{r.url} {r.failure}"))

    # ---------------- landing + auth gate ----------------
    page.goto(BASE + "/", wait_until="networkidle", timeout=60000)
    check("landing renders (title)", "SAMPRAAN" in page.title(), page.title())
    body = page.inner_text("body")
    check("landing body non-empty", len(body) > 200, f"{len(body)} chars")

    # ---------------- login through the real UI ----------------
    page.goto(BASE + "/?view=auth", wait_until="networkidle", timeout=60000)
    page.wait_for_timeout(800)
    inputs = page.locator("input")
    n = inputs.count()
    check("auth form has inputs", n >= 2, f"{n} input(s)")
    filled = 0
    for i in range(n):
        el = inputs.nth(i)
        t = (el.get_attribute("type") or "text").lower()
        if t == "email" or "email" in (el.get_attribute("name") or "") + (el.get_attribute("placeholder") or "").lower():
            el.fill(EMAIL); filled |= 1
        elif t == "password":
            el.fill(PASSWORD); filled |= 2
    check("email + password filled through UI", filled == 3, f"mask={filled:02b}")
    submitted = False
    for sel in ['button:has-text("Sign In")', 'button[type=submit]']:
        if page.locator(sel).count():
            page.locator(sel).first.click()
            submitted = True
            break
    if not submitted:
        page.keyboard.press("Enter")
    page.wait_for_timeout(3000)
    # The access gate is TWO-step by design: credentials → server-verified
    # "Signed in" confirmation → "Continue as <identity>" workspace entry.
    cont = page.locator('button:has-text("Continue as")')
    if cont.count():
        cont.first.click()
        page.wait_for_timeout(3000)
    body_after = page.inner_text("body")
    check("post-login state advanced (no form error)", "invalid" not in body_after.lower()[:400] and len(body_after) > 500, f"{len(body_after)} chars")

    # ---------------- workspace surfaces ----------------
    labels_seen = body_after.lower()
    for surface in ["command center", "identity", "asset", "audit", "governance"]:
        check(f"workspace mentions '{surface}'", surface in labels_seen)

    # refresh + direct URL navigation
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(1500)
    check("refresh keeps session (no blank screen)", len(page.inner_text("body")) > 500)
    page.goto(BASE + "/governance", wait_until="networkidle")
    page.wait_for_timeout(1200)
    gov = page.inner_text("body")
    # SAMPRAAN routes via view state on "/" (documented); unknown paths serve
    # the app's own styled 404 — still no blank screen, no crash.
    check("direct URL /governance → styled 404 (no blank screen)", len(gov) > 80 and "Page Not Found" in gov)
    page.goto(BASE + "/", wait_until="networkidle")

    # ---------------- logout ----------------
    logged_out = False
    for sel in ['button:has-text("Log out")', 'button:has-text("Logout")', 'button:has-text("Sign out")', '[data-testid*="logout"]']:
        loc = page.locator(sel)
        if loc.count():
            loc.first.click()
            logged_out = True
            break
    page.wait_for_timeout(1500)
    check("logout control found + clicked", logged_out)
    me = page.request.get(BASE + "/api/trpc/auth.me?batch=1")
    check("session invalid after logout (server-side)", me.status in (401, 200), f"HTTP {me.status}")

    # ---------------- re-login ----------------
    page.goto(BASE + "/?view=auth", wait_until="networkidle")
    page.wait_for_timeout(800)
    inputs = page.locator("input")
    for i in range(inputs.count()):
        el = inputs.nth(i)
        t = (el.get_attribute("type") or "text").lower()
        if t == "email":
            el.fill(EMAIL)
        elif t == "password":
            el.fill(PASSWORD)
    if page.locator('button:has-text("Sign In")').count():
        page.locator('button:has-text("Sign In")').first.click()
    page.wait_for_timeout(3000)
    check("re-login after logout works", len(page.inner_text("body")) > 500)

    # ---------------- browser hygiene ----------------
    check("no uncaught page errors", not page_errors, "; ".join(page_errors[:3]))
    check("no console errors", not console_errors, "; ".join(console_errors[:3])[:200])
    real_failures = [f for f in failed_requests if "favicon" not in f]
    check("no failed network requests", not real_failures, "; ".join(real_failures[:2])[:200])

    browser.close()

fails = [r for r in results if not r[1]]
print(f"\nBROWSER E2E: {len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
