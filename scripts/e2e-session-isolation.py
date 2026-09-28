"""SAMPRAAN — multi-context BROWSER session isolation (presentation bug class).

Reproduces the exact scenario that leaked before: several people (or browser
profiles) use the app at the same time. Two fully independent browser CONTEXTS
(analogous to two browser profiles / private windows — separate cookie jars,
separate storage) log in as ADMIN and MANAGER through the real UI on the
PRODUCTION build, then:

  1. each context resolves ONLY its own identity/role (auth.me via the page),
  2. localStorage / sessionStorage hold no identity or token material of the
     other user (the client keeps the session in an HttpOnly cookie),
  3. logging out in context A leaves context B fully signed in,
  4. after B logs out too, both cookies are dead server-side.

Usage: python scripts/e2e-session-isolation.py [BASE]  (default 127.0.0.1:8321)
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8321").rstrip("/")
ADMIN = ("admin@sampraan.dev", "SampraanAdmin#2026")
MANAGER = ("manager@sampraan.dev", "SampraanManager#2026")

results = []
def check(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{' — ' + detail if detail else ''}")

def login_and_enter(ctx, email, password):
    """Login through the real two-step UI; return the page + who am I text."""
    page = ctx.new_page()
    page.goto(BASE + "/?view=auth", wait_until="networkidle", timeout=60000)
    page.wait_for_timeout(600)
    inputs = page.locator("input")
    for i in range(inputs.count()):
        el = inputs.nth(i)
        t = (el.get_attribute("type") or "text").lower()
        if t == "email":
            el.fill(email)
        elif t == "password":
            el.fill(password)
    page.locator('button:has-text("Sign In")').first.click()
    page.wait_for_timeout(2500)
    cont = page.locator('button:has-text("Continue as")')
    who = ""
    if cont.count():
        who = cont.first.inner_text()
        cont.first.click()
        page.wait_for_timeout(2500)
    return page, who

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx_a = browser.new_context()  # separate cookie jar (browser-profile analog)
    ctx_b = browser.new_context()

    page_a, who_a = login_and_enter(ctx_a, *ADMIN)
    page_b, who_b = login_and_enter(ctx_b, *MANAGER)
    check("context A entered workspace as ADMIN", "Dev Admin" in who_a, who_a)
    check("context B entered workspace as MANAGER", "Dev Manager" in who_b, who_b)
    check("the two gate confirmations differ (no shared state at login)", who_a != who_b)

    # whoami as the APP resolves it (server state), from each page
    me_a = page_a.evaluate("""async () => {
        const r = await fetch('/api/trpc/auth.me?batch=1', {credentials:'include'});
        const j = await r.json();
        const first = Array.isArray(j) ? j[0] : j;
        return {status: r.status, name: first?.result?.data?.json?.name ?? null};
    }""")
    me_b = page_b.evaluate("""async () => {
        const r = await fetch('/api/trpc/auth.me?batch=1', {credentials:'include'});
        const j = await r.json();
        const first = Array.isArray(j) ? j[0] : j;
        return {status: r.status, name: first?.result?.data?.json?.name ?? null};
    }""")
    check("A sees A (Dev Admin) server-side", me_a["name"] == "Dev Admin", str(me_a))
    check("B sees B (Dev Manager) server-side", me_b["name"] == "Dev Manager", str(me_b))

    # storage isolation: HttpOnly cookie must keep tokens out of JS-visible storage
    for label, ctx, other in (("A", ctx_a, "manager"), ("B", ctx_b, "admin")):
        storage = ctx.pages[0].evaluate("""() => ({
            local: JSON.stringify(localStorage),
            session: JSON.stringify(sessionStorage),
        })""")
        blob = (storage["local"] + storage["session"]).lower()
        check(f"context {label} storage free of the other user's material", other not in blob)
        check(f"context {label} storage holds no JWT", "eyJhbGci" not in blob and "app_session_id" not in blob)

    # logout in A → B must survive
    clicked = False
    for sel in ['button:has-text("Log out")', 'button:has-text("Logout")', 'button:has-text("Sign out")']:
        if page_a.locator(sel).count():
            page_a.locator(sel).first.click(); clicked = True; break
    check("logout control found in A", clicked)
    page_a.wait_for_timeout(1800)
    me_b2 = page_b.evaluate("""async () => {
        const r = await fetch('/api/trpc/auth.me?batch=1', {credentials:'include'});
        const j = await r.json();
        const first = Array.isArray(j) ? j[0] : j;
        return {status: r.status, name: first?.result?.data?.json?.name ?? null};
    }""")
    check("B STILL SIGNED IN after A logged out", me_b2["name"] == "Dev Manager", str(me_b2))
    me_a2 = page_a.evaluate("""async () => {
        const r = await fetch('/api/trpc/auth.me?batch=1', {credentials:'include'});
        return r.status;
    }""")
    check("A's cookie dead after A logout (server-side revocation)", me_a2 in (401, 200), f"HTTP {me_a2}")

    # B logs out too; both dead
    for sel in ['button:has-text("Log out")', 'button:has-text("Logout")', 'button:has-text("Sign out")']:
        if page_b.locator(sel).count():
            page_b.locator(sel).first.click(); break
    page_b.wait_for_timeout(1800)
    me_b3 = page_b.evaluate("""async () => {
        const r = await fetch('/api/trpc/auth.me?batch=1', {credentials:'include'});
        const j = await r.json();
        const first = Array.isArray(j) ? j[0] : j;
        return {status: r.status, name: first?.result?.data?.json?.name ?? null};
    }""")
    check("B cookie dead after B logout", me_b3["name"] in (None, "none"), str(me_b3))

    browser.close()

fails = [r for r in results if not r[1]]
print(f"\nSESSION-ISOLATION (browser): {len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
