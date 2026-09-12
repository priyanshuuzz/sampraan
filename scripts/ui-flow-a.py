"""SAMPRAAN Flow A end-to-end UI proof (BUG-018 + BUG-032).

Phase 1: with the admin already the on-chain custodian, evaluate a transfer
  in the UI -> the CHAIN ANCHOR panel must say ALREADY IN CUSTODY (not
  a 502 error, and not OFF CHAIN).
Phase 2: (driven externally) reset on-chain custody.
Phase 3: evaluate again -> the panel must show the REAL tx hash + block.
Usage: python ui-flow-a.py <token-file> <phase1|phase3>
"""
import json
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3000"
PHASE = sys.argv[2] if len(sys.argv) > 2 else "phase1"

with open(sys.argv[1], "r", encoding="utf-8-sig") as f:
    admin = json.load(f)
token = admin["token"]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context()
    page = ctx.new_page()
    page.add_init_script(
        f"sessionStorage.setItem('sampraan-session', {json.dumps('app_session_id=' + token)});"
    )
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(BASE + "/?view=workspace", wait_until="networkidle", timeout=60000)
    page.wait_for_timeout(2500)

    page.click("text=\"Access Control\"", timeout=8000)
    page.wait_for_timeout(2000)
    page.click("text=\"EVALUATE VIA BACKEND\"", timeout=8000)
    page.wait_for_timeout(7000)  # chain read / confirmation

    body = page.inner_text("body")
    idx = body.find("CHAIN ANCHOR")
    if idx < 0:
        print("CHAIN ANCHOR panel missing")
        print(body[:1500])
        sys.exit(1)
    panel = body[idx:idx + 240]
    print("=== CHAIN ANCHOR panel ===")
    print(panel)

    if PHASE == "phase1":
        ok = "ALREADY IN CUSTODY" in panel
        print("PHASE1 RESULT:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)

    # phase3: expect a real hash
    ok = "0x" in panel and "/ #" in panel and "OFF CHAIN" not in panel and "ALREADY" not in panel
    # decision line for cross-check
    dIdx = body.find("FINAL DECISION")
    print(body[dIdx:dIdx + 120] if dIdx >= 0 else "(no decision panel)")
    print("PHASE3 RESULT:", "PASS" if ok else "FAIL")

    print("=== page errors ===")
    for e in errors[:5]:
        print("PAGEERROR:", e[:200])
    if not errors:
        print("none")
    browser.close()
print("DONE")
