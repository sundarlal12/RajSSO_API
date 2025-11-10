#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uuid, base64, traceback, logging

# -------------------- Standard / Third-party imports --------------------
from bs4 import BeautifulSoup       # pip install beautifulsoup4
from urllib.parse import urljoin, quote
from html import unescape
from pathlib import Path
from typing import Optional, Any, Dict, List

import json
import re
import io
import time
import math
import base64
import requests

from Crypto.Cipher import AES
from PIL import Image, ImageOps, ImageFilter, ImageEnhance

try:
    import pytesseract
except Exception:
    pytesseract = None  # not required for /api endpoints

# --- Optional captcha solver (do not block app startup if missing) ---
try:
    from xapacthaslowve import XCaptchaSolver
except Exception:
    class XCaptchaSolver:  # safe stub
        def __init__(self, *args, **kwargs):
            pass
        def solve_from_url(self, *args, **kwargs):
            return None


# --- Optional captcha solver (don’t block startup if missing) ---
try:
    from xapacthaslowve import XCaptchaSolver
except Exception:
    class XCaptchaSolver:
        def __init__(self, *args, **kwargs): ...
        def solve_from_url(self, *args, **kwargs): return None



try:
    from Crypto.Cipher import AES   # pycryptodome
except Exception:
    AES = None

# Pillow
try:
    from PIL import Image, ImageOps, ImageFilter, ImageEnhance
except Exception:
    Image = ImageOps = ImageFilter = ImageEnhance = None

# Optional OpenCV
try:
    import cv2, numpy as np
    _HAS_CV2 = True
except Exception:
    _HAS_CV2 = False

# Your in-house captcha solver module
from xapacthaslowve import XCaptchaSolver   # ensure this file is importable

# -------------------- RajasthanSSOComplete (your class) --------------------
class RajasthanSSOComplete:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://sso.rajasthan.gov.in"
        self.login_url = f"{self.base_url}/signin"
        self.captcha_url = f"{self.base_url}/SSOCaptchaHandler.ashx"

        # Use your solver (disabled saving/logging by default)
        self.xsolver = XCaptchaSolver(save_images=False, verbose=False)

        # ⚠️ Replace with real creds; API will override these at runtime
        self.username = "RAM.DEV.RVUN"
        self.password = "123456"

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': self.login_url,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': self.base_url,
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Te': 'trailers',
            'Connection': 'keep-alive'
        }

    # -------------------- RP helpers --------------------
    def _rp_headers(self):
        return {k: v for k, v in self.headers.items() if k.lower() != "cookie"}

    def _collect_rp_cookies(self):
        jar = {}
        for c in self.session.cookies:
            if "rajerp.discoms.rajasthan.gov.in" in c.domain:
                jar[c.name] = c.value
        return jar

    def rp_fetch_my_salary(self):
        """
        Fetch the 'My Salary' page, parse the target table and extract all rows and any links.
        Returns:
          {
            "source_url": ...,
            "headers": [...],
            "rows": [
              { "cells": [...], "links": [{"text":..., "href":...}], "mapped": {...optional...} },
              ...
            ],
            "rp_cookies": {...}
          }
        """
        url = "https://rajerp.discoms.rajasthan.gov.in/HRM/SalaryProcess/MySalary"
        headers = self._rp_headers()
        headers["Referer"] = "https://rajerp.discoms.rajasthan.gov.in/SSOIndex.aspx"

        r = self.session.get(url, headers=headers, allow_redirects=True)
        if r.status_code != 200:
            return None

        with open("mysalary.html", "w", encoding="utf-8") as f:
            f.write(r.text)

        soup = BeautifulSoup(r.text, "html.parser")
        table = soup.select_one("table.table.table-vertical-center.table-thead-simple.margin-none")
        if not table:
            return None

        headers_row: List[str] = []
        thead = table.find("thead")
        if thead:
            ths = thead.find_all("th")
            headers_row = [th.get_text(strip=True) for th in ths]

        tbody = table.find("tbody") or table
        rows: List[Dict[str, Any]] = []
        for tr in tbody.find_all("tr"):
            tds = tr.find_all(["td", "th"])
            cell_texts = [td.get_text(" ", strip=True) for td in tds]

            links = []
            for a in tr.find_all("a", href=True):
                links.append({
                    "text": a.get_text(" ", strip=True),
                    "href": urljoin(url, a["href"])
                })

            row_obj: Dict[str, Any] = {"cells": cell_texts, "links": links}
            if headers_row and len(headers_row) == len(cell_texts):
                row_obj["mapped"] = {headers_row[i]: cell_texts[i] for i in range(len(headers_row))}
            rows.append(row_obj)

        result = {
            "source_url": url,
            "headers": headers_row,
            "rows": rows,
            "rp_cookies": self._collect_rp_cookies()
        }

        # Print here only if you want CLI output; API will return JSON
        # print(json.dumps(result, indent=2, ensure_ascii=False))
        return result

    # -------------------- SSO helpers --------------------
    def _no_cookie_headers(self):
        return {k: v for k, v in self.headers.items() if k.lower() != "cookie"}

    def ensure_auth_cookies(self):
        # Ensure session cookies are present (if you persisted them externally)
        return

    def sso_get_form(self):
        import re
        url = f"{self.base_url}/sso"
        headers = {**self.headers, "Referer": f"{self.base_url}/signin"}
        r = self.session.get(url, headers=headers, allow_redirects=True)
        if r.status_code != 200:
            return None
        if "/signin" in r.url.lower():
            with open("sso_page.html", "w", encoding="utf-8") as f:
                f.write(r.text)
            return None

        html = r.text

        def _m(pat, default=None):
            m = re.search(pat, html)
            return m.group(1) if m else default

        tokens = {
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "__LASTFOCUS": "",
            "__VIEWSTATE": _m(r'name="__VIEWSTATE"[^>]*value="([^"]+)"'),
            "__VIEWSTATEGENERATOR": _m(r'name="__VIEWSTATEGENERATOR"[^>]*value="([^"]+)"', ""),
            "__VIEWSTATEENCRYPTED": _m(r'name="__VIEWSTATEENCRYPTED"[^>]*value="([^"]*)"', ""),
            "ctl00$__AntiXsrfToken": _m(r'name="ctl00\$__AntiXsrfToken"[^>]*value="([^"]+)"', ""),
            "ctl00$__AntiXsrfUserName": _m(r'name="ctl00\$__AntiXsrfUserName"[^>]*value="([^"]+)"', ""),
            "ctl00$cpBody$defaultApp": _m(r'name="ctl00\$cpBody\$defaultApp"[^>]*value="([^"]*)"', ""),
            "ctl00$cpBody$hf_AppName": _m(r'name="ctl00\$cpBody\$hf_AppName"[^>]*value="([^"]*)"', ""),
        }

        if not tokens["__VIEWSTATE"]:
            with open("sso_page.html", "w", encoding="utf-8") as f:
                f.write(html)
            return None

        candidates = []
        for m in re.finditer(r'name="(ctl00\$cpBody\$dlActiveApps\$ctl\d{2}\$LinkButton\d+)"', html):
            candidates.append({"target": m.group(1), "arg": ""})

        for m in re.finditer(r"__doPostBack\('([^']+)','([^']*)'\)", html):
            tgt, arg = m.group(1), m.group(2)
            candidates.append({"target": tgt, "arg": arg})

        seen = set()
        uniq = []
        for c in candidates:
            key = (c["target"], c["arg"])
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        candidates = uniq

        if not candidates:
            with open("sso_page.html", "w", encoding="utf-8") as f:
                f.write(html)

        return tokens, candidates

    def sso_post_select_app(self, tokens, target, arg=""):
        form = {
            "__EVENTTARGET": target,
            "__EVENTARGUMENT": arg or tokens.get("__EVENTARGUMENT", ""),
            "__LASTFOCUS": tokens.get("__LASTFOCUS", ""),
            "__VIEWSTATE": tokens["__VIEWSTATE"],
            "__VIEWSTATEGENERATOR": tokens.get("__VIEWSTATEGENERATOR", ""),
            "__VIEWSTATEENCRYPTED": tokens.get("__VIEWSTATEENCRYPTED", ""),
            "ctl00$__AntiXsrfToken": tokens.get("ctl00$__AntiXsrfToken", ""),
            "ctl00$__AntiXsrfUserName": tokens.get("ctl00$__AntiXsrfUserName", ""),
            "onoffswitch": "on",
            "ctl00$cpBody$defaultApp": tokens.get("ctl00$cpBody$defaultApp", ""),
            "ctl00$cpBody$hf_AppName": tokens.get("ctl00$cpBody$hf_AppName", ""),
        }
        headers = {**self.headers, "Referer": f"{self.base_url}/sso"}
        r = self.session.post(f"{self.base_url}/sso", data=form, headers=headers, allow_redirects=True)
        if r.status_code != 200:
            return None

        m = re.search(r"name=['\"]userdetails['\"][^>]*value=['\"]([^'\"]+)['\"]", r.text)
        if not m:
            with open("sso_post.html", "w", encoding="utf-8") as f:
                f.write(r.text)
            return None
        return m.group(1)

    def rp_post_userdetails(self, rp_url, userdetails):
        headers = {
            **self.headers,
            'Referer': f"{self.base_url}/",
            'Origin': self.base_url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {'userdetails': userdetails}
        r = self.session.post(rp_url, data=data, headers=headers, allow_redirects=True)
        return r

    def extract_all_values(self):
        response = self.session.get(self.login_url, headers=self.headers)
        if response.status_code != 200:
            return None

        html = response.text
        self.cookies = self.session.cookies.get_dict()

        results = {}
        key_match = re.search(r"var key\s*=\s*'([^']+)'", html)
        iv_match = re.search(r"var iv\s*=\s*'([^']+)'", html)
        if key_match and iv_match:
            results['encryption_key'] = key_match.group(1)
            results['encryption_iv'] = iv_match.group(1)
        else:
            return None

        m = re.search(r'name="__VIEWSTATE"[^>]*value="([^"]+)"', html)
        if m: results['__VIEWSTATE'] = m.group(1)

        m = re.search(r'name="__VIEWSTATEGENERATOR"[^>]*value="([^"]+)"', html)
        if m: results['__VIEWSTATEGENERATOR'] = m.group(1)

        m = re.search(r'name="ctl00\$ctl00\$__AntiXsrfToken"[^>]*value="([^"]+)"', html)
        if m: results['ctl00$ctl00$__AntiXsrfToken'] = m.group(1)

        m = re.search(r'name="__EVENTVALIDATION"[^>]*value="([^"]+)"', html)
        if m: results['__EVENTVALIDATION'] = m.group(1)

        results['__EVENTTARGET']   = ''
        results['__EVENTARGUMENT'] = ''
        results['__LASTFOCUS']     = ''

        m = re.search(r'name="([^"]*)"[^>]*id="[^"]*txt_Data1[^"]*"', html)
        results['username_field'] = m.group(1) if m else 'ctl00$ctl00$cpBodyMain$cpBody$txt_Data1'

        m = re.search(r'name="([^"]*)"[^>]*id="[^"]*txt_Data2[^"]*"', html)
        results['password_field'] = m.group(1) if m else 'ctl00$ctl00$cpBodyMain$cpBody$txt_Data2'

        m = re.search(r'name="([^"]*)"[^>]*id="[^"]*txtCaptcha[^"]*"', html)
        results['captcha_field'] = m.group(1) if m else 'ctl00$ctl00$cpBodyMain$cpBody$txtCaptcha'

        m = re.search(r'name="([^"]*)"[^>]*id="[^"]*cbx_newsession[^"]*"', html)
        results['checkbox_field'] = m.group(1) if m else 'ctl00$ctl00$cpBodyMain$cpBody$cbx_newsession'

        m = re.search(r'name="([^"]*)"[^>]*value="Login"', html)
        results['login_field'] = m.group(1) if m else 'ctl00$ctl00$cpBodyMain$cpBody$btn_Login'

        return results

    def get_captcha_automatically(self) -> Optional[str]:
        code = self.xsolver.solve_from_url(session=self.session, max_redownloads=5)
        if code and len(code) == 6 and code.isdigit():
            return code
        return None

    def aes_encrypt(self, plaintext, key, iv):
        try:
            key_bytes = key.encode('utf-8')
            iv_bytes = iv.encode('utf-8')
            pt = plaintext.encode('utf-8')
            pad_len = 16 - (len(pt) % 16)
            pt_padded = pt + bytes([pad_len]) * pad_len
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            enc_b64 = base64.b64encode(cipher.encrypt(pt_padded)).decode('utf-8')
            return enc_b64
        except Exception:
            return None

    def build_complete_request(self, captcha, extracted_data):
        enc_pwd = self.aes_encrypt(self.password, extracted_data['encryption_key'], extracted_data['encryption_iv'])
        if not enc_pwd:
            return None

        form_data = {
            '__EVENTTARGET': extracted_data['__EVENTTARGET'],
            '__EVENTARGUMENT': extracted_data['__EVENTARGUMENT'],
            '__LASTFOCUS': extracted_data['__LASTFOCUS'],
            '__VIEWSTATE': extracted_data['__VIEWSTATE'],
            '__VIEWSTATEGENERATOR': extracted_data['__VIEWSTATEGENERATOR'],
            'ctl00$ctl00$__AntiXsrfToken': extracted_data['ctl00$ctl00$__AntiXsrfToken'],
            'ctl00$ctl00$rbtnListLanguage': 'en-US',
            extracted_data['username_field']: self.username,
            extracted_data['password_field']: enc_pwd,
            extracted_data['captcha_field']: captcha,
            extracted_data['checkbox_field']: 'on',
            extracted_data['login_field']: 'Login'
        }
        if '__EVENTVALIDATION' in extracted_data:
            form_data['__EVENTVALIDATION'] = extracted_data['__EVENTVALIDATION']
        return form_data

    def send_login_request(self, form_data):
        try:
            post_headers = self.headers.copy()
            encoded = '&'.join([f"{k}={quote(str(v))}" for k, v in form_data.items()])
            post_headers['Content-Length'] = str(len(encoded))

            resp = self.session.post(
                self.login_url,
                data=form_data,
                headers=post_headers,
                allow_redirects=True
            )
            return resp
        except Exception:
            return None

    def _headers_no_cookie(self):
        return {k: v for k, v in self.headers.items() if k.lower() != "cookie"}

    def _extract_hidden_inputs(self, html: str) -> dict:
        fields = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            html, re.I
        ):
            name = unescape(m.group(1))
            val  = unescape(m.group(2))
            fields[name] = val

        if re.search(r'name=["\']onoffswitch["\']', html, re.I):
            fields['onoffswitch'] = 'on'

        for opt in ("ctl00$cpBody$defaultApp", "ctl00$cpBody$hf_AppName"):
            m = re.search(rf'name=["\']{re.escape(opt)}["\'][^>]*value=["\']([^"\']*)["\']', html, re.I)
            if m:
                fields[opt] = unescape(m.group(1))
        return fields

    def _find_eventtarget(self, html: str) -> Optional[str]:
        m = re.search(r'name=["\'](ctl00\$cpBody\$dlActiveApps\$ctl\d{2}\$LinkButton\d+)["\']', html, re.I)
        if m:
            return m.group(1)
        m = re.search(r"__doPostBack\('([^']+)','([^']*)'\)", html, re.I)
        if m:
            return m.group(1)
        return None

    def sso_get_userdetails_exact(self) -> Optional[str]:
        get_headers = self._headers_no_cookie()
        get_headers["Referer"] = f"{self.base_url}/signin"
        r = self.session.get(f"{self.base_url}/sso", headers=get_headers, allow_redirects=True)
        if r.status_code != 200 or "/signin" in r.url.lower():
            with open("sso_page.html", "w", encoding="utf-8") as f:
                f.write(r.text)
            return None

        html = r.text
        form = self._extract_hidden_inputs(html)
        if not form.get("__VIEWSTATE"):
            with open("sso_page.html", "w", encoding="utf-8") as f:
                f.write(html)
            return None

        evt = self._find_eventtarget(html)
        if not evt:
            evt = "ctl00$cpBody$dlActiveApps$ctl00$LinkButton1"

        form["__EVENTTARGET"]   = evt
        form["__EVENTARGUMENT"] = form.get("__EVENTARGUMENT", "")

        post_headers = self._headers_no_cookie()
        post_headers["Referer"] = f"{self.base_url}/sso"
        pr = self.session.post(f"{self.base_url}/sso", data=form, headers=post_headers, allow_redirects=True)
        if pr.status_code != 200:
            with open("sso_post.html", "w", encoding="utf-8") as f:
                f.write(pr.text)
            return None

        html_post = pr.text
        for pat in [
            r'name=["\']userdetails["\'][^>]*value=["\']([^"\']+)["\']',
            r'id=["\']userdetails["\'][^>]*value=["\']([^"\']+)["\']',
            r"<textarea[^>]*name=['\"]userdetails['\"][^>]*>([A-Za-z0-9+/=]+)</textarea>",
        ]:
            m = re.search(pat, html_post, re.I)
            if m:
                userdetails = m.group(1)
                with open("sso_post.html", "w", encoding="utf-8") as f:
                    f.write(html_post)
                return userdetails

        with open("sso_post.html", "w", encoding="utf-8") as f:
            f.write(html_post)
        return None

    def analyze_response(self, response):
        return response.text

    def check_login_success(self, response):
        html = response.text
        lower = html.lower()

        menu_markers = [
            "change photo", "update profile", "change pass", "totp reg.",
            "my notes", "my docs", "my favourites", "feedback",
        ]
        menu_hits = sum(1 for m in menu_markers if m in lower)
        email_domain_hit = bool(re.search(r"\b[a-z0-9._%+-]+@rajasthan\.in\b", html, re.I))
        phone_hit = bool(re.search(r"\+?91[-\s]*\d{5}[-\s]*\d{5}\b", html))

        if (menu_hits >= 3) or (email_domain_hit and phone_hit):
            return True

        generic_success = any(x in lower for x in ['logout', 'welcome', 'dashboard', 'success', 'home'])
        generic_failure = any(x in lower for x in ['invalid', 'incorrect', 'captcha'])
        if generic_success and not generic_failure:
            return True
        return False

    def sso_extract_exact_tokens(self, html: str):
        def grab(pat, default=""):
            m = re.search(pat, html, re.IGNORECASE)
            return m.group(1) if m else default

        tokens = {
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "__VIEWSTATE": grab(r'name="__VIEWSTATE"[^>]*value="([^"]+)"'),
            "__VIEWSTATEGENERATOR": grab(r'name="__VIEWSTATEGENERATOR"[^>]*value="([^"]+)"'),
            "__VIEWSTATEENCRYPTED": grab(r'name="__VIEWSTATEENCRYPTED"[^>]*value="([^"]*)"'),
            "ctl00$__AntiXsrfToken": grab(r'name="ctl00\$__AntiXsrfToken"[^>]*value="([^"]+)"'),
            "ctl00$__AntiXsrfUserName": grab(r'name="ctl00\$__AntiXsrfUserName"[^>]*value="([^"]+)"'),
            "onoffswitch": "on",
            "ctl00$cpBody$defaultApp": grab(r'name="ctl00\$cpBody\$defaultApp"[^>]*value="([^"]*)"'),
            "ctl00$cpBody$hf_AppName": grab(r'name="ctl00\$cpBody\$hf_AppName"[^>]*value="([^"]*)"'),
        }
        m_lb = re.search(r'name="(ctl00\$cpBody\$dlActiveApps\$ctl00\$LinkButton1)"', html, re.IGNORECASE)
        if m_lb:
            tokens["__EVENTTARGET"] = m_lb.group(1)
        if not tokens["__VIEWSTATE"]:
            return None
        return tokens

    def generate_curl_command(self, form_data):
        form_data_encoded = '&'.join([f"{k}={quote(str(v))}" for k, v in form_data.items()])
        return f"""curl -X POST '{self.login_url}' \\
  -H 'User-Agent: {self.headers["User-Agent"]}' \\
  -H 'Accept: {self.headers["Accept"]}' \\
  -H 'Accept-Language: {self.headers["Accept-Language"]}' \\
  -H 'Referer: {self.headers["Referer"]}' \\
  -H 'Content-Type: {self.headers["Content-Type"]}' \\
  -H 'Origin: {self.headers["Origin"]}' \\
  -H 'Upgrade-Insecure-Requests: {self.headers["Upgrade-Insecure-Requests"]}' \\
  -H 'Sec-Fetch-Dest: {self.headers["Sec-Fetch-Dest"]}' \\
  -H 'Sec-Fetch-Mode: {self.headers["Sec-Fetch-Mode"]}' \\
  -H 'Sec-Fetch-Site: {self.headers["Sec-Fetch-Site"]}' \\
  -H 'Connection: {self.headers["Connection"]}' \\
  --data-raw '{form_data_encoded}'"""

# -------------------- CLI main (kept, but not used when running FastAPI) --------------------
def main():
    sso = RajasthanSSOComplete()
    extracted = sso.extract_all_values()
    if not extracted:
        return
    captcha = sso.get_captcha_automatically()
    if not captcha:
        return
    form_data = sso.build_complete_request(captcha, extracted)
    if not form_data:
        return
    response = sso.send_login_request(form_data)
    if not response:
        return
    content = sso.analyze_response(response)
    success = sso.check_login_success(response)
    signin_dump = 'login_success.html' if success else 'login_failed.html'
    with open(signin_dump, 'w', encoding='utf-8') as f:
        f.write(content)
    if not success:
        return
    sso.ensure_auth_cookies()
    userdetails = sso.sso_get_userdetails_exact()
    if not userdetails:
        return
    rp_url = "https://rajerp.discoms.rajasthan.gov.in/SSOIndex.aspx"
    rp_resp = sso.rp_post_userdetails(rp_url, userdetails)
    salary_payload = sso.rp_fetch_my_salary()
    if not salary_payload:
        return
    with open("rp_landing.html", "w", encoding="utf-8") as f:
        f.write(rp_resp.text)
    print(json.dumps({
        "success": True,
        "sso": {"userdetails_len": len(userdetails)},
        "mysalary": salary_payload
    }, ensure_ascii=False))


# === FastAPI section (drop-in) ==============================================


app = FastAPI(title="Rajasthan SSO Salary API")

# Basic logging so you see tracebacks in the console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("raj_salary")

# In-memory session store
SESSION_STORE: dict[str, dict] = {}

# ---------- Global error handler (so you don't get a blank 500) -------------
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error("Unhandled error on %s %s\n%s", request.method, request.url.path, tb)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "err": "unhandled_exception",
            "msg": str(exc),
            "trace": tb.splitlines()[-10:],  # last lines only (dev)
        },
    )

# ------------------------------- Models -------------------------------------
class LoginPayload(BaseModel):
    session_id: str
    username: str
    password: str
    captcha: str  # 6 digits the user read from /api/captcha

# ------------------------------- Health -------------------------------------
@app.get("/api/health")
def api_health():
    return {"ok": True}

@app.get("/health")
def health():
    return {"status": "ok"}

# ------------------------------ /api/captcha --------------------------------
# Allow GET or POST so simple curl works
@app.get("/api/captcha")
@app.post("/api/captcha")
def api_get_captcha():
    """
    1) Start a fresh session
    2) GET /signin → parse tokens + AES key/iv
    3) GET captcha with SAME session
    4) Return {session_id, captcha_b64}
    """
    try:
        sso = RajasthanSSOComplete()

        # Step A: fetch /signin and parse
        extracted = sso.extract_all_values()
        if not extracted:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "stage": "signin_extract",
                    "err": "signin_extract_failed",
                    "msg": "Failed to fetch /signin or extract dynamic fields.",
                },
            )

        # Step B: fetch captcha with same session + referer
        headers = sso._no_cookie_headers()  # keeps session cookies intact
        headers["Referer"] = sso.login_url
        r = sso.session.get(sso.captcha_url, headers=headers, timeout=30)
        if r.status_code != 200 or not r.content:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "stage": "captcha_fetch",
                    "err": "captcha_fetch_failed",
                    "msg": f"HTTP {r.status_code} when fetching captcha",
                },
            )

        b64 = base64.b64encode(r.content).decode("ascii")
        data_url = f"data:image/png;base64,{b64}"

        session_id = str(uuid.uuid4())
        SESSION_STORE[session_id] = {
            "sso": sso,               # keep this requests.Session (+ cookies)
            "extracted": extracted,   # parsed form fields for /signin POST
        }

        return {
            "success": True,
            "session_id": session_id,
            "captcha_b64": data_url,
        }

    except Exception as e:
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        logger.error("captcha endpoint error: %s\n%s", e, tb)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "stage": "captcha_endpoint",
                "err": type(e).__name__,
                "msg": str(e),
                "trace": tb.splitlines()[-10:],  # last lines only
            },
        )

# ------------------------------ /api/mysalary -------------------------------
@app.post("/api/mysalary")
def api_my_salary(payload: LoginPayload):
    """
    Reuse the session created by /api/captcha via session_id.
    Submit credentials + user-entered captcha, perform /sso handoff,
    and return parsed MySalary JSON.
    """
    # Get the stored session context
    ctx = SESSION_STORE.get(payload.session_id)
    if not ctx:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "err": "bad_session",
                "msg": "Invalid or expired session_id; call /api/captcha first.",
            },
        )

    sso: RajasthanSSOComplete = ctx["sso"]
    extracted = ctx["extracted"]

    # Fill credentials
    sso.username = payload.username
    sso.password = payload.password

    if not (payload.captcha.isdigit() and len(payload.captcha) == 6):
        raise HTTPException(
            status_code=400,
            detail={"success": False, "err": "bad_captcha", "msg": "Captcha must be 6 digits."},
        )

    # Build login form
    form_data = sso.build_complete_request(payload.captcha, extracted)
    if not form_data:
        raise HTTPException(
            status_code=500,
            detail={"success": False, "err": "build_form_failed", "msg": "Could not build login form."},
        )

    # POST /signin with same session
    resp = sso.send_login_request(form_data)
    if not resp:
        raise HTTPException(
            status_code=500,
            detail={"success": False, "err": "signin_request_failed", "msg": "POST /signin failed."},
        )

    # Confirm login by page markers
    content = sso.analyze_response(resp)
    success = sso.check_login_success(resp)
    if not success:
        # Often caused by wrong captcha or expired tokens — client should retry /api/captcha
        raise HTTPException(
            status_code=400,
            detail={"success": False, "err": "login_not_confirmed", "msg": "Login not confirmed; retry captcha."},
        )

    # /sso handoff
    sso.ensure_auth_cookies()
    userdetails = sso.sso_get_userdetails_exact()
    if not userdetails:
        raise HTTPException(
            status_code=500,
            detail={"success": False, "err": "userdetails_missing", "msg": "Could not obtain 'userdetails' from /sso."},
        )

    # RP hop + salary
    rp_url = "https://rajerp.discoms.rajasthan.gov.in/SSOIndex.aspx"
    sso.rp_post_userdetails(rp_url, userdetails)

    salary_payload = sso.rp_fetch_my_salary()
    if not salary_payload:
        raise HTTPException(
            status_code=500,
            detail={"success": False, "err": "mysalary_parse_failed", "msg": "Could not parse salary table."},
        )

    return {
        "success": True,
        "sso": {"userdetails_len": len(userdetails)},
        "mysalary": salary_payload,
    }

# Local dev launcher
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("raj_salary:app", host="127.0.0.1", port=8000, reload=True)
# =========================================================================== 
