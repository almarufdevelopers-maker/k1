"""
Standalone SMS test -- confirms Africa's Talking is actually sending,
without needing the rest of your Flask app (Didit, Google, DB) configured.

Run locally:
  pip install africastalking --break-system-packages
  export AT_USERNAME="your_username"      # "sandbox" while testing
  export AT_API_KEY="your_api_key"
  python test_sms.py +254712345678        # your real number, E.164 format

Or edit TEST_PHONE_NUMBER below and just run: python test_sms.py
"""

import os
import sys

import africastalking

AT_USERNAME = os.environ.get("AT_USERNAME", "").strip()
AT_API_KEY = os.environ.get("AT_API_KEY", "").strip()

if not AT_USERNAME or not AT_API_KEY:
    print("ERROR: set AT_USERNAME and AT_API_KEY as environment variables first.")
    sys.exit(1)

TEST_PHONE_NUMBER = sys.argv[1] if len(sys.argv) > 1 else "+254700000000"

print(f"Initializing Africa's Talking (username={AT_USERNAME})...")
africastalking.initialize(AT_USERNAME, AT_API_KEY)
sms = africastalking.SMS

print(f"Sending test SMS to {TEST_PHONE_NUMBER}...")
try:
    response = sms.send("This is a test message from Kiya. If you got this, SMS works!", [TEST_PHONE_NUMBER])
    print("\nRaw response from Africa's Talking:")
    print(response)

    recipients = (response or {}).get("SMSMessageData", {}).get("Recipients", [])
    if not recipients:
        print("\nWARNING: no recipients in response -- something is off with the request itself.")
    else:
        for r in recipients:
            status = r.get("status")
            cost = r.get("cost")
            if status == "Success":
                print(f"\nSUCCESS: message accepted for {r.get('number')} (cost: {cost}).")
                print("Check your phone. If you're on sandbox and it's not whitelisted, "
                      "this can say 'Success' but never actually arrive -- check the "
                      "Africa's Talking dashboard delivery reports to confirm.")
            else:
                print(f"\nFAILED for {r.get('number')}: status={status}")
except Exception as e:
    print(f"\nEXCEPTION while sending: {e}")
    print("This usually means bad credentials, an invalid phone format, "
          "or a rejected/unapproved sender.")