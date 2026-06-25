"""
OKTA MFA Audit Tool

This application connects to the Okta API to retrieve user
accounts and enrolled MFA factors. It evaluates authentication
strength, assigns a risk classification, and generates both
a detailed CSV report and an executive summary for review.
"""
from dotenv import load_dotenv
import os

load_dotenv("okta.env")



import requests
import pandas as pd



url = os.getenv("OKTA_DOMAIN")
token = os.getenv("OKTA_TOKEN")

header = {"Authorization": f"SSWS {token}"} #authorizes the use of token
"""
header creates a python directory of request header
Authorization = HTTP header name used for creds
SSWS prefiz Okta used for its API tokens
"""

users = requests.get(f"{url}/api/v1/users", headers=header).json() #Only returns active users
results = [] #initialize results array to store

"""
Initializing risk values
"""
low = 0
medium = 0
high = 0
critical = 0


for user in users:
    # variables
    userid = user["id"]
    firstname = user["profile"].get("firstName", " ")
    lastname = user["profile"].get("lastName", " ")
    email = user["profile"]["email"]
    status = user.get("status", "UNKNOWN")

    fullname  = f"{firstname} {lastname}".strip()

    factors = requests.get(f"{url}/api/v1/users/{userid}/factors", headers=header).json()

    factor_types = [] #initilize array to store 
    
    for factor in factors:
        factor_types.append(factor["factorType"])
    
    factor_types = sorted(set(factor_types))
    """
    RISK Logic
    """
    if "signed_nonce" in factor_types:
        risk = "LOW"
    elif "token:software:totp" in factor_types:
        risk = "MEDIUM"
    elif factor_types == ["email"]:
        risk = "HIGH"
    elif "question" in factor_types:
        risk = "CRITICAL"
    else:
        risk = "CRITICAL"
    

    if risk == "LOW":
        low += 1
    elif risk == "MEDIUM":
        medium += 1
    elif risk == "HIGH":
        high += 1
    elif risk == "CRITICAL":
        critical += 1


    results.append({"Name ": fullname,
                    "Email ": email,
                    "Status ": status,
                    "Factors ": ", ".join(sorted(set(factor_types))),
                    "Risk ": risk})
        
df = pd.DataFrame(results)
df.to_csv("Okta_MFA_Audit.csv", index = False)

"""
Executive Summary Block
"""
print("\n" + "=" * 50)
print("OKTA MFA AUDIT - EXECUTIVE SUMMARY")
print("=" * 50)

total_users = len(results)

print(f"Total Users Audited: {total_users}")
print()
print(f"LOW RISK:           {low}")
print(f"MEDIUM RISK:        {medium}")
print(f"HIGH RISK:          {high}")
print(f"CRITICAL RISK:      {critical}")
print()
print("=" * 50)
print("Report Created")

    

