import base64
import re
import requests
from flask import json
from config import Config


def check_in_RL_API(url):
    api_url = Config.RL_ENDPOINT
    username = Config.RL_USERNAME
    password = Config.RL_PASSWORD
    payload = {
        "rl": {
            "query": {
                "url": url,
                "response_format": "json"
            }
        }
    }

    print("payload ---> ", payload)
    print("api_url ---> ", api_url)

    try:
        response = requests.post(api_url, json=payload, auth=(username, password))
        response.raise_for_status()
        data = response.json()

        # Extract statistics
        statistics = data.get("rl", {}).get("third_party_reputations", {}).get("statistics", {})
        malicious_count = statistics.get("malicious", 0)
        suspicious_count = statistics.get("suspicious", 0)
        classification = data.get("rl", {}).get("classification", "")
        base64_encoded_url = data.get("rl", {}).get("base64", "")
        
        # print("base64_encoded_url > ", base64_encoded_url)
        return malicious_count + suspicious_count, base64_encoded_url, classification

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while making the API call: {e}")
        return 0, "", ""
    except json.JSONDecodeError:
        print("Failed to parse the API response as JSON.")
        return 0, "", ""

def check_in_VT_API(url, is_base):
    # print("asdasdasd")
    # print("url > ", url)
    if is_base:
        encoded_url = url
    else:
        encoded_url = base64.b64encode(url.encode('utf-8')).decode('utf-8').rstrip("=")

    # print(" Config.VT_ENDPOINT >",  Config.VT_ENDPOINT + encoded_url)
    api_url = Config.VT_ENDPOINT + encoded_url
    # print("API URL > ", api_url)
    api_key = Config.VT_KEY
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Extract statistics
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        # print("malicious_count > ", malicious_count )
        # print("suspicious_count > ", suspicious_count )
        return malicious_count + suspicious_count

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return -1
    except KeyError as e:
        print(f"Unexpected response structure: {e}")
        return -1
