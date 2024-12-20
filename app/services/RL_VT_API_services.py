import base64
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

    try:
        response = requests.post(api_url, json=payload, auth=(username, password))
        response.raise_for_status()
        response_data = response.json()
        classification = response_data.get("rl", {}).get("classification", "")

        return classification

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while making the API call: {e}")
        return "unknown"
    except json.JSONDecodeError:
        print("Failed to parse the API response as JSON.")
        return "unknown"


def check_in_VT_API(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    api_url = Config.VT_ENDPOINT + encoded_url
    api_key = Config.VT_KEY
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        data = response.json()

        malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious_count = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        thread_names = data["data"]["attributes"]["threat_names"]

        return malicious_count + suspicious_count >= 5 and thread_names
    
    except requests.exceptions.RequestException as e:  
        print(f"Request failed: {e}")
        return False
    except KeyError as e:
        print(f"Unexpected response structure: {e}")
        return False
