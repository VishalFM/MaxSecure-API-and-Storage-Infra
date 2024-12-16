import base64
import requests  # Import the requests module
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
        response = requests.post(api_url, json=payload, auth=(username, password))  # Use requests.post
        response.raise_for_status()
        response_data = response.json()
        classification = response_data.get("rl", {}).get("classification", "")

        return classification in ["malicious", "suspicious"]
            
    except requests.exceptions.RequestException as e:  # Use requests.exceptions
        print(f"An error occurred while making the API call: {e}")
        return False
    except json.JSONDecodeError:
        print("Failed to parse the API response as JSON.")
        return False
    
def check_in_VT_API(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    api_url = Config.VT_ENDPOINT + encoded_url
    api_key = Config.VT_KEY

    # Set up headers with the API key
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    print("in vt")
    try:
        response = requests.get(api_url, headers=headers)  # Use requests.get
        response.raise_for_status()

        data = response.json()
        
        malicious_count = data["data"]["attributes"]["last_analysis_results"]["malicious"]
        suspicious_count = data["data"]["attributes"]["last_analysis_results"]["suspicious"]
        thread_names = data["data"]["attributes"]["threat_names"]
        
        print("malicious_count > ", malicious_count)
        print("suspicious_count > ", suspicious_count)
        print("thread_names > ", thread_names)

        return malicious_count + suspicious_count >= 5 and thread_names

    except requests.exceptions.RequestException as e:  # Use requests.exceptions
        print(f"Request failed: {e}")
        return False
    except KeyError as e:
        print(f"Unexpected response structure: {e}")
        return False