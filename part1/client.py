import requests

url = "https://127.0.0.1:8443"

try:
    #make the GET request
    message = "Hello from the Client!"
    answer = requests.get(url, data=message, verify=False)  # Set verify=False to ignore SSL warnings for self-signed certs
    print(f"Response from server: {answer.text}")
except Exception as e:
    print(f"An error occurred: {e}")