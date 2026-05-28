import requests

url_to_attestation = "https://127.0.0.1:8443/attestation"
url_to_gateway = "https://127.0.0.1:8443"
url_to_relay = None
pcc_node_pub_rek = None  

try:

    #make the attestion request to PCC (straight TLS (Client to Gateway))
    message = "ATTESTATION_REQUEST"
    answer = requests.get(url_to_attestation, data=message, verify=False)  # Set verify=False to ignore SSL warnings for self-signed certs
    print(f"Response from PCC: {answer.text}")
    

    # #encrypt the message with REK


    # #make the request to get the PCC response (HTTP to relay --> OHTTPS from relay to gateway)


except Exception as e:
    print(f"An error occurred: {e}")