import requests
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
class pythonClient:
    def __init__(self):
        self.url_to_attestation = "https://127.0.0.1:8443/attestation"
        self.url_to_gateway = "https://127.0.0.1:8443"
        self.url_to_relay = "http://127.0.0.1:8080"
        self.pcc_node_pub_rek = None 
        self.encrypted_message = None

        #messages
        self.attestation_request_message = "ATTESTATION_REQUEST"

    #helper
    def make_attestion_request(self):
        message = self.attestation_request_message
        answer = requests.get(self.url_to_attestation, data=message, verify=False)  # Set verify=False to ignore SSL warnings for self-signed certs
        print(f"Response from PCC: {answer.text}")
        return answer.text
        
    def scrape_public_rek(self, attestation_response):
        print(f"Scraping public REK from attestation response: {attestation_response}")
        self.pcc_node_pub_rek = attestation_response  # Dummy assignment for illustration
        print(f"Scraped public REK: {self.pcc_node_pub_rek}")

    def encrypt_with_rsa(self, public_key_pem, message):
        cleaned_key = public_key_pem.replace('\\n', '\n')
        public_key = load_pem_public_key(cleaned_key.encode())
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Encrypted message: {encrypted}")
        self.encrypted_message = base64.b64encode(encrypted).decode('utf-8')  # Store the encrypted message for later use

    def send_to_relay(self):
        if self.encrypted_message is None:
            print("No encrypted message to send.")
            return
        # Send the encrypted message to the relay
        response = requests.post(self.url_to_relay, data=self.encrypted_message, verify=False)
        print(f"Response from relay: {response.text}")

        
    #this is the main sauce of the class 
    def start_client_process(self):
        #make the attestion request to pcc node (straight TLS (Client to Gateway))
        attestion_response = self.make_attestion_request()

        #scrape the public rek from the attestation response 
        self.scrape_public_rek(attestion_response)
        self.encrypt_with_rsa(self.pcc_node_pub_rek, "Hello, this is a test message!")

        #send to the relay in plain https
        self.send_to_relay()



    
client_example = pythonClient()
client_example.start_client_process()
    
