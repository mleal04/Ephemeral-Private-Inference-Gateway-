# part1/relay.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

# Point this to your C Gateway Server
GATEWAY_URL = "https://127.0.0.1:8443/inference"

class PrivacyRelayHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        encrypted_payload_str = self.rfile.read(content_length).decode('utf-8')
        
        print(f"\n[RELAY] Received request from client!")
        print(f"[RELAY] Payload string (Base64): {encrypted_payload_str[:30]}...")
        

        # 2. Forward the string to the C Gateway via a fresh HTTPS link
        # This completely hides the client's original IP header from the Gateway
        try:
            print("[RELAY] Forwarding payload to C Gateway via HTTPS...")
            gateway_response = requests.post(
                GATEWAY_URL, 
                data=encrypted_payload_str, 
                verify=False # Ignoring self-signed cert validation for local simulation
            )
            
            # 3. Return the response from the C Gateway back to the client
            self.send_response(gateway_response.status_code)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(gateway_response.text.encode('utf-8'))
            print("[RELAY] Successfully relayed response back to client.\n")

        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Relay internal error forwarding to gateway: {e}".encode('utf-8'))

def run_relay(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, PrivacyRelayHandler)
    print(f"Privacy Relay listening on plain HTTP at http://127.0.0.1:{port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run_relay()