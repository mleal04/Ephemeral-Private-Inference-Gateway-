# part1/relay.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

GATEWAY_URL = "https://127.0.0.1:8443/inference"

class PrivacyRelayHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        encrypted_payload_str = self.rfile.read(content_length).decode('utf-8')
        
        print(f"\n[RELAY] Received request from client!")
        print(f"[RELAY] Payload string (Base64): {encrypted_payload_str[:30]}...")

        try:
            print("[RELAY] Forwarding payload to C Gateway via HTTPS...")
            gateway_response = requests.post(
                GATEWAY_URL, 
                data=encrypted_payload_str, 
                verify=False 
            )
  
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

# from fastapi import FastAPI, Request, Response
# import httpx
# import uvicorn  # 1. Import the ASGI server

# app = FastAPI()
# GATEWAY_URL = "https://127.0.0.1:8443/inference"
# async_client = httpx.AsyncClient(verify=False)

# @app.post("/")
# async def privacy_relay(request: Request):
#     raw_payload = await request.body()
#     encrypted_payload_str = raw_payload.decode('utf-8')
#     try:
#         gateway_response = await async_client.post(GATEWAY_URL, content=encrypted_payload_str)
#         return Response(content=gateway_response.text, status_code=gateway_response.status_code)
#     except Exception as e:
#         return Response(content=f"Relay error: {e}", status_code=500)

# # 2. Add this block to lock down port 8080 natively
# if __name__ == '__main__':
#     uvicorn.run("relay:app", host="127.0.0.1", port=8080, log_level="info")