#Imports important modules
import base64
import json
import jwt
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import parse_qs, urlparse

#initializes the name of the host and the port
hostName = "localhost"
serverPort = 8080

#generates a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

#puts the unexpired private key into PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

#generates an RSA key pair for the expired key
expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

expired_public_key = expired_private_key.public_key()

#converts the expired key pair to PEM format
expired_private_key_pem = expired_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

expired_public_key_pem = expired_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#stores the key ID (kid) and expiration timestamp (in seconds since epoch)
kid = "my-key-id"
expiry_timestamp = int(time.time()) + 360  # Expires in 6 minutes

#creates the JWKS JSON containing the public key
jwks = {
    "keys": [
        {
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": expired_public_key.public_numbers().n,
            "e": expired_public_key.public_numbers().e,
            "exp": expiry_timestamp
        }
    ]
}

class MyServer(BaseHTTPRequestHandler):
    #GET method for /.well-known/jwks.json
    def do_GET(self):
        if self.path == '/.well-known/jwks.json':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            if int(time.time()) >= expiry_timestamp:
                self.wfile.write(json.dumps({"error": "Key has expired"}).encode('utf-8'))
            else:
                self.wfile.write(json.dumps(jwks).encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("<html><head><title>Error</title></head>", "utf-8"))
            self.wfile.write(bytes("Please go to either of the two locations: <br> localhost:8080/.well-known/jwks.json <br> localhost:8080/auth", "utf-8"))
    #POST method for /auth
    def do_POST(self):
        if self.path.startswith('/auth'):
            #checks if the "expired" query parameter is present
            query_params = parse_qs(urlparse(self.path).query)
            expired_param = False
            if len(query_params) > 1:
                query_string = query_params[1]
                if "expired" in query_string:
                    expired_param = True

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            #generates a JWT with the appropriate key and expiration
            key_to_use = expired_private_key_pem if expired_param else private_key_pem
            exp_to_use = expiry_timestamp if expired_param else (int(time.time()) + 360)
            payload = {
                "sub": "user123",
                "exp": exp_to_use,
            }
            token = jwt.encode(payload, key_to_use, algorithm="RS256")
            response_data = {
                 "token": token,
                 "expired": expired_param
             }
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_response(405)
            self.end_headers()
    #the following requests are not allowed, and will be sent responses accordingly
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")
