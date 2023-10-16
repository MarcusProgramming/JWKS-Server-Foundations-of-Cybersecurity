#Imports important modules
import base64
import json
import jwt
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import parse_qs, urlparse

#initializes the name of the host and the port
hostName = "localhost"
serverPort = 8080

#generates a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#generates expired private key
expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size = 2048,
)

#puts the unexpired private key into PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

#generates an RSA key pair for the expired key
expired_private_key_pem = expired_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

def int_to_base64(x):
    """Convert an integer to a Base64URL-encoded string"""
    heX = format(x, 'x')
    # Ensure even length
    if len(heX) % 2 == 1:
        heX = '0' + heX
    x_bytes = bytes.fromhex(heX)
    encoded = base64.urlsafe_b64encode(x_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    #GET method for /.well-known/jwks.json
    def do_GET(self):
        if self.path == '/.well-known/jwks.json':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            #creates the JWKS JSON containing the public key
            jwks_key = {
                "keys": [
                    {
                        "kid": "kid",
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(jwks_key), 'utf-8'))
        else:
            self.send_response(405)
            self.end_headers()

    #POST method for /auth
    def do_POST(self):
        if self.path.startswith('/auth'):
            #checks if the "expired" query parameter is present
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            #generates a JWT with the appropriate key and expiration
            header = {
                "kid": "kid"
            }
            payload = {
                 "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                 "user": "username"
             }
            if 'expired' in query_params:
                 header["kid"] = "expiredkid"
                 payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            jwt_enc = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header)
            #sends a success response to the user
            self.send_response(200)
            self.end_headers()
            #writes json dumps to the file
            self.wfile.write(bytes(jwt_enc, "utf-8"))
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
