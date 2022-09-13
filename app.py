import re
from base64 import b64decode
from http import HTTPStatus
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from flask import Flask, request

app = Flask(__name__)


# Load public key from configuration
app.config.from_object('config')
pem_file = app.config.get('PEM_FILE_PATH')
file = open(pem_file, 'r')
public_key = RSA.importKey(file.read())
print('public_key : ' + str(public_key))


@app.route('/shipments', methods=['PUT'])
def update_shipments():
    headers = request.headers
    authorization = headers.get('authorization')
    print(authorization)
    host_hdr = headers.get('host')
    date_hdr = headers.get('date')
    digest_hdr = headers.get('digest')
    input_str = host_hdr + date_hdr + digest_hdr
    print("input_str: " + input_str)

    pattern = 'signature="(.*)"'
    match = re.search(pattern, authorization)
    signature = match.group(1)
    print(signature)

    is_legit = is_legit_digital_signature(signature, input_str)
    is_legit_str = str(is_legit)
    print("is_legit : " + is_legit_str)

    return '', HTTPStatus.NO_CONTENT


def is_legit_digital_signature(signature, input_str):
    is_legit = False
    try:
        digest = SHA256.new()
        digest.update(bytes(input_str, 'utf-8'))
        signer = pkcs1_15.new(public_key)
        signer.verify(digest, b64decode(signature))
        is_legit = True
    except ValueError as ve:
        print('The signature is not authentic. ' + str(ve))
    except TypeError as te:
        print('A TypeError occurred : ' + str(te))

    return is_legit


if __name__ == '__main__':
    app.run()
