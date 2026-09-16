"""DEPRECATED early Python/fido2 Passkey registration proof of concept."""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256


def simulate_passkey_registration(request_json):
    if not os.path.exists("keys"):
        os.makedirs("keys")
    try:
        request_data = request_json["datas"]["request"]
        options = request_data["publicKeyCredentialCreationOptions"]
        challenge = options["challenge"]
        rp_id = options["rp"]["id"]
        origin = f"https://{rp_id}"
    except KeyError as exc:
        return f"Error: 无法从输入的JSON中找到字段 {exc}"

    private_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = os.urandom(16)
    cred_id_b64 = base64.urlsafe_b64encode(credential_id).decode("utf-8").rstrip("=")
    key_filename = f"keys/privkey_{cred_id_b64}.pem"
    with open(key_filename, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    auth_data = (
        rp_id_hash + b"\x41" + b"\x00\x00\x00\x00" + b"\x00" * 16
        + len(credential_id).to_bytes(2, byteorder="big")
        + credential_id + cbor.encode(ES256.from_cryptography_key(private_key.public_key()))
    )
    client_data = {"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": False}
    client_data_b64 = base64.urlsafe_b64encode(
        json.dumps(client_data, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8").rstrip("=")
    attestation_object = {"fmt": "none", "attStmt": {}, "authData": auth_data}
    att_obj_b64 = base64.urlsafe_b64encode(cbor.encode(attestation_object)).decode("utf-8").rstrip("=")
    response_inner = {
        "requestId": request_data["requestId"],
        "credential": {
            "type": "public-key", "id": cred_id_b64,
            "response": {"attestationObject": att_obj_b64, "clientDataJSON": client_data_b64},
            "clientExtensionResults": {},
        },
        "sessionToken": None,
    }
    return {
        "deviceName": "Python-Simulated-Device", "anonbiometricsd": None,
        "response": json.dumps(response_inner, separators=(",", ":")),
        "n": "0.9239225681951135",
    }
