from flask import Flask, request, jsonify
from pyplayready.cdm import Cdm
from pyplayready.device import Device
from pyplayready.pssh import PSSH
import requests

app = Flask(__name__)

device = Device.load("C:/Path/To/A/Device.prd")
cdm = Cdm.from_device(device)

@app.route('/generate-challenge', methods=['POST'])
def generate_challenge():
    try:
        # Extract PSSH input from request JSON
        data = request.get_json()
        pssh_input = data.get('pssh')
        if not pssh_input:
            return jsonify({"error": "PSSH input is required"}), 400

        # Create PSSH object
        pssh = PSSH(pssh_input)

        # Generate the license challenge
        license_challenge = cdm.get_license_challenge(pssh.wrm_headers[0])

        return jsonify({"license_challenge": license_challenge.decode('utf-8')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decode-license', methods=['POST'])
def decode_license():
    try:
        # Extract license URL and PSSH from request JSON
        data = request.get_json()
        license_url = data.get('license_url')
        license_challenge = data.get('license_challenge')

        if not license_url or not license_challenge:
            return jsonify({"error": "License URL and challenge are required"}), 400

        # Send the license request
        response = requests.post(
            url=license_url,
            headers={'Content-Type': 'text/xml; charset=UTF-8'},
            data=license_challenge,
        )

        if response.status_code != 200:
            return jsonify({"error": f"License server returned status code {response.status_code}"}), 500

        # Parse the license response
        cdm.parse_license(response.text)

        # Extract keys
        keys = [{"key_id": key.key_id.hex(), "key": key.key.hex()} for key in cdm.get_keys()]

        return jsonify({"keys": keys})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
