# PlayReady API

This repository contains a simple Flask-based API that allows you to generate PlayReady license challenges and decode PlayReady licenses to extract the keys.

## Prerequisites

- Python 3.7+
- Install the required dependencies:
  ```sh
  pip install flask requests pyplayready
  ```
- A valid PlayReady `.prd` device file located at `C:/Path/To/A/Device.prd`. Update the path in the script accordingly.

## Installation

1. Clone this repository.
2. Install the necessary dependencies by running:
   ```sh
   pip install -r requirements.txt
   ```
3. Update the `device` path in the script to point to your PlayReady device file.

## Usage

1. **Start the Flask server:**
   
   Run the following command to start the server:
   ```sh
   python playready_api.py
   ```
   The application will start on `http://127.0.0.1:5000`.

2. **Endpoints**

   - **`/generate-challenge` (POST)**
     
     This endpoint generates a license challenge using the provided PSSH.
     
     Example request:
     ```sh
     curl -X POST http://127.0.0.1:5000/generate-challenge \
     -H "Content-Type: application/json" \
     -d '{"pssh": "YOUR_PSSH_HERE"}'
     ```
     
     Example response:
     ```json
     {
       "license_challenge": "GeneratedLicenseChallengeHere"
     }
     ```

   - **`/decode-license` (POST)**
     
     This endpoint sends the license challenge to a license server and returns the keys.
     
     Example request:
     ```sh
     curl -X POST http://127.0.0.1:5000/decode-license \
     -H "Content-Type: application/json" \
     -d '{
       "license_url": "LICENSE_SERVER_URL",
       "license_challenge": "GeneratedLicenseChallengeHere"
     }'
     ```
     
     Example response:
     ```json
     {
       "keys": [
         {
           "key_id": "key_id_1",
           "key": "key_1"
         },
         {
           "key_id": "key_id_2",
           "key": "key_2"
         }
       ]
     }
     ```

## Important Notes

- Make sure to have a valid PlayReady device file (`.prd`) to use the API.
- The `/generate-challenge` endpoint accepts PSSH data in base64 format.
- The `/decode-license` endpoint uses the license challenge to communicate with the provided license server and decodes the response to extract keys.

## License

This project is licensed under the MIT License.

