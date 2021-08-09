import requests

import hashlib
import hmac
from flask import request, current_app


def create_identification(client_id, client_secret, webhook, redirect_url):
  current_app.logger.info('create_identification')
  data = {
    "data": {
      "type": "identifications",
      "attributes": {
        "identification-form": {
          "phone-number" : "+687"
        },
        "webhook": webhook,
        "redirect_url": redirect_url
      },
    }
  }

  headers = {
    "Accept": "application/vnd.api+json",
    "Content-Type": "application/vnd.api+json"
  }

  res = requests.post(
      "https://api.ubble.ai/identifications/",
      auth=(client_id, client_secret),
      headers=headers,
      json=data
  )
  res.raise_for_status()
  identification = res.json()

  current_app.logger.info(f'identification created {identification["data"]["attributes"]["identification-id"]}')
  return identification


def get_identification(client_id, client_secret, identification_id):
  current_app.logger.info(f'get identification {identification_id}')
  headers = {"Accept": "application/vnd.api+json"}
  res = requests.get(
      f"https://api.ubble.ai/identifications/{identification_id}/",
      auth=(client_id, client_secret),
      headers=headers
  )
  res.raise_for_status()
  return res.json()


def verify_signature(webhook_secret):
  ubble_signature = request.headers['Ubble_Signature']
  ubble_signature_dict = dict(token.split('=') for token in ubble_signature.split(','))
  # Let's compare the hash

  # First we create the signed_payload
  signed_payload = ubble_signature_dict['ts'] + '.' + request.get_data(as_text=True)

  # Then we create the hash
  expected_signature = hmac.new(
    # WEBHOOK_SECRET can be found in the Configuration page on your dashboard.
    webhook_secret.encode('utf-8'),
    msg=signed_payload.encode('utf-8'),
    digestmod=hashlib.sha256
  ).hexdigest()

  # Then we compare both signature.
  if expected_signature != ubble_signature_dict['v1']:
    current_app.logger.warn('Bad signature !!!')
    raise Exception("Bad signature")
  current_app.logger.warn('Signature OK')
