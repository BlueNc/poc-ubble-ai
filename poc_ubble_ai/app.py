import logging
import os

from flask import Flask, send_file, redirect, request
from poc_ubble_ai import ubble_client


WEBHOOK = os.environ['WEBHOOK']
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
REDIRECT_URL = os.environ['REDIRECT_URL']
WEBHOOK_SECRET = os.environ['WEBHOOK_SECRET']

app = Flask(__name__)

app.logger.setLevel(logging.INFO)


@app.route('/')
def root():
  return send_file('html/index.html')


@app.route('/api/health/')
def health():
  return {'message': 'Healthy'}


@app.route('/verify-identity', methods=['GET'])
def verify_identity():
  app.logger.info("verify-identity request received")
  identification = ubble_client.create_identification(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, webhook=WEBHOOK, redirect_url=REDIRECT_URL)
  app.logger.info(f'redirecting user to {identification["data"]["attributes"]["identification-url"]}')
  return redirect(identification["data"]["attributes"]["identification-url"], code=303)


@app.route('/verification-pending', methods=['GET'])
def verification_pending():
  return send_file('html/verification-pending.html')


@app.route('/webhook', methods=['POST'])
def webhook():
  data = request.get_json()
  app.logger.info("webhook received")
  app.logger.info(data)
  ubble_client.verify_signature(WEBHOOK_SECRET)
  identification = ubble_client.get_identification(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, identification_id=data['identification_id'])
  app.logger.info(identification)
  return 'Ok', 200


