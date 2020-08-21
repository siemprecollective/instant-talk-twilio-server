# TODO ANALYTICS

import os
from flask import Flask, abort, jsonify, request, Response
from flask_cors import CORS
from twilio.rest import Client
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VideoGrant
from twilio.request_validator import RequestValidator

import apns2
from apns2.client import APNsClient
from apns2.payload import Payload

import analytics
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from firebase_admin import auth
from firebase_admin import messaging

from functools import wraps
from collections import defaultdict

analytics.write_key = "BLANK"

cred = credentials.Certificate("BLANK")
firebase_admin.initialize_app(cred)
db = firestore.client()

DEV = os.environ.get("DEV", "0") == "1"
PORT = int(os.environ.get("PORT", 5006))

SERVER_ADDR = "BLANK"+str(PORT)+"/"

ACCOUNT_SID = 'BLANK'
API_KEY = 'BLANK'
API_KEY_SECRET = 'BLANK'
APP_SID = '' # TODO

AUTH_TOKEN = 'BLANK'

USER_COLLECTION = "new-users"
GROUP_COLLECTION = "groups"

app = Flask(__name__)
CORS(app)

apns_client = APNsClient("siempreone-push.pem", use_sandbox=False)
apns_client_dev = APNsClient("siempreone-push.pem", use_sandbox=True)

client = Client(ACCOUNT_SID, AUTH_TOKEN)
request_validator = RequestValidator(AUTH_TOKEN)

real_track = analytics.track
def track_patch(*args, **kwargs):
  if DEV:
    return 
  return real_track(*args, **kwargs)
analytics.track = track_patch

def set_in_call(in_call, userid, groupid=None):
  db.collection(USER_COLLECTION).document(userid).update({
    "inCall": in_call
  })
  if (groupid != None):
    db.collection(GROUP_COLLECTION).document(groupid).update({
      "users."+userid: in_call
    })

def send_call_notification(to_id, from_id, group_id=None):
  user = db.collection(USER_COLLECTION).document(to_id).get()
  if from_id not in user.to_dict()["friends"]: # TODO handle error
    return
  if "APNSVoIPToken" in user.to_dict() and not user.to_dict().get("APNSDev", False):
    send_call_notification_apns(user.to_dict()["APNSVoIPToken"], apns_client, to_id, from_id, group_id)
  if "APNSVoIPToken" in user.to_dict() and user.to_dict().get("APNSDev", False):
    send_call_notification_apns(user.to_dict()["APNSVoIPToken"], apns_client_dev, to_id, from_id, group_id)
  if "FCMToken" in user.to_dict():
    token = user.to_dict()["FCMToken"]
    if "FCMTokenWatch" in user.to_dict():
      if "headphonesIn" not in user.to_dict() or not user.to_dict()["headphonesIn"]:
        if "watchIn" in user.to_dict() and user.to_dict()["watchIn"]:
          token = user.to_dict()["FCMTokenWatch"]
    send_call_notification_fcm(token, to_id, from_id, group_id)

def send_call_notification_apns(token, client, to_id, from_id, group_id):
  print("sending notification to", to_id)
  custom = {"from-id": from_id}
  if group_id != None:
    custom["group-id"] = group_id
  payload = Payload(alert="placeholder", custom=custom)
  try:
    client.send_notification(token, payload, "com.siempre.SiempreOne.voip")
  except apns2.errors.BadDeviceToken:
    print("got bad voip token "+ to_id)
  except apns2.errors.TopicDisallowed:
    print("got bad voip token "+ to_id)

def send_call_notification_fcm(token, to_id, from_id, group_id):
  print("Sending notification to ", to_id)
  if group_id is None:
    group_id = ""
  android_config = messaging.AndroidConfig(priority='high')
  message = messaging.Message(
    data={
      'type': 'incoming_call',
      'id': from_id,
      'group_id': group_id
    },
    android=android_config,
    token=token
  )
  response = messaging.send(message)
  print('Successfully sent message:', response)

"""
decorator to ensure requests come from twilio
"""
def validate_twilio_request(f):
  """Validates that incoming requests genuinely originated from Twilio"""
  @wraps(f)
  def decorated_function(*args, **kwargs):
    request_valid = request_validator.validate(
      request.url,
      request.form,
      request.headers.get('X-TWILIO-SIGNATURE', ''))
    if request_valid:
      return f(*args, **kwargs)
    else:
      return abort(403)
  return decorated_function

"""
Creates an access token with VoiceGrant using your Twilio credentials.
"""
@app.route('/accessToken', methods=['GET', 'POST'])
def accessToken():
  account_sid = os.environ.get("ACCOUNT_SID", ACCOUNT_SID)
  api_key = os.environ.get("API_KEY", API_KEY)
  api_key_secret = os.environ.get("API_KEY_SECRET", API_KEY_SECRET)
  app_sid = os.environ.get("APP_SID", APP_SID)

  if request.args.get('jwt'):
    identity = auth.verify_id_token(request.args.get('jwt'))['uid']
  else:
    return abort(403)
  if request.args.get('room'):
    requested_room = request.args.get('room')
  else:
    return abort(400)

  groupid = None
  if requested_room.startswith("group:"):
    groupid = requested_room[6:]
    group = db.collection(GROUP_COLLECTION).document(groupid).get()
    if identity not in group.to_dict()["users"]: # TODO handle error
      return abort(403)
  elif requested_room.startswith("private:"):
    userids = requested_room[8:].split(":") # TODO handle error
    if identity == userids[0]:
      requested_userid = userids[1]
    elif identity == userids[1]:
      requested_userid = userids[0]
    else:
      return abort(403)

    user = db.collection(USER_COLLECTION).document(requested_userid).get()
    if identity not in user.to_dict()["friends"]: # TODO handle error
      return abort(403)
    requested_room = "private:"+userids[0]+":"+userids[1]
  else:
    return abort(400)

  token = AccessToken(account_sid, api_key, api_key_secret, identity=identity, ttl=180)
  grant = VideoGrant(room=requested_room) 
  token.add_grant(grant)
 
  to_call = [] 
  if request.args.get('call'):
    to_call = request.args.get('call').split(',')
    print("to call: " + " ".join(to_call))
    for userid in to_call:
      # send call notification checks if is friend
      send_call_notification(userid, identity, groupid)
   
  if groupid != None: 
    analytics.track(identity, "group call made", {
      "group_id": groupid,
      "to": to_call
    })
  else:
    analytics.track(identity, "call made", {
      "to": to_call
    })

  print("granting token to "+identity)
  return token.to_jwt()

@app.route('/statusCallback', methods=['GET', 'POST'])
@validate_twilio_request
def statusCallback():
  event = request.values.get("StatusCallbackEvent")
  room = request.values.get("RoomName")
  user = request.values.get("ParticipantIdentity")
  print("event:", room, user, event)

  if room.startswith("private:"):
    if event == "participant-connected":
      set_in_call(True, user)
      analytics.track(user, "call entered", {})
    elif event == "participant-disconnected":
      set_in_call(False, user)
      analytics.track(user, "call left", {})
  elif room.startswith("group:"): # TODO
    groupid = room[6:]
    if event == "participant-connected":
      set_in_call(True, user, groupid)
      analytics.track(user, "group call entered", {
        "group_id": groupid
      })
    elif event == "participant-disconnected":
      set_in_call(False, user, groupid)
      analytics.track(user, "group call left", {
        "group_id": groupid
      })
  return ""  

if __name__ == "__main__":
  # start everyone not in call when server starts
  if not DEV:
      for doc in db.collection(USER_COLLECTION).get():
          doc.reference.update({"inCall": False})
      for doc in db.collection(GROUP_COLLECTION).get():
          for userid in doc.to_dict()["users"]:
              doc.reference.update({"users."+userid: False})
    
  app.run(host='0.0.0.0', port=PORT, debug=False)
