#V3 API
import http.client
import json

conn = http.client.HTTPSConnection("api.gpt.ge")
payload = ''
headers = {
   'Authorization': 'Bearer ',
   'Content-Type': 'application/json'
}
conn.request("GET", "/v1/models", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))

#Base
import os
OPENAI_BASE_URL = os.environ.get('API_BASE')
OPENAI_KEY = os.environ.get('API_KEY')
MODEL_NAME = os.environ.get('API_MODEL')

if OPENAI_BASE_URL is None:
    OPENAI_BASE_URL = 'https://api.gptapi.us/v1'

if OPENAI_KEY is None:
    OPENAI_KEY = 'sk-LteIytwwtWtrsZuh5285C3897e2c4a2aB556DaD73a8cCf69'
    MODEL_NAME = 'gpt-4o-mini'
    
if MODEL_NAME is None:
    MODEL_NAME = 'tq-gpt'