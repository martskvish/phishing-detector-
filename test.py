#Used to test the API system. 

import requests

response = requests.post(
    "http://127.0.0.1:5000/api/scan",
    json={
        "api_key": "876279b7225e308edf9914aa337469df2a1857c6f93689f5d0d8e764965b82046c757de7",
        "url": "https://www.charactercountonline.com/"
    }
)

print(response.json())