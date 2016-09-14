import base64
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

import requests

try:
    import simplejson as json
except ImportError:
    import json


class OAuth2(object):
    def __init__(self):
        self.client_id = 'ee79a182fe014e118499652fb92c95a6'  # IDM APP CLIENT ID
        self.client_secret = '39d0e791563b4216a740778ed7f258ef'  # IDM APP CLIENT SECRET

        raw_auth_code = '{}:{}'.format(self.client_id, self.client_secret)
        self.base_64_auth_code = base64.b64encode(raw_auth_code.encode('utf-8')).decode('utf-8')

        self.redirect_uri = 'http://192.168.99.100:8000/auth'  # CALLBACK URL REGISTERED ON IDM (UI APP AUTH ADDRESS)

        self.idm_address = 'http://0.0.0.0:8000/'  # IDM ADDRESS
        self.authorization_url = self.idm_address + 'oauth2/authorize'
        self.token_url = self.idm_address + 'oauth2/token'
        self.acess_token = ''

    def authorize_url(self, **kwargs):
        oauth_params = {'response_type': 'code', 'redirect_uri': self.redirect_uri, 'client_id': self.client_id}
        oauth_params.update(kwargs)
        return '{}?{}'.format(self.authorization_url, urlencode(oauth_params))

    def get_token(self, code):
        headers = {'Authorization': 'Basic {}'.format(self.base_64_auth_code),
                   'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': self.redirect_uri}
        response = requests.post(self.token_url, headers=headers, data=data)

        str_response_content = response.content.decode('utf-8')
        token_dict = json.loads(str_response_content)
        self.access_token = token_dict['access_token']
        return token_dict

    def get_user_info(self):
        s = requests.Session()

        response = requests.get(self.idm_address + '/user?access_token=' + self.acess_token)
        user_info = json.loads(response)
        return user_info