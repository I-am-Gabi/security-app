import requests
from config import BaseConfig
from flask import Flask, render_template, request, redirect
from oauth_fiware import OAuth2

try:
    import simplejson as json
except ImportError:
    import json

app = Flask(__name__)
app.config.from_object(BaseConfig)

auth_code = ''
url_service = 'http://192.168.99.101:8000/'  # REST APP ADDRESS
auth_app = OAuth2()


@app.route('/reset')
@app.route('/')
def index():
    return render_template('index.html')


@app.route("/authenticate")
def authenticate():
    auth_url = auth_app.authorize_url()
    return redirect(auth_url)

@app.route("/authenticate")
def authenticate():
    auth_url = auth_app.authorize_url()
    return redirect(auth_url)


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error

    if request.method == 'GET':
        auth_code = request.args.get('code')
        token_dict = auth_app.get_token(auth_code)
        return render_template('index.html', content="access_token: " + token_dict['access_token'] + ", " +
                                                     "token_type: " + token_dict['token_type'] + ", " +
                                                     "expires_in: " + str(token_dict['expires_in']) + ", " +
                                                     "refresh_token: " + token_dict['refresh_token'])


@app.route("/username", methods=['GET'])
def username():
    response = requests.get(url_service + "service1/" + request.args.get('username'))
    return render_template('index.html', content=response.text)


@app.route("/list", methods=['GET'])
def list():
    response = requests.get(url_service + "service2/list")
    return render_template('index.html', content=response.text)


@app.route("/add", methods=['GET'])
def add():
    response = requests.get(url_service + "service2/add/" + request.args.get('name'))
    return render_template('index.html', content=response.url)


if __name__ == '__main__':
    app.run()
