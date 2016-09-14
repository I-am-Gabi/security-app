from config import BaseConfig
from flask import Flask, jsonify

app = Flask(__name__)
app.config.from_object(BaseConfig)


@app.route('/service1')
@app.route('/service1/<username>')
def hello(username=None):
    if not username:
        return jsonify(result='Hello World', status=200)
    return jsonify(result='Hello World! {}'.format(username), status=200)


@app.route('/service2/list')
def list():
    list_users = ['gabi', 'lucas', 'felipe']
    return jsonify(result=tuple(list_users), status=200)


@app.route('/service2/add/<username>')
def add(username=None):
    list_users = ['gabi', 'lucas', 'felipe']
    if not username:
        return jsonify(result=tuple(list_users), status=200)
    list_users.append(username)
    return jsonify(result=tuple(list_users), status=200)


if __name__ == '__main__':
    app.run()
