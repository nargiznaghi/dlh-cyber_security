from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    "admin": "DLH{example_flag_here}",
    "alice": None,
    "bob": None
}

@app.route("/api/check_username")
def check_username():
    username = request.args.get("username")
    if username in users:
        return jsonify({"exists": True, "flag": users[username]})
    return jsonify({"exists": False})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
