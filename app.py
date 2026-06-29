from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import re
import math

app = Flask(__name__)
CORS(app)

# ── MONGODB CONNECTION ────────────────────────────────────────
client = MongoClient("mongodb+srv://makwanamilan946_db_user:364515@cluster0.5dv5kpu.mongodb.net/?appName=Cluster0")
db = client["passguard"]
collection = db["checks"]
# ── PASSWORD ANALYSIS ─────────────────────────────────────────
def analyze_password(password):
    length = len(password)
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_lower   = bool(re.search(r'[a-z]', password))
    has_number  = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))
    no_repeats  = not bool(re.search(r'(.)\1{2,}', password))
    no_common   = password.lower() not in ['password','123456','qwerty','abc123','letmein','admin','welcome','pass@123']

    score = 0
    if length >= 8:  score += 15
    if length >= 12: score += 15
    if length >= 16: score += 10
    if has_upper:    score += 10
    if has_lower:    score += 10
    if has_number:   score += 10
    if has_special:  score += 15
    if no_repeats:   score += 10
    if no_common:    score += 5
    score = min(100, score)

    if score < 20:   label = "Very Weak"
    elif score < 40: label = "Weak"
    elif score < 60: label = "Fair"
    elif score < 80: label = "Strong"
    else:            label = "Very Strong"

    charset = 0
    if has_lower:   charset += 26
    if has_upper:   charset += 26
    if has_number:  charset += 10
    if has_special: charset += 32

    entropy = round(math.log2(charset ** length)) if charset > 0 else 0
    secs = (charset ** length) / 1e10 / 2 if charset > 0 else 0

    if secs < 1:         crack_time = "Instantly"
    elif secs < 60:      crack_time = f"{int(secs)} seconds"
    elif secs < 3600:    crack_time = f"{int(secs/60)} minutes"
    elif secs < 86400:   crack_time = f"{int(secs/3600)} hours"
    elif secs < 3.15e7:  crack_time = f"{int(secs/86400)} days"
    elif secs < 3.15e9:  crack_time = f"{int(secs/3.15e7)} years"
    else:                crack_time = "Millions of years"

    suggestions = []
    if length < 12:      suggestions.append("Use at least 12 characters")
    if not has_upper:    suggestions.append("Add uppercase letters (A-Z)")
    if not has_lower:    suggestions.append("Add lowercase letters (a-z)")
    if not has_number:   suggestions.append("Add numbers (0-9)")
    if not has_special:  suggestions.append("Add special characters (!@#$%)")
    if not no_repeats:   suggestions.append("Avoid repeating characters")
    if not no_common:    suggestions.append("Avoid common passwords")

    return {
        "score": score,
        "label": label,
        "length": length,
        "entropy": entropy,
        "crack_time": crack_time,
        "suggestions": suggestions,
        "checks": {
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_number": has_number,
            "has_special": has_special,
            "no_repeats": no_repeats,
            "no_common": no_common
        }
    }

def mask_password(pwd):
    if len(pwd) <= 2:
        return '*' * len(pwd)
    return pwd[0] + '*' * (len(pwd) - 2) + pwd[-1]

# ── ROUTES ────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'Password required'}), 400

    result = analyze_password(password)

    # Save to MongoDB
    record = {
        "password_masked": mask_password(password),
        "score": result["score"],
        "label": result["label"],
        "length": result["length"],
        "entropy": result["entropy"],
        "crack_time": result["crack_time"],
        "has_upper": result["checks"]["has_upper"],
        "has_lower": result["checks"]["has_lower"],
        "has_number": result["checks"]["has_number"],
        "has_special": result["checks"]["has_special"],
        "checked_at": datetime.now()
    }
    collection.insert_one(record)

    return jsonify(result)

@app.route('/api/history', methods=['GET'])
def get_history():
    records = list(collection.find({}, {'_id': 0}).sort('checked_at', -1).limit(20))
    for r in records:
        if 'checked_at' in r:
            r['checked_at'] = r['checked_at'].strftime('%d-%m-%Y %H:%M')
    return jsonify(records)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total = collection.count_documents({})
    if total == 0:
        return jsonify({'total': 0, 'avg_score': 0, 'strong_pct': 0})
    pipeline = [
        {"$group": {
            "_id": None,
            "avg_score": {"$avg": "$score"},
            "strong_count": {"$sum": {"$cond": [{"$gte": ["$score", 80]}, 1, 0]}}
        }}
    ]
    stats = list(collection.aggregate(pipeline))[0]
    return jsonify({
        'total': total,
        'avg_score': round(stats['avg_score'], 1),
        'strong_pct': round((stats['strong_count'] / total) * 100)
    })

# ── START ─────────────────────────────────────────────────────
if __name__ == '__main__':
    print("🚀 PassGuard Server Starting...")
    print("📡 Open: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)