import os
from flask import Flask, request, render_template, redirect, url_for, send_file, jsonify, send_from_directory
from models import init_db, SessionLocal, Alert
from parser import parse_pcap, parse_access_log
from detectors import run_all
import pandas as pd
import io

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

init_db()

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/media/<path:filename>')
def media(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/capabilities')
def capabilities():
    return render_template('capabilities.html')

@app.route('/architecture')
def architecture():
    return render_template('architecture.html')


@app.route('/showcase')
def showcase():
    return render_template('showcase.html')

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('file')
    if not f:
        return 'no file', 400
    fname = os.path.join(UPLOAD_FOLDER, f.filename)
    f.save(fname)
    ext = f.filename.lower().split('.')[-1]
    records = []
    if ext in ['pcap','pcapng']:
        records = parse_pcap(fname)
    else:
        records = parse_access_log(fname)
    session = SessionLocal()
    recent_login_attempts = []
    for r in records:
        alerts = run_all(r, recent_login_attempts=recent_login_attempts)
        for note, conf in alerts:
            a = Alert(src_ip=r.get('src_ip',''), dst_ip=r.get('dst_ip',''), http_method=r.get('method',''), url=r.get('url',''), params=str(r.get('params','')), user_agent=r.get('user_agent',''), attack_type=note, confidence=conf, raw=r.get('raw',''))
            session.add(a)
    session.commit()
    session.close()
    return redirect(url_for('service'))

@app.route('/alerts')
def alerts_api():
    q = request.args.get('q')
    attack = request.args.get('attack')
    session = SessionLocal()
    query = session.query(Alert)
    if attack:
        query = query.filter(Alert.attack_type == attack)
    rows = query.order_by(Alert.timestamp.desc()).limit(200).all()
    out = []
    for r in rows:
        out.append({
            'id': r.id,
            'timestamp': r.timestamp.isoformat(),
            'src_ip': r.src_ip,
            'dst_ip': r.dst_ip,
            'method': r.http_method,
            'url': r.url,
            'attack': r.attack_type,
            'confidence': r.confidence,
            'raw': r.raw
        })
    session.close()
    return jsonify(out)

@app.route('/export')
def export():
    fmt = request.args.get('fmt','csv')
    session = SessionLocal()
    rows = session.query(Alert).all()
    data = []
    for r in rows:
        data.append({'id':r.id,'timestamp':r.timestamp,'src_ip':r.src_ip,'url':r.url,'attack':r.attack_type,'confidence':r.confidence})
    df = pd.DataFrame(data)
    buf = io.BytesIO()
    if fmt=='csv':
        df.to_csv(buf, index=False)
        buf.seek(0)
        return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='alerts.csv')
    else:
        s = df.to_json(orient='records', date_format='iso')
        return jsonify({'data': s})

if __name__ == '__main__':
    app.run(debug=True)
