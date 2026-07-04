from flask import Flask, render_template, request, jsonify
from models import db, ScanHistory
from scanner import run_dynamic_network_assessment, get_active_interfaces
import json
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///enumeration.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SmartEnumeration")
file_handler = RotatingFileHandler('execution_surface.log', maxBytes=2*1024*1024, backupCount=3)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(file_handler)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/interfaces', methods=['GET'])
def get_networks():
    """Exposes current active Wi-Fi and LAN interface segments to the UI dashboard."""
    discovered_nets = get_active_interfaces()
    return jsonify(discovered_nets)

@app.route('/api/scan', methods=['POST'])
def start_assessment():
    data = request.get_json() or {}
    target = data.get('target')
    
    if not target:
        return jsonify({"error": "A target IP or subnet range configuration is required."}), 400
        
    logger.info(f"[ENGINE] Launching infrastructure map execution against: {target}")
    
    try:
        network_map = run_dynamic_network_assessment(target)
        saved_records = []
        
        for host_ip, host_data in network_map.items():
            new_record = ScanHistory(
                target_ip=host_ip,
                status="Completed",
                os_name=host_data["os"],
                ports_services=json.dumps(host_data["ports"]),
                snmp_data=json.dumps(host_data["cves"]), 
                rpc_nfs_data=json.dumps(host_data["exploits"])
            )
            db.session.add(new_record)
            saved_records.append(new_record)
            
        db.session.commit()
        
        if saved_records:
            return jsonify(saved_records[0].to_dict())
        return jsonify({"message": "No responding local assets located.", "ports_services": []})
        
    except Exception as e:
        logger.error(f"[CRITICAL] Operational failure map trace: {str(e)}")
        return jsonify({"error": f"Internal mapping core execution failure: {str(e)}"}), 500

@app.route('/api/history', methods=['GET'])
def get_history_ledger():
    records = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
    return jsonify([r.to_dict() for r in records])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)