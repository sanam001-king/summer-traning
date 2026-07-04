from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')
    os_name = db.Column(db.String(50), default='Unknown')
    
    ports_services = db.Column(db.Text, default='[]')
    smb_shares = db.Column(db.Text, default='[]')
    snmp_data = db.Column(db.Text, default='{}')
    rpc_nfs_data = db.Column(db.Text, default='{}')
    security_alerts = db.Column(db.Text, default='[]')

    def to_dict(self):
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "timestamp": self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "status": self.status,
            "os_name": self.os_name,
            "ports_services": json.loads(self.ports_services),
            "smb_shares": json.loads(self.smb_shares),
            "snmp_data": json.loads(self.snmp_data),
            "rpc_nfs_data": json.loads(self.rpc_nfs_data),
            "security_alerts": json.loads(self.security_alerts)
        }