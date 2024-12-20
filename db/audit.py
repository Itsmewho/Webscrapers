import logging
from datetime import datetime
from db.db_operations import find_documents, insert_document
from utils.helpers import red, green, reset

#
# ---- For the audit logs --->
#

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def log_audit_event(user_id, email, action, details=None):

    try:
        audit_log = {
            "user_id": user_id,
            "email": email,
            "action": action,
            "details": details or {},
            "timestamp": datetime.now(),
        }
        insert_document("audit_log", audit_log)
        logger.info(
            green + f"Audit log created for user {email}, action: {action}" + reset
        )
    except Exception as e:
        logger.error(red + f"Failed to log audit event: {e}" + reset)


def get_audit_logs(user_id=None, action=None):
    query = {}
    if user_id:
        query["user_id"] = user_id
    if action:
        query["action"] = action

    logs = find_documents["audit_log"].find(query).sort("timestamp", -1)
    return sorted(logs, key=lambda x: x["timestamp"], reverse=True)
