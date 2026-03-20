import frappe
from frappe.utils import now_datetime


def cleanup_expired_tokens():
	"""Delete Mobile Auth Token records where both tokens have expired."""
	expired = frappe.get_all(
		"Mobile Auth Token",
		filters={"refresh_token_expiry": ["<", now_datetime()]},
		fields=["name"],
	)
	for token in expired:
		frappe.delete_doc("Mobile Auth Token", token.name, ignore_permissions=True)

	if expired:
		frappe.db.commit()
