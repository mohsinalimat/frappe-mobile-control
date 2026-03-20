import frappe
from frappe.utils import now_datetime


def validate_bearer_token():
	"""before_request hook: validates Authorization: Bearer tokens.

	If the request has a Bearer token, look it up in Mobile Auth Token,
	verify it's not expired, and set frappe.session.user accordingly.
	If no Bearer header is present, skip (let Frappe handle normal auth).
	"""
	auth_header = frappe.get_request_header("Authorization", "")
	if not auth_header.startswith("Bearer "):
		return

	token = auth_header[7:].strip()
	if not token:
		return

	token_doc = frappe.db.get_value(
		"Mobile Auth Token",
		{"access_token": token},
		["name", "user", "access_token_expiry"],
		as_dict=True,
	)

	if not token_doc:
		frappe.throw("Invalid or expired token", frappe.AuthenticationError)

	if now_datetime() > token_doc.access_token_expiry:
		frappe.throw("Access token expired", frappe.AuthenticationError)

	frappe.set_user(token_doc.user)
