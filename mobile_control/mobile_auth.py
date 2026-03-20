import secrets
import frappe
from frappe import _
from frappe.utils import now_datetime, add_to_date, cstr, get_datetime


# Token TTL constants
ACCESS_TOKEN_HOURS = 24
REFRESH_TOKEN_DAYS = 30
OTP_MAX_PER_HOUR = 3


def _generate_token(nbytes=48):
	return secrets.token_urlsafe(nbytes)


def _get_user_roles(user):
	return frappe.get_roles(user)


def _get_mobile_form_names():
	"""Return list of enabled Mobile Form entries with doctype_meta_modifed_at (intentional typo)."""
	forms = frappe.get_all(
		"Mobile Form",
		filters={"enabled": 1},
		fields=["mobile_doctype", "group_name", "doctype_icon"],
	)
	result = []
	for form in forms:
		# Get the DocType's modified timestamp for metadata sync
		dt_modified = frappe.db.get_value("DocType", form.mobile_doctype, "modified")
		result.append({
			"mobile_doctype": form.mobile_doctype,
			"group_name": form.group_name,
			# INTENTIONAL TYPO: SDK parses "doctype_meta_modifed_at" (missing 'i')
			"doctype_meta_modifed_at": cstr(dt_modified),
			"doctype_icon": form.doctype_icon,
		})
	return result


def _get_user_permissions(user):
	"""Return per-DocType permissions for the given user."""
	mobile_forms = frappe.get_all(
		"Mobile Form",
		filters={"enabled": 1},
		fields=["mobile_doctype"],
	)

	permissions = {}
	for form in mobile_forms:
		doctype = form.mobile_doctype
		perms = frappe.permissions.get_doc_permissions(
			frappe.new_doc(doctype), user=user
		)
		permissions[doctype] = {
			"read": bool(perms.get("read")),
			"write": bool(perms.get("write")),
			"create": bool(perms.get("create")),
			"delete": bool(perms.get("delete")),
			"submit": bool(perms.get("submit")),
			"cancel": bool(perms.get("cancel")),
			"amend": bool(perms.get("amend")),
		}
	return permissions


def _create_tokens(user, device_uuid=None):
	"""Create access + refresh tokens and store in Mobile Auth Token."""
	access_token = _generate_token()
	refresh_token = _generate_token()
	now = now_datetime()

	frappe.get_doc({
		"doctype": "Mobile Auth Token",
		"user": user,
		"device_uuid": device_uuid or "",
		"access_token": access_token,
		"refresh_token": refresh_token,
		"access_token_expiry": add_to_date(now, hours=ACCESS_TOKEN_HOURS),
		"refresh_token_expiry": add_to_date(now, days=REFRESH_TOKEN_DAYS),
	}).insert(ignore_permissions=True)

	return access_token, refresh_token


def _build_login_response(user, device_uuid=None):
	"""Build the full login response expected by the SDK."""
	access_token, refresh_token = _create_tokens(user, device_uuid)

	full_name = frappe.db.get_value("User", user, "full_name") or ""
	roles = _get_user_roles(user)
	language = frappe.db.get_value("User", user, "language") or frappe.local.lang or "en"

	return {
		"access_token": access_token,
		"refresh_token": refresh_token,
		"user": user,
		"full_name": full_name,
		"roles": roles,
		"language": language,
		"permissions": _get_user_permissions(user),
		"mobile_form_names": _get_mobile_form_names(),
	}


def _check_otp_rate_limit(mobile_no):
	"""Enforce max OTP_MAX_PER_HOUR OTPs per mobile per hour using Redis."""
	cache_key = f"mobile_otp_count:{mobile_no}"
	count = frappe.cache.get(cache_key)

	if count and int(count) >= OTP_MAX_PER_HOUR:
		frappe.throw(
			_("Too many OTP requests. Please try again later."),
			frappe.RateLimitExceededError,
		)

	if count:
		frappe.cache.set(cache_key, int(count) + 1, expires_in_sec=3600)
	else:
		frappe.cache.set(cache_key, 1, expires_in_sec=3600)


def _format_mobile_number(mobile_no):
	"""Normalize mobile number: strip +, ensure 91 prefix for India."""
	mobile_no = cstr(mobile_no).strip()
	if mobile_no.startswith("+"):
		mobile_no = mobile_no[1:]
	if len(mobile_no) == 10:
		mobile_no = "91" + mobile_no
	return mobile_no


# ─────────────────────────────────────────────
# 1. login (username + password)
# ─────────────────────────────────────────────
@frappe.whitelist(allow_guest=True)
def login(username, password):
	"""Stateless login with username + password. Returns tokens + user info."""
	from frappe.auth import LoginManager

	login_manager = LoginManager()
	login_manager.authenticate(username, password)
	login_manager.post_login()

	user = frappe.session.user
	return _build_login_response(user)


# ─────────────────────────────────────────────
# 2. send_login_otp
# ─────────────────────────────────────────────
@frappe.whitelist(allow_guest=True)
def send_login_otp(mobile_no):
	"""Send OTP to mobile number. Returns tmp_id for verify step.

	Wraps frappe_msg91_integration.send_otp(). MSG91 generates the OTP
	server-side — we never see or store the OTP value.
	"""
	mobile_no = _format_mobile_number(mobile_no)
	_check_otp_rate_limit(mobile_no)

	# Find user by mobile number — check User doctype's mobile_no field
	user = frappe.db.get_value("User", {"mobile_no": mobile_no}, "name")
	if not user:
		# Also check with +91 prefix
		user = frappe.db.get_value("User", {"mobile_no": f"+{mobile_no}"}, "name")
	if not user:
		# Check 10-digit format
		if len(mobile_no) > 2 and mobile_no.startswith("91"):
			user = frappe.db.get_value("User", {"mobile_no": mobile_no[2:]}, "name")

	if not user:
		frappe.throw(_("No account found with this mobile number"), frappe.DoesNotExistError)

	from frappe_msg91_integration.msg91_integration.utils import send_otp

	result = send_otp(number=mobile_no, otp_length=6, otp_expiry=5)

	if not result.get("success"):
		frappe.throw(
			_("Failed to send OTP: {0}").format(result.get("error", "Unknown error")),
			frappe.ValidationError,
		)

	# Generate a tmp_id and cache the mapping tmp_id -> (mobile_no, user)
	tmp_id = secrets.token_urlsafe(32)
	frappe.cache.set(f"otp_tmp:{tmp_id}", {"mobile_no": mobile_no, "user": user}, expires_in_sec=600)

	return {"tmp_id": tmp_id}


# ─────────────────────────────────────────────
# 3. verify_login_otp
# ─────────────────────────────────────────────
@frappe.whitelist(allow_guest=True)
def verify_login_otp(tmp_id, otp):
	"""Verify OTP and complete login. Returns same shape as login().

	Wraps frappe_msg91_integration.verify_otp(). MSG91 verifies
	the OTP server-side.
	"""
	cached = frappe.cache.get(f"otp_tmp:{tmp_id}")
	if not cached:
		frappe.throw(_("OTP session expired or invalid"), frappe.AuthenticationError)

	mobile_no = cached["mobile_no"]
	user = cached["user"]

	from frappe_msg91_integration.msg91_integration.utils import verify_otp

	result = verify_otp(number=mobile_no, otp=cstr(otp))

	if not result.get("success"):
		frappe.throw(
			_("OTP verification failed: {0}").format(result.get("message", "Invalid OTP")),
			frappe.AuthenticationError,
		)

	# Clear the tmp_id from cache
	frappe.cache.delete(f"otp_tmp:{tmp_id}")

	# Set user session for the response
	frappe.set_user(user)

	return _build_login_response(user)


# ─────────────────────────────────────────────
# 4. refresh_token
# ─────────────────────────────────────────────
@frappe.whitelist(allow_guest=True)
def refresh_token(refresh_token):
	"""Refresh expired access token. Must be allow_guest because SDK
	clears the Bearer token before calling this endpoint.
	"""
	token_doc = frappe.db.get_value(
		"Mobile Auth Token",
		{"refresh_token": refresh_token},
		["name", "user", "refresh_token_expiry"],
		as_dict=True,
	)

	if not token_doc:
		frappe.throw(_("Invalid refresh token"), frappe.AuthenticationError)

	if now_datetime() > get_datetime(token_doc.refresh_token_expiry):
		# Clean up expired token
		frappe.delete_doc("Mobile Auth Token", token_doc.name, ignore_permissions=True)
		frappe.throw(_("Refresh token expired. Please login again."), frappe.AuthenticationError)

	# Delete old token
	frappe.delete_doc("Mobile Auth Token", token_doc.name, ignore_permissions=True)

	# Issue new tokens
	new_access_token, new_refresh_token = _create_tokens(token_doc.user)

	return {
		"access_token": new_access_token,
		"refresh_token": new_refresh_token,
	}


# ─────────────────────────────────────────────
# 5. me
# ─────────────────────────────────────────────
@frappe.whitelist()
def me():
	"""Return current user info. Requires Bearer token auth."""
	user = frappe.session.user
	if user == "Guest":
		frappe.throw(_("Not authenticated"), frappe.AuthenticationError)

	full_name = frappe.db.get_value("User", user, "full_name") or ""
	roles = _get_user_roles(user)
	language = frappe.db.get_value("User", user, "language") or frappe.local.lang or "en"

	return {
		"user": user,
		"full_name": full_name,
		"roles": roles,
		"language": language,
		"permissions": _get_user_permissions(user),
		"mobile_form_names": _get_mobile_form_names(),
	}


# ─────────────────────────────────────────────
# 6. configuration
# ─────────────────────────────────────────────
@frappe.whitelist()
def configuration():
	"""Return list of mobile forms with metadata timestamps.

	CRITICAL: Response includes 'doctype_meta_modifed_at' (intentional typo).
	The SDK parses this exact misspelled key. Do NOT fix the typo.
	"""
	return _get_mobile_form_names()


# ─────────────────────────────────────────────
# 7. permissions
# ─────────────────────────────────────────────
@frappe.whitelist()
def permissions():
	"""Return per-DocType permissions for the current user."""
	user = frappe.session.user
	if user == "Guest":
		frappe.throw(_("Not authenticated"), frappe.AuthenticationError)

	return {"permissions": _get_user_permissions(user)}


# ─────────────────────────────────────────────
# 8. get_translations
# ─────────────────────────────────────────────
@frappe.whitelist()
def get_translations(lang="en"):
	"""Return Frappe translations for the given language.

	Response format expected by SDK:
	{ "lang": "en", "translations": { "en": { "source": "translated", ... } } }
	"""
	from frappe.translate import get_all_translations

	translations = get_all_translations(lang)

	return {
		"lang": lang,
		"translations": {
			lang: translations or {},
		},
	}


# ─────────────────────────────────────────────
# 9. app_status (allow_guest — called before login)
# ─────────────────────────────────────────────
@frappe.whitelist(allow_guest=True)
def app_status():
	"""Return mobile app status for kill switch / force-update check.

	Called by SDK's FrappeAppGuard before auth. No Bearer token needed.
	"""
	try:
		settings = frappe.get_single("Mobile App Status")
	except frappe.DoesNotExistError:
		return {"enabled": True}

	return {
		"enabled": bool(settings.enabled),
		"package_name": settings.package_name or "",
		"app_title": settings.app_title or "",
		"version": settings.version or "",
		"store_url": settings.store_url or "",
	}
