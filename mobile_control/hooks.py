app_name = "mobile_control"
app_title = "Mobile Control"
app_publisher = "DHWANI RIS"
app_description = "Mobile authentication and control endpoints for Frappe Mobile SDK"
app_email = "frappeteam@dhwaniris.com"
app_license = "mit"

required_apps = ["frappe_msg91_integration"]

# ─────────────────────────────────────────────
# Request Hooks — Bearer Token Middleware
# ─────────────────────────────────────────────
before_request = ["mobile_control.auth.validate_bearer_token"]

# ─────────────────────────────────────────────
# Whitelisted Methods — mobile_auth.* namespace
# SDK calls these as /api/method/mobile_auth.<endpoint>
# ─────────────────────────────────────────────
override_whitelisted_methods = {
	"mobile_auth.login": "mobile_control.mobile_auth.login",
	"mobile_auth.send_login_otp": "mobile_control.mobile_auth.send_login_otp",
	"mobile_auth.verify_login_otp": "mobile_control.mobile_auth.verify_login_otp",
	"mobile_auth.refresh_token": "mobile_control.mobile_auth.refresh_token",
	"mobile_auth.me": "mobile_control.mobile_auth.me",
	"mobile_auth.configuration": "mobile_control.mobile_auth.configuration",
	"mobile_auth.permissions": "mobile_control.mobile_auth.permissions",
	"mobile_auth.get_translations": "mobile_control.mobile_auth.get_translations",
	"mobile_auth.app_status": "mobile_control.mobile_auth.app_status",
}

# ─────────────────────────────────────────────
# Scheduled Tasks — Token Cleanup
# ─────────────────────────────────────────────
scheduler_events = {
	"daily": [
		"mobile_control.tasks.cleanup_expired_tokens",
	],
}
