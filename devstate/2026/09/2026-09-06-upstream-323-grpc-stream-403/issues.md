# Issues

- [ ] note large  opt-in drop for unreadable AppSec bodies (`CrowdsecAppsecUnreadableBodyBlock` / lua `APPSEC_DROP_UNREADABLE_BODY`) after this change always headers-only GETs streams
  Why: operators who want fail-closed on uninspectable gRPC/HTTP2 bodies lose the folded `ban` drop. Not taken: ticket asks for pass-through; the bool was already removed in fail-mode.
