# Standards

1. [hard] Leave a trail — `README.md:130` — architecture intro still says three pieces after the table gained captcha
   Fix: Count four independent pieces (LAPI, AppSec, captcha, and bouncer)
   Quote:
      ```
      One Traefik middleware object can run up to three independent pieces:

      | Piece | Flag | Job |
      | ----- | ---- | --- |
      | LAPI client | `lapiEnabled` | ...
      | AppSec client | `appsecEnabled` | ...
      | Captcha client | `captchaEnabled` | ...
      | Bouncer | `bouncerEnabled` | ...
      ```
   Status: done
   Argument: README architecture intro now says four independent pieces.
2. [hard] Leave a trail — `plugin.go:165` — claimOwned comment still names only AppSec→LAPI rollback after captcha failure also clears published LAPI and AppSec
   Fix: Say a later claim failure clears already-published legs (LAPI and AppSec when captcha’s SetAlias fails)
   Quote:
      ```
      // claimOwned publishes each owned instance name (SetAlias) to the Client Open just
      // created. A taken name fails New. If AppSec's claim fails after LAPI published,
      // drop the LAPI alias so we do not leave a half-claimed owner.
      ```
   Status: done
   Argument: claimOwned comment now names later-claim rollback of published LAPI and AppSec.
