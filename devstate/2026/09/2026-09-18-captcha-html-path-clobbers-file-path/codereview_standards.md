# Standards

1. [hard] Name for the scope — `zzz_plugin_test.go:464` — `h` is a listed placeholder for the Bouncer `New` returns
   → Rename to `handler`
   Status: done
   Argument: renamed `h` to `handler` in both new tests (0ce9264).
2. [judgement] Mysterious Name — `zzz_plugin_test.go:456` — `au` is an author-only abbreviation for the parsed AppSec URL
   → Rename to `appsecURL`
   Status: skipped
   Argument: judgement; sibling tests already use `u` for a parsed URL, and `au` is not a listed placeholder.
3. [judgement] Duplicated Code — `zzz_plugin_test.go:448` — both new tests share AppSec-500 + reclaim + serve setup and differ by one path pair
   → Leave the two sibling tests; design asked for both named cases
   Status: skipped
   Argument: judgement; design asked for two named sibling tests; extract would be extra.
