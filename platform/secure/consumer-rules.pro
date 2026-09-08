# Rules applied to any app consuming :platform:secure.
#
# Nothing here is reflective, so nothing needs keeping. The one rule that matters is
# negative: this module must not cause a consumer to retain debugging metadata about
# key handling.
-renamesourcefileattribute ""
