-module(eaws).
-include("include/eaws.hrl").

-compile(export_all).

connect() -> eaws_client:connect().

is_authed(_Client) -> false.

