-module(eaws_tests).

-include_lib("eunit/include/eunit.hrl").
-include("include/eaws.hrl").

auth_test() ->
  {ok, Client} = eaws:connect(),
  ?assert(eaws:is_authed(Client)).


