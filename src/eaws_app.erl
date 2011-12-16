-module(eaws_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) -> eaws_sup:start_link().
stop(_Client) -> ok.
