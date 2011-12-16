-module(eaws_sup).
-behaviour(supervisor).

-export([start_link/0, client/0, init/1]).

start_link() -> {ok, Pid} = supervisor:start_link({local, ?MODULE}, ?MODULE, []),
                {ok, Pid, client()}.

client()     -> [{eaws_client, Client, worker, [eaws_client]}] = supervisor:which_children(?MODULE),
                Client.

init(_Args)  -> {ok, {{one_for_one, 1, 60}, [
                {eaws_client, {eaws_client, connect, []}, transient, 500, worker, [eaws_client]}]}}.
