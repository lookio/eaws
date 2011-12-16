-module(eaws_client).
-behaviour(gen_server).

-include("include/eaws.hrl").

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([connect/0,
         send_formatted_email/1]).

-record(state, {access_key_id, secret_access_key}).

escape_uri(S) when is_list(S) -> escape_uri(unicode:characters_to_binary(S));
escape_uri(<<C:8, Cs/binary>>) when C >= $a, C =< $z -> [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C >= $A, C =< $Z -> [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C >= $0, C =< $9 -> [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C == $. -> [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C == $- -> [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) when C == $_ -> [C] ++ escape_uri(Cs);
escape_uri(<<C:8, Cs/binary>>) -> escape_byte(C) ++ escape_uri(Cs);
escape_uri(<<>>) -> "".
escape_byte(C) -> "%" ++ hex_digit(C bsr 4) ++ hex_digit(C band 15).
hex_digit(D) when D =< 9 -> [$0 + D];
hex_digit(D)             -> [D - 10 + $A].

calculate_signature(Access_Key_Id, Secret_Access_Key) ->
    {Today, Time} = erlang:universaltime(),
    {{Year, Month, Day}, {Hour, Minute, Second}} = {Today, Time},
    Day_Name = httpd_util:day(calendar:day_of_the_week(Today)),
    Month_Name = httpd_util:month(Month),
    Date_String = lists:flatten(io_lib:format("~s, ~p ~s ~p ~2.10.0B:~2.10.0B:~2.10.0B +0000", [Day_Name, Day, Month_Name, Year, Hour, Minute, Second])),
    Signature = binary_to_list(base64:encode(crypto:sha_mac(list_to_binary(Secret_Access_Key), list_to_binary(Date_String)))),
    {Date_String, lists:flatten(io_lib:format("AWS3-HTTPS AWSAccessKeyId=~s, Algorithm=HMACSHA1, Signature=~s", [Access_Key_Id, Signature]))}.

connect() -> 
    Access_Key_Id     = case application:get_env(eaws, access_key_id) of
                            undefined -> "MISSING_ACCESS_KEY";
                            {ok, V1}  -> V1
                        end,
    Secret_Access_Key = case application:get_env(eaws, secret_access_key) of
                            undefined -> "MISSING_SECRET_ACCESS_KEY";
                            {ok, V2}  -> V2
                        end,

    gen_server:start_link({local, ?MODULE}, ?MODULE, 
                        [{access_key_id,     Access_Key_Id}, 
                         {secret_access_key, Secret_Access_Key}], []).

send_formatted_email(Params) ->
    Ses_Email = #ses_email{from      = proplists:get_value(from_address, Params),
                           to        = proplists:get_value(to_addresses, Params),
                           subject   = proplists:get_value(subject, Params),
                           text_body = proplists:get_value(text_body, Params),
                           html_body = proplists:get_value(html_body, Params)},

    gen_server:cast(?MODULE, {send_formatted_email, Ses_Email}).

init(Args) ->
    inets:start(),
    ssl:start(),
    crypto:start(),

    {ok, #state{access_key_id     = proplists:get_value(access_key_id, Args),
                secret_access_key = proplists:get_value(secret_access_key, Args)}}.


handle_call(Request, _From, State) -> {stop, {unknown_call, Request}, State}.

handle_cast({send_formatted_email, Ses_Email}, State) ->
    {Date, Signature} = calculate_signature(State#state.access_key_id, State#state.secret_access_key),
    Host = "email.us-east-1.amazonaws.com",

    io:format("Signature = ~p\n", [Signature]),
    Params = lists:append([{"Action",                 "SendEmail"}, 
                           {"Source",                 Ses_Email#ses_email.from},
                           {"Message.Subject.Data",   Ses_Email#ses_email.subject},
                           {"Message.Body.Text.Data", Ses_Email#ses_email.text_body},
                           {"Message.Body.Text.Html", Ses_Email#ses_email.html_body}],
                         lists:foldl(fun(To, {Count, B}) -> B ++ [{"Destination.ToAddresses.member." ++ integer_to_list(Count), To}] end, {1, []}, Ses_Email#ses_email.to)),

    % Remove any undefined params and build the body
    Body = string:strip(lists:foldl(fun({K, V}, Acc) -> Acc ++ "&" ++ K ++ "=" ++ escape_uri(V) end, "", lists:filter(fun({_, undefined}) -> false; (_) -> true end, Params)), left, $&),

    Headers = [{"X-Amzn-Authorization", Signature},
               {"Content-Type", "application/x-www-form-urlencoded"},
               {"Content-Length", length(Body)},
               {"Date", Date},
               {"Host", Host}],

    case httpc:request(post, {"https://" ++ Host ++ "/", Headers, "application/x-www-form-urlencoded", Body}, [], []) of
        O -> io:format("O = ~p\n", [O])
    end,

    {noreply, State};
handle_cast(_Msg, State) -> {noreply, State}.

handle_info(_Msg, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

