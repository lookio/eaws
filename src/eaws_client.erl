-module(eaws_client).
-behaviour(gen_server).

-include("include/eaws.hrl").

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([connect/0,
         connect/2,
         send_formatted_email/1,
         send_raw_email/1]).

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
    connect(Access_Key_Id, Secret_Access_Key).

connect(Access_Key_Id, Secret_Access_Key) -> 
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

send_raw_email(Params) ->
    Ses_Email = #ses_email{from      = proplists:get_value(from_address, Params),
                           to        = proplists:get_value(to_addresses, Params),
                           subject   = proplists:get_value(subject, Params),
                           text_body = proplists:get_value(text_body, Params),
                           html_body = proplists:get_value(html_body, Params),
                           file_names = proplists:get_value(file_names, Params, [])},

    gen_server:cast(?MODULE, {send_raw_email, Ses_Email}).

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
                         lists:foldl(fun(To, B) -> B ++ [{"Destination.ToAddresses.member." ++ integer_to_list(length(B) + 1), To}] end, [], Ses_Email#ses_email.to)),

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

handle_cast({send_raw_email, Ses_Email}, State) ->
    {Date, Signature} = calculate_signature(State#state.access_key_id, State#state.secret_access_key),
    Host = "email.us-east-1.amazonaws.com",
    Part_Separator = "_003_97DCB304C5294779BEBCFC8357FCC4D2",

    Message_Text = string:join([
      "Content-Type: text/plain; charset=\"us-ascii\"",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      ensure_list(Ses_Email#ses_email.text_body),
      "",
      "--" ++ Part_Separator], "\n"),

    %% TODO: Get create and modification dates from file
    %% TODO: Map extensions to Content-Type as allowed by amazon (http://docs.aws.amazon.com/ses/latest/DeveloperGuide/mime-types.html)
    %% TODO: Allow attaching from memory buffers, not just files
    %% TODO: Generate unique message IDs
    All_Parts = lists:foldl(fun(File_Name, Cur_Parts) ->
        Display_File_Name = ensure_list(filename:basename(File_Name)),
        File_Size = filelib:file_size(File_Name),
        {ok, Bin_Content} = file:read_file(File_Name),
        Part = string:join([
            "Content-Type: application/octet-stream; name=\"" ++ Display_File_Name ++ "\"",
            "Content-Description: " ++ Display_File_Name,
            "Content-Disposition: attachment; " ++
             "filename=\"" ++ Display_File_Name ++ "\"; " ++
             "size=" ++ ensure_list(File_Size) ++ "; " ++
             "creation-date=\"" ++ Date ++ "\"; " ++
             "modification-date=\"" ++ Date ++ "\"",
            "Content-Transfer-Encoding: base64",
            "",
            base64:encode_to_string(Bin_Content),
            "",
            "--" ++ Part_Separator], "\n"),
        [Part] ++ Cur_Parts end, [Message_Text], Ses_Email#ses_email.file_names),

    lists:foreach(fun(To) ->
      Message_Header = string:join([
        "From: " ++ ensure_list(Ses_Email#ses_email.from),
        "To: " ++ ensure_list(To),
        "Date: " ++ Date,
        "Subject: " ++ ensure_list(Ses_Email#ses_email.subject),
        "Message-ID: " ++ "<97DCB304-C529-4779-BEBC-FC8357FCC4D2@amazon.com>",
        "Accept-Language: en-US",
        "Content-Language: en-US",
        "Content-Type: multipart/mixed; boundary=\"" ++ Part_Separator ++ "\"",
        "MIME-Version: 1.0",
        "",
        "--" ++ Part_Separator], "\n"),

      Message = Message_Header ++ "\n" ++
                string:join(All_Parts, "\n"),

      Params = [{"Action",                 "SendRawEmail"},
                {"RawMessage.Data",        base64:encode(Message)}],

      Body = mochiweb_util:urlencode(Params),

      Headers = [{"X-Amzn-Authorization", Signature},
                 {"Content-Type", "application/x-www-form-urlencoded"},
                 {"Content-Length", length(Body)},
                 {"Date", Date},
                 {"Host", Host}],

      Result = httpc:request(post, {"https://" ++ Host ++ "/", Headers, "application/x-www-form-urlencoded", Body}, [], []),
      io:format("Result = ~p\n", [Result]) end,
                  Ses_Email#ses_email.to),

    {noreply, State};

handle_cast(_Msg, State) -> {noreply, State}.

handle_info(_Msg, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

ensure_list(Val) when is_binary(Val) -> binary_to_list(Val);
ensure_list(Val) when is_list(Val) -> Val;
ensure_list(Val) when is_integer(Val) -> integer_to_list(Val);
ensure_list(Val) -> binary_to_list(term_to_binary(Val)).
