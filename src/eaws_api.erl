-module(eaws_api).
-author('divolgin@liveperson.com').

-export([describe_addresses/0,
         associate_address/2]).

%-include("lookio.hrl").
-include_lib("xmerl/include/xmerl.hrl").

%-define(rec_info2(T,R),lists:zip(record_info(fields,T),tl(tuple_to_list(R)))).

signature(Access_Key_Id, Secret_Access_Key, get, Host, Path, Params) ->
  signature(Secret_Access_Key, get, Host, Path,
            [{"AWSAccessKeyId", Access_Key_Id},
             {"SignatureVersion", "2"},
             {"SignatureMethod", "HmacSHA256"},
             {"Version", "2013-08-15"},
             {"Timestamp", now_utc_str()}] ++ Params).


signature(Secret_Access_Key, get, Host, Path, Params) ->
  Concatenated = params_from_list(Params),
  % Note that ~n cannot be used instead of \n
  Signature_Params = lists:flatten(["GET\n",
                                    Host, "\n",
                                    Path, "\n",
                                    Concatenated]),
  {Concatenated, base64:encode_to_string(crypto:hmac(sha256, Secret_Access_Key, Signature_Params))}.


now_utc_str() ->
  {{Year, Month, Day}, {Hour, Min, Sec}} = calendar:now_to_universal_time(os:timestamp()),
  lists:flatten(io_lib:fwrite("~4..0B-~2..0B-~2..0BT~2..0B:~2.10.0B:~2.10.0BZ", [Year, Month, Day, Hour, Min, Sec])).


params_from_list(Params) ->
  Encoded = [{http_uri:encode(K), http_uri:encode(V)} || {K, V} <- Params],
  Sorted = lists:sort(Encoded),
  Concatenated = [lists:concat([K, "=", V]) || {K, V} <- Sorted],
  string:join(Concatenated, "&").


call_api(get, Path, Params) ->
  Access_Key_Id     = case application:get_env(eaws, access_key_id) of
                            undefined -> "MISSING_ACCESS_KEY";
                            {ok, V1}  -> V1
                        end,
  Secret_Access_Key = case application:get_env(eaws, secret_access_key) of
                            undefined -> "MISSING_SECRET_ACCESS_KEY";
                            {ok, V2}  -> V2
                        end,
  Proto = "https",
  Host = "ec2.amazonaws.com",
  {Param_String, Signature} = signature(Access_Key_Id,
            Secret_Access_Key,
            get,
            Host,
            Path,
            Params),
  Url = Proto ++ "://" ++ Host ++ Path ++ "?" ++ Param_String ++ "&Signature=" ++ http_uri:encode(Signature),
  case ibrowse:send_req(Url, [], get, [], []) of
    {ok, "200", Headers, Body} ->
      case proplists:get_value("Content-Type", Headers) of
        "text/xml;charset=UTF-8" -> {xml, Body};
        "text/xml" -> {xml, Body};
        _ ->
          %io:format("Unknown response format:~p, ~p", [Headers, Body]),
          error
      end;
    Other ->
      %io:format("AWS error:~p", [Other]),
      error
  end.


-spec associate_address(list() | binary(), list() | binary()) -> true | error.
associate_address(Instance_Id, Public_Ip) ->
  case call_api(get, "/", [{"Action", "AssociateAddress"},
                           {"InstanceId", to_list(Instance_Id)},
                           {"PublicIp", to_list(Public_Ip)}]) of
    {xml, Xml_Data} ->
      {Xml, _} = xmerl_scan:string(to_list(Xml_Data)),
      case content_to_text(xmerl_xs:select("return", Xml)) of
        <<"true">> -> true;
        _          -> error
      end;
    _ -> error
  end.


-spec describe_addresses() -> list() | error.
describe_addresses() ->
  case call_api(get, "/", [{"Action", "DescribeAddresses"}]) of
    {xml, Xml_Data} ->
      {Xml, _} = xmerl_scan:string(to_list(Xml_Data)),
      [Xml2 | _] = xmerl_xs:select("addressesSet", Xml),
      xml_list_to_list(Xml2#xmlElement.content);
    _ -> error
  end.


xml_list_to_list(Xml_List) ->
  lists:map(fun(#xmlElement{} = Element) ->
        {content_to_text(xmerl_xs:select("instanceId", Element)),
         content_to_text(xmerl_xs:select("publicIp", Element))}
    end, lists:filter(fun(#xmlElement{}) -> true;
        (_) -> false end, Xml_List)).


content_to_text([#xmlElement{} = Element]) ->
  case Element#xmlElement.content of
    [#xmlText{} = Xml | _] -> to_binary(Xml#xmlText.value);
    _ -> <<"">>
  end;

content_to_text([]) -> <<"">>.


to_list(Object) when is_binary(Object) -> binary_to_list(Object);
to_list(Object) when is_atom(Object) -> atom_to_list(Object);
to_list(Object) when is_list(Object) -> Object;
to_list(Object) when is_pid(Object) -> pid_to_list(Object);
to_list(Object) when is_number(Object) -> lists:flatten(io_lib:format("~p", [Object])).


to_binary(Object) when is_binary(Object) -> Object;
to_binary(Object) when is_list(Object) -> list_to_binary(Object);
to_binary(Object) when is_atom(Object) -> list_to_binary(atom_to_list(Object));
to_binary(Object) when is_number(Object) -> list_to_binary(to_list(Object)).

