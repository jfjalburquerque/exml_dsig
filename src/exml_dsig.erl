%%%-------------------------------------------------------------------
%%% @author jfjalburquerque
%%% @copyright (C) 2014
%%% @doc
%%%
%%% @end
%%% Created : 14. oct 2014 16:54
%%%-------------------------------------------------------------------
-module(exml_dsig).
-author("jfjalburquerque").

-include_lib("exmpp/include/exmpp_xml.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("../include/exml_dsig.hrl").

%% API
-export([verify/1]).

-spec verify(XML::xmlel()) -> true | false.

verify(XML) ->
    [XML2] = exmpp_xml:parse_document(XML),
    {ok, Params} = exml_dsig_parse:parse_xml(XML2),
    verify_signature(Params).

-spec verify_signature(#exml{}) -> true | false.

verify_signature(#exml{signature = #signature{value = SigValue},
        digest = #digest{method = DigMethod, value = DigValue}, xml_to_digest = DigObj, public_key = PK,
        signed_info_to_digest = SigObj}) ->
    case check_digests(DigValue, DigObj, DigMethod) of
        true ->
            ?debugFmt("true, SigObj:~p, DigMethod:~p, SigValue:~p, PK:~p", [SigObj, DigMethod, SigValue, PK]),
            [S] = exmpp_xml:parse_document(SigObj),
            {S2,_} = xmerl_scan:string(exmpp_xml:document_to_list(exmpp_xml:remove_whitespaces_deeply(S))),
            C14N = xmerl_c14n:c14n(S2),
            ?debugFmt("c14n: ~p", [C14N]),
            public_key:verify(list_to_binary(C14N), DigMethod, base64:decode(SigValue), PK);
        false -> false
    end.

check_digests(DigValue, DigObj, Method) ->
    ObjList = exmpp_xml:document_to_list((DigObj)),
    ?debugFmt("objlist:~p, DigValue:~p", [ObjList, DigValue]),
    Hash = crypto:hash(Method, ObjList),
    B64 = base64:encode(Hash),
    ?debugFmt("B64:~p", [B64]),
    B64 == DigValue.
