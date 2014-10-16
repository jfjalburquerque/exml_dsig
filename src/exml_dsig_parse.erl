%%%-------------------------------------------------------------------
%%% @author jfjalburquerque
%%% @copyright (C) 2014
%%% @doc
%%%
%%% @end
%%% Created : 14. oct 2014 18:08
%%%-------------------------------------------------------------------
-module(exml_dsig_parse).
-author("jfjalburquerque").

-include_lib("exmpp/include/exmpp_xml.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("../include/exml_dsig.hrl").

%% API
-export([parse_xml/1]).

-spec parse_xml(XML:: xmlel()) -> {ok, #exml{}} | {error, bad_format}.

parse_xml(XML) ->
    try
        {ok, Params} = get_digest(XML, #exml{xml = XML}),
        ?debugFmt("params:~p", [Params]),
        {ok, Params2} = get_signature(XML, Params),?debugFmt("params2:~p", [Params2]),
        {ok, Params3} = get_public_key(XML, Params2),?debugFmt("params3:~p", [Params3]),
        {ok, Params4} = get_object_to_digest(XML, Params3),
        {ok, Params5} = get_signature_to_digest(XML, Params4),
        ?debugFmt("params4:~p", [Params5]),
        case Params5 of
            #exml{digest = #digest{value = <<>>}} ->
                {error, bad_format};
            #exml{signature = #signature{value = <<>>}} ->
                {error, bad_format};
            #exml{xml_to_digest = undefined} ->
                {error, bad_format};
            _ ->
                {ok, Params5}
        end
    catch _:_ ->
        {error, bad_format}
    end.


get_digest(XML, Params) ->
    SignedInfo = exmpp_xml:get_element(XML, 'SignedInfo'),
    Reference = exmpp_xml:get_element(SignedInfo, 'Reference'),
    DigestMethod = exmpp_xml:get_attribute(exmpp_xml:get_element(Reference, 'DigestMethod'), <<"Algorithm">>, undefined),
    DigestValue = exmpp_xml:get_cdata(exmpp_xml:get_element(Reference, 'DigestValue')),
    Digest = #digest{value = DigestValue, method = get_method(DigestMethod)},
    {ok, Params#exml{digest = Digest}}.

get_signature(XML, Params) ->
    SignatureValue = exmpp_xml:get_cdata(exmpp_xml:get_element(XML, 'SignatureValue')),
    SignedInfo = exmpp_xml:get_element(XML, 'SignedInfo'),
    SignatureMethod = exmpp_xml:get_attribute(exmpp_xml:get_element(SignedInfo, 'SignatureMethod'), <<"Algorithm">>, undefined),
    Signature = #signature{value = SignatureValue, method = SignatureMethod},
    {ok, Params#exml{signature = Signature}}.

get_public_key(XML, Params) ->
    KeyInfo = exmpp_xml:get_element(XML, 'KeyInfo'),
    ?debugMsg("ccc"),
    KeyValue = exmpp_xml:get_element(KeyInfo, 'KeyValue'),
    ?debugMsg("bbb"),
    RSAKeyValue = exmpp_xml:get_element(KeyValue, 'RSAKeyValue'),
    ?debugFmt("aaa, ~p", [RSAKeyValue]),
    Modulus = base64:decode(exmpp_xml:get_cdata(exmpp_xml:get_element(RSAKeyValue, 'Modulus'))),
    ?debugFmt("modulus:~p", [Modulus]),
    Exponent = base64:decode(exmpp_xml:get_cdata(exmpp_xml:get_element(RSAKeyValue, 'Exponent'))),
    ?debugFmt("exponent:~p", [Exponent]),
    {ok, Params#exml{public_key = #'RSAPublicKey'{modulus = Modulus, publicExponent = Exponent}}}.

get_object_to_digest(XML, Params) ->
    Object = exmpp_xml:get_element(XML, 'Object'),
    NS = XML#xmlel.ns,
    {ok, Params#exml{xml_to_digest = Object#xmlel{ns = NS}}}.

get_signature_to_digest(XML, Params) ->
    SignedInfo = exmpp_xml:get_element(XML, 'SignedInfo'),
    NewSignedInfo = exmpp_xml:document_to_binary(SignedInfo#xmlel{ns = XML#xmlel.ns}),
    {ok, Params#exml{signed_info_to_digest = NewSignedInfo}}.


get_method(Method) ->
    case Method of
        ?SHA1 -> 'sha';
        ?SHA256 -> 'sha256';
        ?SHA512 -> 'sha512';
        _ -> undefined
    end.