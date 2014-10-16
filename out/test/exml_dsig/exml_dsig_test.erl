%%%-------------------------------------------------------------------
%%% @author jfjalburquerque
%%% @copyright (C) 2014
%%% @doc
%%%
%%% @end
%%% Created : 14. oct 2014 17:01
%%%-------------------------------------------------------------------
-module(exml_dsig_test).
-author("jfjalburquerque").

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").


verify_xml_cert_test_() ->
    Xml = get_xml(),
    ?assertEqual(true, exml_dsig:verify(Xml)).




get_xml() ->
    <<"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">
        <SignedInfo>
          <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />
          <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" />
          <Reference URI=\"#object\">
            <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />
            <DigestValue>OPnpF/ZNLDxJ/I+1F3iHhlmSwgo=</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>nihUFQg4mDhLgecvhIcKb9Gz8VRTOlw+adiZOBBXgK4JodEe5aFfCqm8WcRIT8GL
        LXSk8PsUP4//SsKqUBQkpotcAqQAhtz2v9kCWdoUDnAOtFZkd/CnsZ1sge0ndha4
        0wWDV+nOWyJxkYgicvB8POYtSmldLLepPGMz+J7/Uws=</SignatureValue>
        <KeyInfo>
          <KeyValue>
            <RSAKeyValue>
              <Modulus>4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqC
              UQ8wgL6xUJ5GRPEsu9gyz8ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm
              +Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=</Modulus>
              <Exponent>AQAB</Exponent>
            </RSAKeyValue>
          </KeyValue>
        </KeyInfo>
        <Object Id=\"object\">some text
          with spaces and CR-LF.</Object>
    </Signature>">>.