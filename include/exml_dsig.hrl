-record(digest, {
    value :: binary(),
    method :: list()
}).

-record(signature, {
    value :: binary(),
    method :: list()
}).

-record(exml, {
    digest :: #digest{},
    signature :: #signature{},
    public_key,
    xml_to_digest,
    signed_info_to_digest,
    xml
}).

-define(SHA1, <<"http://www.w3.org/2000/09/xmldsig#sha1">>).
-define(SHA256, <<"http://www.w3.org/2001/04/xmlenc#sha256">>).
-define(SHA512, <<"http://www.w3.org/2001/04/xmlenc#sha512">>).