# open62541 JSON / XML corpus

`../open62541_corpus.json` is cross-stack evidence for `ua.EncodeJSON`,
`ua.DecodeJSON`, `ua.EncodeXML` and `ua.DecodeXML`. It was produced with
**open62541 v1.5.9** (default build: `UA_ENABLE_JSON_ENCODING=ON`,
`UA_ENABLE_XML_ENCODING=ON`, `UA_ENABLE_JSON_ENCODING_LEGACY=OFF`, i.e. the
OPC UA 1.05 JSON encoding) and is checked by `TestOpen62541Corpus` on every
test run, without Docker.

For every case in `corpusCases()` (`ua/open62541_corpus_test.go`) an entry
records:

| field | content |
|-------|---------|
| `binary` | the value in the binary DataEncoding (hex) - the neutral reference both stacks already agree on |
| `open62541Json`, `open62541Xml` | what `UA_encodeJson` / `UA_encodeXml` wrote for that value |
| `goJson`, `goXml` | what `ua.EncodeJSON` / `ua.EncodeXML` wrote for it |
| `goJsonDecodedByOpen62541`, `goXmlDecodedByOpen62541` | the binary encoding of what `UA_decodeJson` / `UA_decodeXml` read from the go-opcua document |

`ERR <StatusCode>` stands for a call that open62541 rejected.

The test asserts that go-opcua decodes the open62541 documents to `binary`,
that it still emits exactly `goJson` / `goXml`, and that open62541 decoded
those to `binary`. Where the stacks disagree the case must be listed in
`corpusDivergences` with the reason; a listed case that starts to agree fails
the test as well, so the list cannot go stale.

## Regenerating

`uacodec.c` is a ~90 line helper around the four open62541 functions that
talks hex over stdin/stdout; `Dockerfile` builds it against open62541 v1.5.9.

```sh
docker build -t go-opcua-uacodec ua/testdata/open62541
OPEN62541_UACODEC="docker run -i --rm go-opcua-uacodec" \
    go test ./ua -run TestOpen62541Corpus -count=1
docker rmi go-opcua-uacodec
```

The corpus only covers the OPC UA 1.05 JSON encoding, open62541's default.
The Dockerfile takes `--build-arg
OPEN62541_CMAKE_ARGS=-DUA_ENABLE_JSON_ENCODING_LEGACY=ON` for a helper that
speaks the 1.04 encoding instead; no corpus was recorded with it, so the
legacy reversible form of go-opcua is covered by its own round-trip and
golden tests only.

Regenerate after adding cases or after an intended change of what the
encoders emit, and review the diff of the corpus file.
