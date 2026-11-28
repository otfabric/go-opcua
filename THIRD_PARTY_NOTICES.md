# Third-party notices

go-opcua is licensed under the MIT License ([LICENSE](LICENSE)). The
repository also contains files of the OPC Foundation, kept unmodified as
inputs of the generators and as test data. They are listed here with their
source and terms; their rights stay with their owner.

## OPC UA NodeSets and schema files (UA-Nodeset)

Source: <https://github.com/OPCFoundation/UA-Nodeset>, at the commits pinned
in [schema/manifest.json](schema/manifest.json).

Files: every input `schema/manifest.json` lists, that is

- `schema/*.csv` and `schema/*.bsd`
- `internal/schema/Opc.Ua.NodeSet2.xml`, `internal/schema/Opc.Ua.Gds.NodeSet2.xml`
- `uafx/internal/model/*.xml` (the UAFX and DI NodeSets)
- `server/aggregate/testdata/AggregateExamples.csv`

and `examples/server/NodeSet2_server/Opc.Ua.Di.NodeSet2.xml`, a DI NodeSet of the
same repository.

License: MIT, as stated in the LICENSE.md of that repository, whose copyright
line reads "Copyright (c) 2005-2026, OPC Federation AISBL, All rights
reserved."

## OPC UA profile set (Profile Reporting Application)

Source: the export of the Released UACore 1.05 profile group of the OPC
Foundation Profile Reporting Application, <https://profiles.opcfoundation.org/>,
retrieved and pinned as recorded in
[internal/profiles/testdata/ProfileSet_UACore_1.05.source.json](internal/profiles/testdata/ProfileSet_UACore_1.05.source.json)
(URL, date and SHA-256).

File: `internal/profiles/testdata/ProfileSet_UACore_1.05.xml`

Terms: the export and the application state no license. The file is
© OPC Foundation and is included unmodified, only as the input from which
`make gen` derives the profile and conformance unit inventory
([docs/profiles.md](docs/profiles.md)); it is not compiled into the library.
It is not covered by the MIT License of go-opcua. Anyone who redistributes
it should check the OPC Foundation's terms for the profile data.
