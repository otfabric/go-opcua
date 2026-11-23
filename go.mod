module github.com/otfabric/go-opcua

go 1.26.0

require (
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/cloudflare/circl v1.6.5
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.47.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/telemetry v0.0.0-20261116191925-e77a43154acb // indirect
	golang.org/x/tools v0.53.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	golang.org/x/tools/cmd/goimports
	golang.org/x/tools/cmd/stringer
)
