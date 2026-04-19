module proxy-gateway

go 1.26.1

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/fergusstrange/embedded-postgres v1.34.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/jackc/pgx/v5 v5.9.1
	gopkg.in/yaml.v3 v3.0.1
	proxy-kit v0.0.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/lib/pq v1.12.1 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/sardanioss/http v1.2.0 // indirect
	github.com/sardanioss/httpcloak v1.6.1 // indirect
	github.com/sardanioss/net v1.2.5 // indirect
	github.com/sardanioss/qpack v0.6.3 // indirect
	github.com/sardanioss/quic-go v1.2.23 // indirect
	github.com/sardanioss/udpbara v1.1.0 // indirect
	github.com/sardanioss/utls v1.10.3 // indirect
	github.com/ua-parser/uap-go v0.0.0-20251207011819-db9adb27a0b8 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

replace proxy-kit => ../proxy-kit
