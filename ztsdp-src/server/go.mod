module ztsdpd

go 1.21.5

//replace ztsdp => /home/jo/ALDER/branches/CURRENT/sdp/lib/go
replace ztsdp => /home/jasper/my-go-project/ztsdp-src/lib/go

require (
	github.com/coreos/go-iptables v0.7.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/gorilla/websocket v1.5.1
	github.com/txn2/txeh v1.5.5
	gopkg.in/yaml.v3 v3.0.1
	ztsdp v0.0.0-00010101000000-000000000000
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.30.0 // indirect
	github.com/pquerna/otp v1.4.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stretchr/testify v1.8.1 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)
