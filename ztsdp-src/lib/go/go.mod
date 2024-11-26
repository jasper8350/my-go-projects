module ztsdp

go 1.21.5

replace ztsdp => /home/jo/ALDER/branches/CURRENT/sdp/lib/go

require (
	github.com/go-sql-driver/mysql v1.8.1
	github.com/pquerna/otp v1.4.0
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)
