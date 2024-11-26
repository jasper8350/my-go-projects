BINARY_NAME=ztsdpd

all: build

build: deps
	go build -o ${BINARY_NAME} ztsdpd.go auth_manager.go hmac_auth_manager.go iptable_manager.go keycloak_manager.go mtls_service.go interface_manager.go

deps: go.mod
	go mod tidy

go.mod:
	go mod init ztsdpd
	echo "replace ztsdp => ${GNWORKDIR}/sdp/lib/go" >> go.mod

docker:
	sudo docker build -t ztsdpd .

clean:
	go clean
	rm -f ${BINARY_NAME}
