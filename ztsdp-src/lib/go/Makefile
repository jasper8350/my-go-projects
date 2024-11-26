BINARY_NAME=ztsdp

all: build

build: deps
	go get github.com/pquerna/otp/totp
	go build -o ${BINARY_NAME} ztsdp.go logging.go

deps: go.mod
	go mod tidy

go.mod:
	go mod init ztsdp
	echo "replace ztsdp => ${GNWORKDIR}/sdp/lib/go" >> go.mod

clean:
	go clean
	rm -f ${BINARY_NAME}
