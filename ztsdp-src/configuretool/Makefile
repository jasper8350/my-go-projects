BINARY_NAME=ztsdp_configtool

all: build

build: deps
	go build -o ${BINARY_NAME} main.go

deps: go.mod
	go mod tidy

clean:
	go clean
	rm -f ${BINARY_NAME}
