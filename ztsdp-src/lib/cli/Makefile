BINARY_NAME=sdp-prompt

all: build

build: deps
	go build -o ${BINARY_NAME} sdp-prompt.go

deps: go.mod
	go mod tidy

clean:
	go clean
	rm -f ${BINARY_NAME}
