.PHONY: all server client clean release

all: server client

server:
	go build -o nekopass-lite-server ./cmd/server

client:
	go build -o nekopass-lite-client ./cmd/client

clean:
	rm -f nekopass-lite-server nekopass-lite-client

release:
	GOOS=linux GOARCH=amd64 go build -o release/nekopass-lite-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -o release/nekopass-lite-client-linux-amd64 ./cmd/client
	GOOS=linux GOARCH=arm64 go build -o release/nekopass-lite-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -o release/nekopass-lite-client-linux-arm64 ./cmd/client
	GOOS=darwin GOARCH=arm64 go build -o release/nekopass-lite-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -o release/nekopass-lite-client-darwin-arm64 ./cmd/client
	GOOS=windows GOARCH=amd64 go build -o release/nekopass-lite-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -o release/nekopass-lite-client-windows-amd64.exe ./cmd/client
