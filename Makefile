build: 
	go build -o build/clavis ./internal/cmd/server/

build-static:
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o build/clavis ./internal/cmd/server

run: build 
	./build/clavis
	
	
