all: build run

build:
	go mod tidy;
	go get -tool github.com/cilium/ebpf/cmd/bpf2go;
	go generate
	go build

run: build
	./ebpf-golang
