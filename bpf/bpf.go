package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-15 -no-strip -target native -type event Bpf ./ghaik.c -- -I./headers -I. -Wall
