package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/ghaik/bpf"
)

func main() {
	spec, err := bpf.LoadBpf()
	if err != nil {
		slog.Error("Failed to load BPF", "err", err)
		return
	}

	var opts ebpf.CollectionOptions
	objs := bpf.BpfObjects{}

	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		slog.Error(verifierLog, "err", err)
		return
	}

	cgroupPath, err := detectCgroupPath()

	for prog, attach := range map[*ebpf.Program]ebpf.AttachType{
		objs.CgroupSockRelease: ebpf.AttachCgroupInetSockRelease,
		objs.CgroupSockCreate:  ebpf.AttachCGroupInetSockCreate,
		objs.CgroupConnect4:    ebpf.AttachCGroupInet4Connect,
		objs.CgroupConnect6:    ebpf.AttachCGroupInet6Connect,
		objs.CgroupSendmsg4:    ebpf.AttachCGroupUDP4Sendmsg,
		objs.CgroupSendmsg6:    ebpf.AttachCGroupUDP6Sendmsg,
	} {
		cg, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Program: prog,
			Attach:  attach,
		})
		defer cg.Close()
		if err != nil {
			slog.Error("failed to attach cgroup", err)
		}
	}

	k, err := link.Kprobe("kfree_skbmem", objs.KprobeFreeSkb, nil)
	if err != nil {
		slog.Error("failed to attach kfree_skbmem", err)
		return
	}
	defer k.Close()

	targets, allocSkbFuncs, _, err := searchAvailableTargets()
	if err != nil {
		slog.Error("failed to find targets", err)
		return
	}
	allKaddrs := []uintptr{}
	for _, syms := range targets {
		for _, sym := range syms {
			allKaddrs = append(allKaddrs, uintptr(kallsymsByName[sym].Addr))
		}
	}
	krmulti, err := link.KretprobeMulti(objs.KretprobeSkb, link.KprobeMultiOptions{Addresses: allKaddrs})
	if err != nil {
		slog.Error("failed to attach kretprobe.multi", err)
		return
	}
	defer krmulti.Close()

	for prog, syms := range map[*ebpf.Program][]string{
		objs.KprobeSkb1: targets[0],
		objs.KprobeSkb2: targets[1],
		objs.KprobeSkb3: targets[2],
		objs.KprobeSkb4: targets[3],
		objs.KprobeSkb5: targets[4],
	} {
		addrs := []uintptr{}
		for _, sym := range syms {
			addrs = append(addrs, uintptr(kallsymsByName[sym].Addr))
		}
		kmulti, err := link.KprobeMulti(prog, link.KprobeMultiOptions{Addresses: addrs})
		if err != nil {
			slog.Error("failed to attach kprobe.multi", err)
			return
		}
		defer kmulti.Close()
	}

	krs, err := link.KretprobeMulti(objs.KretprobeAllocSkb, link.KprobeMultiOptions{Symbols: allocSkbFuncs})
	if err != nil {
		slog.Error("failed to attach __alloc_skb", err)
		return
	}
	defer krs.Close()

	println("tracing")
	time.Sleep(23333 * time.Second)

}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func searchAvailableTargets() (targets map[int][]string, allocSkbFuncs []string, kfreeSkbReasons map[uint64]string, err error) {
	targets = map[int][]string{}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load kernel BTF: %+v\n", err)
	}

	files, err := os.ReadDir("/sys/kernel/btf")
	if err != nil {
		log.Fatalf("Failed to read directory: %s", err)
	}

	iters := map[string]*btf.TypesIterator{
		"": btfSpec.Iterate(),
	}
	for _, file := range files {
		if !file.IsDir() && file.Name() != "vmlinux" {
			path := filepath.Join("/sys/kernel/btf", file.Name())

			f, err := os.Open(path)
			if err != nil {
				log.Fatalf("failed to open btf")
			}
			defer f.Close()

			modSpec, err := btf.LoadSplitSpecFromReader(f, btfSpec)
			if err != nil {
				log.Fatalf("failed to load spec")
			}
			iters[file.Name()] = modSpec.Iterate()
		}
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	ReadKallsyms()

	for kmod, iter := range iters {
		for iter.Next() {
			typ := iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			name := fn.Name
			if kmod != "" {
				name = fmt.Sprintf("%s [%s]", fn.Name, kmod)
			}
			if _, ok := availableFuncs[name]; !ok {
				continue
			}
			if _, ok := kallsymsByName[name]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			for i, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i < 5 {
							targets[i] = append(targets[i], name)
							continue
						}
					}
				}
			}
			if ptr, ok := fnProto.Return.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == "sk_buff" {
						allocSkbFuncs = append(allocSkbFuncs, fn.Name)
						continue
					}
				}
			}

		}
	}

	return targets, allocSkbFuncs, kfreeSkbReasons, nil
}

func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

type Symbol struct {
	Type string
	Name string
	Addr uint64
	Kmod string
}

var kallsyms []Symbol
var kallsymsByName map[string]Symbol = make(map[string]Symbol)
var kallsymsByAddr map[uint64]Symbol = make(map[uint64]Symbol)

func ReadKallsyms() {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		slog.Error("failed to open /proc/kallsyms: %v", err)
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		typ, name := parts[1], parts[2]
		kmod := ""
		if len(parts) >= 4 && parts[3][0] == '[' {
			kmod = parts[3]
		}
		sym := Symbol{typ, name, addr, kmod}
		kallsyms = append(kallsyms, sym)
		if kmod != "" {
			name = fmt.Sprintf("%s %s", name, kmod)
		}
		if parts[2] == "veth_xdp_rcv_skb" {
			println(name)
		}
		kallsymsByName[name] = sym
		kallsymsByAddr[addr] = sym
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}
