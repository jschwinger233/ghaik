package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/jschwinger233/ghaik/bpf"
	"github.com/sirupsen/logrus"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

type bpfEvent struct {
	Pc          uint64
	Skb         uint64
	SecondParam uint64
	Mark        uint32
	Netns       uint32
	Ifindex     uint32
	Pid         uint32
	Ifname      [16]uint8
	Pname       [32]uint8
	Saddr       [16]byte
	Daddr       [16]byte
	Sport       uint16
	Dport       uint16
	L3Proto     uint16
	L4Proto     uint8
	TcpFlags    uint8
	PayloadLen  uint16
}

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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("failed to new reader", err)
		return
	}
	defer eventsReader.Close()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()

	writer, err := os.Create("/dev/stdout")
	if err != nil {
		return
	}

	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logrus.Debugf("failed to read ringbuf: %+v", err)
			continue
		}

		var event bpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), nativeEndian, &event); err != nil {
			logrus.Debugf("failed to parse ringbuf event: %+v", err)
			continue
		}

		sym := NearestSymbol(event.Pc)
		skb_ev := event
		fmt.Fprintf(writer, "%x mark=%x netns=%010d if=%d(%s) proc=%d(%s) ", skb_ev.Skb, skb_ev.Mark, skb_ev.Netns, skb_ev.Ifindex, TrimNull(string(skb_ev.Ifname[:])), skb_ev.Pid, TrimNull(string(skb_ev.Pname[:])))
		if event.L3Proto == syscall.ETH_P_IP {
			fmt.Fprintf(writer, "%s:%d > %s:%d ", net.IP(skb_ev.Saddr[:4]).String(), Ntohs(skb_ev.Sport), net.IP(skb_ev.Daddr[:4]).String(), Ntohs(skb_ev.Dport))
		} else {
			fmt.Fprintf(writer, "[%s]:%d > [%s]:%d ", net.IP(skb_ev.Saddr[:]).String(), Ntohs(skb_ev.Sport), net.IP(skb_ev.Daddr[:]).String(), Ntohs(skb_ev.Dport))
		}
		if event.L4Proto == syscall.IPPROTO_TCP {
			fmt.Fprintf(writer, "tcp_flags=%s ", TcpFlags(skb_ev.TcpFlags))
		}
		fmt.Fprintf(writer, "payload_len=%d ", event.PayloadLen)
		fmt.Fprintf(writer, "%s", sym.Name)
		fmt.Fprintf(writer, "\n")
	}

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
		kallsymsByName[name] = sym
		kallsymsByAddr[addr] = sym
	}
	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})
}

func NearestSymbol(addr uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int { return int(x.Addr - addr) })
	if idx == len(kallsyms) {
		return kallsyms[idx-1]
	}
	if kallsyms[idx].Addr == addr {
		return kallsyms[idx]
	}
	if idx == 0 {
		return kallsyms[0]
	}
	return kallsyms[idx-1]
}

func Htons(x uint16) uint16 {
	data := make([]byte, 2)
	nativeEndian.PutUint16(data, x)
	return binary.BigEndian.Uint16(data)
}

func Ntohs(x uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, x)
	return nativeEndian.Uint16(data)
}

func TrimNull(s string) string {
	return strings.TrimRight(s, "\x00")
}

func TcpFlags(data uint8) string {
	flags := []string{}
	if data&0b00100000 != 0 {
		flags = append(flags, "U")
	}
	if data&0b00010000 != 0 {
		flags = append(flags, ".")
	}
	if data&0b00001000 != 0 {
		flags = append(flags, "P")
	}
	if data&0b00000100 != 0 {
		flags = append(flags, "R")
	}
	if data&0b00000010 != 0 {
		flags = append(flags, "S")
	}
	if data&0b00000001 != 0 {
		flags = append(flags, "F")
	}
	return strings.Join(flags, "")
}
