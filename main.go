package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
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

type Symbol struct {
	Type string
	Name string
	Addr uint64
	Kmod string
}

// Types that match the constants in the BPF program
// This matches the 'struct config' in the BPF program
type BpfConfig struct {
	Pname [16]byte
	Plen  uint32
}

var (
	kallsyms       []Symbol
	kallsymsByName = make(map[string]Symbol)
	kallsymsByAddr = make(map[uint64]Symbol)
)

func main() {
	var filterProcessName string
	flag.StringVar(&filterProcessName, "p", "", "Process name to filter (up to 16 characters)")
	flag.Parse()

	if filterProcessName == "" {
		fmt.Println("No process name provided. Use -p flag to specify a process name.")
		os.Exit(1)
	}
	if err := run(filterProcessName); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run(processName string) error {
	spec, err := bpf.LoadBpf()
	if err != nil {
		return fmt.Errorf("failed to load BPF: %w", err)
	}

	// Pass the process filter to the BPF program if provided
	if processName != "" {
		for varName, varSpec := range spec.Variables {
			println("Variable name:", varName, "Variable spec:", varSpec)
		}
		configVar, ok := spec.Variables["CONFIG"]
		if !ok {
			return fmt.Errorf("'CONFIG' variable not found in BPF program")
		}

		// Create and populate the configuration structure
		config := BpfConfig{}

		// Copy process name to the Pname field, ensuring we don't exceed the array size
		copy(config.Pname[:], processName)

		// Set the length of the process name
		nameLen := len(processName)
		if nameLen > len(config.Pname) {
			nameLen = len(config.Pname)
		}
		config.Plen = uint32(nameLen)

		// Set the variable in the BPF program
		if err := configVar.Set(config); err != nil {
			return fmt.Errorf("failed to set process filter: %w", err)
		}

		log.Printf("Process filter set to: %s (length: %d)", processName, config.Plen)
	}

	objs := bpf.BpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		if ve, ok := err.(*ebpf.VerifierError); ok {
			return fmt.Errorf("verifier error: %+v", ve)
		}
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return fmt.Errorf("failed to detect cgroup path: %w", err)
	}

	// Attach cgroup programs
	links := attachCgroupPrograms(cgroupPath, objs)
	defer closeLinks(links)

	// Attach kprobes
	kprobeLinks, err := attachKprobes(objs)
	if err != nil {
		return fmt.Errorf("failed to attach kprobes: %w", err)
	}
	defer closeLinks(kprobeLinks)

	fmt.Println("Tracing started...")

	// Print header row for formatted output
	printColumnHeaders()

	// Set up signal handling and ringbuffer reader
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	eventsReader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	defer eventsReader.Close()

	go func() {
		<-ctx.Done()
		eventsReader.Close()
	}()

	if err := processEvents(eventsReader); err != nil {
		return fmt.Errorf("error processing events: %w", err)
	}

	return nil
}

func printColumnHeaders() {
	fmt.Printf("%-16s %-10s %-12s %-20s %-18s %-45s %-10s %-7s %s\n",
		"SKB", "MARK", "NETNS", "INTERFACE", "PROCESS", "CONNECTION", "FLAGS", "LENGTH", "FUNCTION")
	fmt.Printf("%s\n", strings.Repeat("-", 150)) // Separator line
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

func attachCgroupPrograms(cgroupPath string, objs bpf.BpfObjects) []link.Link {
	programs := map[*ebpf.Program]ebpf.AttachType{
		objs.CgroupSockRelease: ebpf.AttachCgroupInetSockRelease,
		objs.CgroupSockCreate:  ebpf.AttachCGroupInetSockCreate,
		objs.CgroupConnect4:    ebpf.AttachCGroupInet4Connect,
		objs.CgroupConnect6:    ebpf.AttachCGroupInet6Connect,
		objs.CgroupSendmsg4:    ebpf.AttachCGroupUDP4Sendmsg,
		objs.CgroupSendmsg6:    ebpf.AttachCGroupUDP6Sendmsg,
	}

	var links []link.Link
	for prog, attach := range programs {
		cg, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Program: prog,
			Attach:  attach,
		})
		if err != nil {
			log.Printf("Warning: failed to attach cgroup %v: %v", attach, err)
			continue
		}
		links = append(links, cg)
	}
	return links
}

func attachKprobes(objs bpf.BpfObjects) ([]link.Link, error) {
	var links []link.Link

	// Attach kprobe for kfree_skbmem
	k, err := link.Kprobe("kfree_skbmem", objs.KprobeFreeSkb, nil)
	if err != nil {
		return links, fmt.Errorf("failed to attach kfree_skbmem: %w", err)
	}
	links = append(links, k)

	// Find and attach other kprobes
	targets, allocSkbFuncs, err := searchAvailableTargets()
	if err != nil {
		return links, fmt.Errorf("failed to find targets: %w", err)
	}

	// Attach kretprobe to all addresses
	allKaddrs := getAllAddresses(targets)
	krmulti, err := link.KretprobeMulti(objs.KretprobeSkb, link.KprobeMultiOptions{Addresses: allKaddrs})
	if err != nil {
		return links, fmt.Errorf("failed to attach kretprobe.multi: %w", err)
	}
	links = append(links, krmulti)

	// Attach kprobes for different targets
	kprobePrograms := map[*ebpf.Program][]string{
		objs.KprobeSkb1: targets[0],
		objs.KprobeSkb2: targets[1],
		objs.KprobeSkb3: targets[2],
		objs.KprobeSkb4: targets[3],
		objs.KprobeSkb5: targets[4],
	}

	for prog, syms := range kprobePrograms {
		if len(syms) == 0 {
			continue
		}

		addrs := make([]uintptr, 0, len(syms))
		for _, sym := range syms {
			addrs = append(addrs, uintptr(kallsymsByName[sym].Addr))
		}

		kmulti, err := link.KprobeMulti(prog, link.KprobeMultiOptions{Addresses: addrs})
		if err != nil {
			return links, fmt.Errorf("failed to attach kprobe.multi: %w", err)
		}
		links = append(links, kmulti)
	}

	// Attach kretprobe for alloc_skb functions
	if len(allocSkbFuncs) > 0 {
		krs, err := link.KretprobeMulti(objs.KretprobeAllocSkb, link.KprobeMultiOptions{Symbols: allocSkbFuncs})
		if err != nil {
			return links, fmt.Errorf("failed to attach alloc_skb: %w", err)
		}
		links = append(links, krs)
	}

	return links, nil
}

func getAllAddresses(targets map[int][]string) []uintptr {
	var allKaddrs []uintptr
	for _, syms := range targets {
		for _, sym := range syms {
			if ksym, ok := kallsymsByName[sym]; ok {
				allKaddrs = append(allKaddrs, uintptr(ksym.Addr))
			}
		}
	}
	return allKaddrs
}

func processEvents(eventsReader *ringbuf.Reader) error {
	writer := os.Stdout

	for {
		rec, err := eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// This is expected on graceful shutdown
				return nil
			}
			// Just log the error and continue processing other events
			log.Printf("Failed to read ringbuf: %v", err)
			continue
		}

		var event bpfEvent
		if err = binary.Read(bytes.NewBuffer(rec.RawSample), nativeEndian, &event); err != nil {
			log.Printf("Failed to parse ringbuf event: %v", err)
			continue
		}

		formatEvent(writer, event)
	}
}

func formatEvent(writer *os.File, event bpfEvent) {
	sym := nearestSymbol(event.Pc)

	// Format interface info
	ifInfo := fmt.Sprintf("%d(%s)", event.Ifindex, trimNull(string(event.Ifname[:])))

	// Format process info
	procInfo := fmt.Sprintf("%d(%s)", event.Pid, trimNull(string(event.Pname[:])))

	// Format connection info based on protocol
	var connInfo string
	if event.L3Proto == syscall.ETH_P_IP {
		connInfo = fmt.Sprintf("%s:%d > %s:%d",
			net.IP(event.Saddr[:4]).String(), ntohs(event.Sport),
			net.IP(event.Daddr[:4]).String(), ntohs(event.Dport))
	} else {
		connInfo = fmt.Sprintf("[%s]:%d > [%s]:%d",
			net.IP(event.Saddr[:]).String(), ntohs(event.Sport),
			net.IP(event.Daddr[:]).String(), ntohs(event.Dport))
	}

	// Format TCP flags if applicable
	tcpFlagsStr := ""
	if event.L4Proto == syscall.IPPROTO_TCP {
		tcpFlagsStr = tcpFlags(event.TcpFlags)
	}

	// Format and print the event with column alignment
	fmt.Fprintf(writer, "%-16x %-10x %-12d %-20s %-18s %-45s %-10s %-7d %s\n",
		event.Skb,        // SKB address - 16 chars for 64-bit hex
		event.Mark,       // Mark - 10 chars for 32-bit hex
		event.Netns,      // Network namespace - 12 chars for up to 10-digit number
		ifInfo,           // Interface info - 20 chars for index and name
		procInfo,         // Process info - 18 chars for pid and name
		connInfo,         // Connection info - 45 chars for source and destination
		tcpFlagsStr,      // TCP flags - 10 chars
		event.PayloadLen, // Payload length - 7 chars
		sym.Name,         // Function name - variable length
	)
}

func searchAvailableTargets() (map[int][]string, []string, error) {
	targets := make(map[int][]string)
	var allocSkbFuncs []string

	// Load kernel BTF spec
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load kernel BTF: %w", err)
	}

	// Create a map of iterators for kernel modules
	iters := map[string]*btf.TypesIterator{
		"": btfSpec.Iterate(),
	}

	// Add iterators for kernel modules
	files, err := os.ReadDir("/sys/kernel/btf")
	if err == nil {
		for _, file := range files {
			if !file.IsDir() && file.Name() != "vmlinux" {
				path := filepath.Join("/sys/kernel/btf", file.Name())
				f, err := os.Open(path)
				if err != nil {
					continue
				}

				modSpec, err := btf.LoadSplitSpecFromReader(f, btfSpec)
				f.Close()
				if err != nil {
					continue
				}

				iters[file.Name()] = modSpec.Iterate()
			}
		}
	}

	// Get available filter functions
	availableFuncs, _ := getAvailableFilterFunctions()

	// Load kallsyms
	if err := readKallsyms(); err != nil {
		return nil, nil, fmt.Errorf("failed to read kallsyms: %w", err)
	}

	// Find functions with sk_buff parameters or return values
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

			// Skip functions that aren't available for tracing
			if _, ok := availableFuncs[name]; !ok {
				continue
			}
			if _, ok := kallsymsByName[name]; !ok {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)

			// Check function parameters for sk_buff
			for i, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i < 5 {
							targets[i] = append(targets[i], name)
							break
						}
					}
				}
			}

			// Check return value for sk_buff
			if ptr, ok := fnProto.Return.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == "sk_buff" {
						allocSkbFuncs = append(allocSkbFuncs, fn.Name)
					}
				}
			}
		}
	}

	return targets, allocSkbFuncs, nil
}

func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return availableFuncs, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}

	return availableFuncs, scanner.Err()
}

func readKallsyms() error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return fmt.Errorf("failed to open /proc/kallsyms: %w", err)
	}
	defer file.Close()

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

		fullName := name
		if kmod != "" {
			fullName = fmt.Sprintf("%s %s", name, kmod)
		}
		kallsymsByName[fullName] = sym
		kallsymsByAddr[addr] = sym
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading kallsyms: %w", err)
	}

	sort.Slice(kallsyms, func(i, j int) bool {
		return kallsyms[i].Addr < kallsyms[j].Addr
	})

	return nil
}

func nearestSymbol(addr uint64) Symbol {
	idx, _ := slices.BinarySearchFunc(kallsyms, addr, func(x Symbol, addr uint64) int {
		return int(x.Addr - addr)
	})

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

func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

func ntohs(x uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, x)
	return nativeEndian.Uint16(data)
}

func trimNull(s string) string {
	return strings.TrimRight(s, "\x00")
}

func tcpFlags(data uint8) string {
	var flags []string
	flagMap := map[uint8]string{
		0b00100000: "U",
		0b00010000: ".",
		0b00001000: "P",
		0b00000100: "R",
		0b00000010: "S",
		0b00000001: "F",
	}

	for bit, flag := range flagMap {
		if data&bit != 0 {
			flags = append(flags, flag)
		}
	}

	return strings.Join(flags, "")
}
