package main

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
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
		objs.CgroupSockCreate:  ebpf.AttachCGroupInetSockCreate,
		objs.CgroupSockRelease: ebpf.AttachCgroupInetSockRelease,
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

	kprobe, err := link.Kprobe("__dev_queue_xmit", objs.KprobeSkb1, nil)
	if err != nil {
		slog.Error("failed to attach kprobe", err)
	}
	defer kprobe.Close()
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
