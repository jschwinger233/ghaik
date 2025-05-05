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
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.CgroupSockCreate,
		Attach:  ebpf.AttachCGroupInetSockCreate,
	})
	defer cg.Close()
	if err != nil {
		slog.Error("failed to attach cgroup")
	}
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
