// +build linux

package main

import (
	"C"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/tracepipe"
)

//go:embed map_in_map.c
var bpfText []byte

type ParentKey struct{
	ContainerID [16]byte
}


type Key struct {
	key int
}
type Leaf struct {
	Executable [16]byte
}

func StringToAsciiBytes(s string) [16]byte {
	t := make([]byte, 16)
	i := 0
	for _, r := range s {
		t[i] = byte(r)
		i++
	}
	var res [16]byte
	copy(res[:], t[:16])
	return res
}
func inetNtoa(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func main() {

	m := bpf.NewModule(string(bpfText), []string{})
	defer m.Close()

	kprobe, err := m.LoadKprobe("trace_inet_bind")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_inet_bind: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe("inet_bind", kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach inet_bind: %s\n", err)
		os.Exit(1)
	}

	parentTable := bpf.NewTable(m.TableId("parent_table"), m)

	innerTable := bpf.NewTable(m.TableId("inner1"), m)
	leaf := &Leaf{
		Executable: StringToAsciiBytes("curl"),
	}

	key := uint32(1)
	if err := innerTable.SetP(unsafe.Pointer(&key), unsafe.Pointer(leaf)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add data to inner1: %s\n", err)
		os.Exit(1)
	}

	leaf2 := &Leaf{
		Executable: StringToAsciiBytes("curl2"),
	}

	key = 1
	// 16 is the size of Leaf
	innerTable2Fd := m.CreateMap(bpf.BPF_MAP_TYPE_HASH, "inner2", int(unsafe.Sizeof(key)), 16, 10, 
	1)

	if err := bpf.SetPByFd(innerTable2Fd, unsafe.Pointer(&key), unsafe.Pointer(leaf2)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add data to inner2: %s\n", err)
		os.Exit(1)
	}

	p, err := bpf.GetPByFd(innerTable2Fd,int(unsafe.Sizeof(leaf2)), unsafe.Pointer(&key))
	if err != nil {
	fmt.Fprintf(os.Stderr, "Failed to get value from inner2: %s\n", err)
	os.Exit(1)
	}
	v := (*Leaf)(p)
	fmt.Printf("GetPByFd:%+v\n",v)

	parentKey := &ParentKey{
		ContainerID: StringToAsciiBytes("test_id1"),
	}

	fd := innerTable.Fd()
	if err := parentTable.SetMap(unsafe.Pointer(parentKey), fd); err != nil {
	fmt.Fprintf(os.Stderr, "Failed to add innerTable to parentTable: %s\n", err)
	os.Exit(1)
	}

	parentKey2 := &ParentKey{
		ContainerID: StringToAsciiBytes("test_id2"),
	}

	if err := parentTable.SetMap(unsafe.Pointer(parentKey2), innerTable2Fd); err != nil {
	 	fmt.Fprintf(os.Stderr, "Failed to add innerTable2 to parentTable: %s\n", err)
	 	os.Exit(1)
	 }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	fmt.Println("attached")

	tp, err := tracepipe.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	defer tp.Close()

	channel2, errorChannel := tp.Channel()

	go func() {
		for {
			select {
			case event := <-channel2:
				fmt.Printf("%+v\n", event)
			case err := <-errorChannel:
				fmt.Printf("%+x\n", err)
			}

		}
	}()
	<-sig

}

