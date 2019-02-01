package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/spf13/cobra"
)

func Notify(payload string) {
	title := "firewall"
	bus, _ := dbus.SessionBus()
	bus.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications").
		Call("org.freedesktop.Notifications.Notify", 0, "", uint32(0),
			"", title, payload, []string{},
			map[string]dbus.Variant{}, int32(5000))
}

func logPayload(payload *nfqueue.Payload) int {
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			Notify(fmt.Sprintf("dropped TCP packet: %s:%d", ip.DstIP, tcp.DstPort))
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			Notify(fmt.Sprintf("dropped UDP packet: %s:%d\n", ip.DstIP, udp.DstPort))
		} else {
			// Iterate over all layers, printing out each layer type
			for _, layer := range packet.Layers() {
				Notify(fmt.Sprintf("dropped %s packet\n", layer.LayerType()))
				break
			}
		}
	}
	payload.SetVerdict(nfqueue.NF_DROP)
	return nfqueue.NF_DROP
}

func main() {
	root := &cobra.Command{
		Run: func(cmd *cobra.Command, _ []string) {
			queueID, err := cmd.Flags().GetInt("queue-num")
			if err != nil {
				log.Printf("failed to read flag for queue-num: %v", err)
				log.Printf("using queue num 0")
				queueID = 0
			}
			q := new(nfqueue.Queue)
			q.SetCallback(logPayload)

			err = q.Init()
			if err != nil {
				log.Fatalf("failed to init queue: %v", err)
			}
			q.Bind(syscall.AF_INET)
			if err != nil {
				log.Fatalf("failed to bind queue: %v", err)
			}
			err = q.CreateQueue(queueID)
			if err != nil {
				log.Fatalf("failed to listen on queue %d: %v", queueID, err)
			}
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			go func() {
				for sig := range c {
					// sig is a ^C, handle it
					_ = sig
					q.StopLoop()
				}
			}()

			// XXX Drop privileges here

			q.Loop()
			q.DestroyQueue()
			q.Close()
		},
	}
	root.Flags().IntP("queue-num", "q", 0, "iptables queue number")
	root.Execute()
}
