package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var (
		device       string = "en0"
		snapshot_len int32  = 1024
		promiscuous  bool   = false
		err          error
		timeout      time.Duration = 30 * time.Second
		handle       *pcap.Handle
	)

	// read device from commandline
	if len(os.Args) > 1 {
		device = os.Args[1]
	}

	fmt.Println("Listening on ", device)

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			for _, question := range dns.Questions {
				fmt.Printf("Record Type: %v, Record Name: %s\n", question.Type, string(question.Name))
			}
		}
	}
}
