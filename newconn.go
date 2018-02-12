package main

import (
	"net"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"os"
)


type Output struct {
	Source_Mac net.HardwareAddr
	Destination_Mac net.HardwareAddr
	Source_IP net.IP
	Destination_IP net.IP
	Source_Port layers.TCPPort
	Destination_Port layers.TCPPort  
}

var (
	device       string = "wlp4s0"
    snapshot_len int32  = 1600
    promiscuous  bool   = false
	err          error
    handle       *pcap.Handle
)

func handleError(err error){
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
    }
}

func main(){
	// Open intf for capture 
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, pcap.BlockForever)
	handleError(err)


	//  Filter to collect only tcp packets
	filter := "tcp"
	err = handle.SetBPFFilter(filter)
	handleError(err)

	// Read a packet 
	fmt.Println("Listing New  TCP Connections...")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
	   ethLayer := packet.Layer(layers.LayerTypeEthernet)
	   ipLayer := packet.Layer(layers.LayerTypeIPv4)
	   tcpLayer := packet.Layer(layers.LayerTypeTCP)
	
	   if ethLayer != nil && ipLayer != nil && 
	      tcpLayer != nil {
	      	eth, _ :=  ethLayer.(*layers.Ethernet)
	      	ip, _ := ipLayer.(*layers.IPv4)
	      	tcp, _ := tcpLayer.(*layers.TCP)
	      	if tcp.SYN {
	      		newOp := Output{eth.SrcMAC, eth.DstMAC,
			                    ip.SrcIP, ip.DstIP, tcp.SrcPort,
			                    tcp.DstPort}
			    fmt.Printf("%+v\n", newOp)
			}
		}
	}

}

