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
