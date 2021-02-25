#!/usr/bin/env ruby

require 'rubygems'
require 'packetfu'


class ARPSpoof

    #add your iface
    def initialize(victim_ip, victim_mac, gateway, router_mac iface="" spoof=false)
        @victim_ip = victim_ip
        cfg = PACKETFu::Utils.whoami?(:iface => iface)

        