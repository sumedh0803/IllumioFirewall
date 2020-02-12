# -*- coding: utf-8 -*-
"""
Created on Tue Feb 11 2020
@author: Sumedh Sen
"""

class Firewall:
    '''
    This function takes the IP address in string format Eg: '192.168.1.1'
    and returns a decimal number corresponding to the IP
    '''
    def getIpFromString(self, strIp: str):
        ipaddr = strIp.split(".")
        return int(ipaddr[0])*(256**3)+int(ipaddr[1])*(256**2)+int(ipaddr[2])*(256**1)+int(ipaddr[3])*(256**0)
    
    
    '''
    This method takes the decimal form of an IP address and returns the IP in IPv4 format
    '''
    def getStringFromIp(self, ip: int):
        ipaddr = ""
        count = 3
        while count >= 1:
            ipaddr += str(ip//(256**count)) + "."
            ip = ip % (256**count)
            count -= 1
        ipaddr += str(ip)
        return ipaddr
    
    
        
    '''
    In case of IP address ranges, this method acepts 2 strings, the lower and upper bound for the IP address,
    and returns a list of all IP addresses within that range
    '''    
    def getIpRange(self, lower_ip: str, upper_ip: str):
        ipRange = []
        for ip in range(self.getIpFromString(lower_ip),self.getIpFromString(upper_ip)+1):
            ipRange.append(self.getStringFromIp(ip))
        return ipRange
    
    
    
    '''
    This method accespt 4 parameters: direction (outbound / inbound), protocol (tcp / udp), port (single or range)
    and IP address (IPv4: single / range), and returns a boolean value, indicating whether the Firewall accepts or
    rejects the request. 'True' meaning the Firewall will accept the packet and False meaning the Firewall will reject the packet.
    '''
    def accept_packet(self, direction:str, protocol: str, port:int,ip:str):
        try:
            if ip in self.fwRules[direction][protocol][port]:
                return True
            else:
                return False
        except KeyError:
            return False
        
        
        
    def __init__(self, path):
        import csv

        self.path = path
        
        self.fwRules = { 'inbound':{'tcp':{},'udp':{}},
                   'outbound':{'tcp':{},'udp':{}}}
        
        with open(path, 'r') as file:
            rules = csv.reader(file, delimiter='\n')
            for rule in rules:
                #Taking each rule one by one and extracting the direction, protocol, port and IP address
                direction,protocol,port,ip = rule[0].split(",")
                
                
                multiple_ports = False
                multiple_ip = False
                if '-' in port: #sets the boolean value multiple_ports to True, if a '-' exists in the port, which means that a port range is given.
                    multiple_ports = True
                    lower_port,upper_port = port.split("-")
                if '-' in ip:
                    multiple_ip = True #sets the boolean value multiple_ip to True, if a '-' exists in the IP, which means that a IP range is given.
                    lower_ip,upper_ip = ip.split('-')
                    
                
                
                if multiple_ports: #in case a port range is given
                    if not multiple_ip: #single ip for multiple ports
                        for ports in range(int(lower_port),int(upper_port)+1): #iterating through each of the port numbers
                            if ports in self.fwRules[direction][protocol] and not ip in self.fwRules[direction][protocol][ports]: #if a port has already been set in the dictionary, but the IP is not set for that port number
                                self.fwRules[direction][protocol][ports].append(ip)
                                #self.fwRules[direction][protocol][ports].sort() #sorting needed only if we want to implement binary search
                            elif ports in self.fwRules[direction][protocol] and ip in self.fwRules[direction][protocol][ports]: #if a port-ip pair exists already
                                continue
                            elif not ports in self.fwRules[direction][protocol]: # if a new port number is being added
                                self.fwRules[direction][protocol][ports] = [ip]
                                
                    else: #multiple_ips for multiple_ports
                        for ports in range(int(lower_port),int(upper_port)+1):
                            if ports in self.fwRules[direction][protocol]: # if a port is already set in dictionary, but new IP addresses are to be added for that port
                                self.fwRules[direction][protocol][ports] = self.fwRules[direction][protocol][ports] + self.getIpRange(lower_ip,upper_ip)
                            else: #new port and ip addresses are set
                                self.fwRules[direction][protocol][ports] = self.getIpRange(lower_ip,upper_ip)
                else: #single port
                    port = int(port)
                    if not multiple_ip: #single ip for single port
                        if port in self.fwRules[direction][protocol] and not ip in self.fwRules[direction][protocol][port]: #if a port has already been set in the dictionary, but the IP is not set for that port number
                            self.fwRules[direction][protocol][port].append(ip)
                            #self.fwRules[direction][protocol][port].sort() #sorting needed only if we want to implement binary search
                        elif port in self.fwRules[direction][protocol] and ip in self.fwRules[direction][protocol][port]: #if a port-ip pair exists already
                                continue
                        elif not port in self.fwRules[direction][protocol]: #new port and ip addresses are set
                            self.fwRules[direction][protocol][port] = [ip]
                    else: #multiple ip for single port
                        if port in self.fwRules[direction][protocol]: #if a port is already set in dictionary, but new IP addresses are to be added for that port
                                self.fwRules[direction][protocol][port] = self.fwRules[direction][protocol][port] + self.getIpRange(lower_ip,upper_ip)
                        else: #new port and ip addresses are set
                            self.fwRules[direction][protocol][port] = self.getIpRange(lower_ip,upper_ip)
      
        
if __name__ == "__main__":
    fw = Firewall('fw.csv')
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # matches first rule
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) # matches third rule
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))  # matches second rule
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    print(fw.accept_packet("outbound", "tcp", 550, "192.229.0.0"))
    print(fw.accept_packet("inbound", "tcp", 1000, "0.0.0.0"))
    print(fw.accept_packet("inbound", "udp", 65535, "255.255.255.255"))
    print(fw.accept_packet("inbound", "tcp", 81, "125.168.1.2"))
    print(fw.accept_packet("inbound", "tcp", 80, "192.154.1.3"))
    print(fw.accept_packet("outbound", "udp", 13, "192.192.168.192"))
    print(fw.accept_packet("outbound", "udp", 12, "192.192.254.192"))
    print(fw.accept_packet("outbound", "udp", 13, "192.136.192.194"))
    print(fw.accept_packet("outbound", "tcp", 13, "192.255.192.192"))
