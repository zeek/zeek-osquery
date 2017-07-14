#! Provides current interface information about hosts.

module osquery::host_info;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        host: string &log;
        utype: osquery::UpdateType &log;
        interface: string &log;
        ip: addr &log;
        mac: string &log;
    };

    type InterfaceInfo: record {
        ipv4: addr &optional;
        ipv6: addr &optional;
        mac: string;
    };

    type HostInfo: record {
        # The host ID
        host: string;
        # IP address and MAC address per interface name
        interface_info: table[string] of InterfaceInfo;
    };

    global getHostInfoByHostID: function(host_id: string): HostInfo;
}

# Set for the IDs for hosts
global hosts: set[string];

# Set of HostInfos
global host_infos: set[HostInfo];

# Table to access HostInfos by HostID
global host_info_hostid: table[string] of HostInfo;

# Table to access HostInfos by IP address
#global host_info_addr: table[addr] of vector of HostInfo;

function getHostInfoByHostID(host_id: string): HostInfo
{
    if (host_id in hosts)
        return host_info_hostid[host_id];

    local new_interface_info: table[string] of InterfaceInfo;
    return [$host="", $interface_info=new_interface_info];

}

function equalInterfaceInfo(ii1: InterfaceInfo, ii2: InterfaceInfo): bool
{
    if (ii1?$ipv4 != ii2?$ipv4 || (ii1?$ipv4 && ii2?$ipv4 && ii1$ipv4 != ii2$ipv4))
        return F;
    if (ii1?$ipv6 != ii2?$ipv6 || (ii1?$ipv6 && ii2?$ipv6 && ii1$ipv6 != ii2$ipv6))
        return F;
    if (ii1$mac != ii2$mac)
        return F;
    return T;
}

function equalHostInfo(hi1: HostInfo, hi2: HostInfo): bool
{
    if (hi1$host != hi2$host)
        return F;
    if (|hi1$interface_info| != |hi1$interface_info|)
        return F;
    for (interface in hi1$interface_info)
    {
        if (interface ! in hi2$interface_info)
            return F;
        if (! equalInterfaceInfo(hi1$interface_info[interface], hi2$interface_info[interface]))
            return F;
    }
    return T;
}

function remove_from_interface_info(host_info: HostInfo, interface: string, ip: addr, mac: string)
{
    local host_id = host_info$host;
    print(fmt("About to remove InterfaceInfo for host %s and interface %s", host_id, interface));
    
    # Check if InterfaceInfo exists for the interface
    if (interface ! in  host_info$interface_info)
    {
        print(fmt("No InterfaceInfo exists for host %s and interface %s", host_id, interface));
        return;
    }

    # Does the mac match?
    if (host_info$interface_info[interface]$mac != mac)
    {
        print(fmt("Overriding outdated mac in InterfaceInfo for host %s and interface %s", host_id, interface));
        host_info$interface_info[interface]$mac = mac;
    }

    local interface_info = host_info$interface_info[interface];
    # IPv4
    if (is_v4_addr(ip))
    {
        # Does an IPv4 exist?
        if (! interface_info?$ipv4 || interface_info$ipv4 != ip)
        {
            print(fmt("Removing outdated ipv4 in InterfaceInfo for host %s and interface %s", host_id, interface));
        }
        # Update InterfaceInfo
        host_info$interface_info[interface] = [$mac=mac];
        if (interface_info?$ipv6)
            host_info$interface_info[interface]$ipv6=interface_info$ipv6;
        interface_info = host_info$interface_info[interface];
    }

    # IPv6
    if (is_v6_addr(ip))
    {
        # Does an IPv6 exist?
        if (! interface_info?$ipv6 || interface_info$ipv6 != ip)
        {
            print(fmt("Removing outdated ipv6 in InterfaceInfo for host %s and interface %s", host_id, interface));
        }
        # Update InterfaceInfo
        host_info$interface_info[interface] = [$mac=mac];
        if (interface_info?$ipv4)
            host_info$interface_info[interface]$ipv4=interface_info$ipv4;
        interface_info = host_info$interface_info[interface];
    }

    # Remove interface if no active IP
    interface_info = host_info$interface_info[interface];
    if (! interface_info?$ipv4 && !interface_info?$ipv6)
    {
        delete host_info$interface_info[interface];
    }
}

function add_to_interface_info(host_info: HostInfo, interface: string, ip: addr, mac: string)
{
    local host_id = host_info$host;
    print(fmt("About to add InterfaceInfo for host %s and interface %s", host_id, interface));

    # Create new InterfaceInfo for the interface if needed
    if (interface ! in host_info$interface_info)
    {
        host_info$interface_info[interface] = [$mac=mac];
    }
    local interface_info = host_info$interface_info[interface];

    # Does the mac match?
    if (interface_info$mac != mac)
    {
        print(fmt("Overriding outdated mac in InterfaceInfo for host %s and interface %s", host_id, interface));
        interface_info$mac = mac;
    }

    # IPv4
    if (is_v4_addr(ip))
    {
        # Does an IPv4 already exist?
        if (interface_info?$ipv4)
        {
            print(fmt("Overriding existing ipv4 in InterfaceInfo for host %s and interface %s", host_id, interface));
        }
        interface_info$ipv4 = ip;
    }

    # IPv6
    if (is_v6_addr(ip))
    {
        # Does an IPv6 already exist?
        if (interface_info?$ipv6)
        {
            print(fmt("Overriding existing ipv6 in InterfaceInfo for host %s and interface %s", host_id, interface));
        }
        interface_info$ipv6 = ip;
    }
}

event host_info_net(resultInfo: osquery::ResultInfo, interface: string, ip: string, mac: string)
{
    local host_id = resultInfo$host;
    print(fmt("Received new InterfaceInfo for host %s and interface %s", host_id, interface));
    # New host?
    if (host_id ! in hosts)
    {
        # Include the new host
        add hosts[host_id];
        # Setup a HostInfo Object
        local interface_info_new: table[string] of InterfaceInfo;
        local host_info_new: HostInfo = [$host=host_id, $interface_info=interface_info_new];
        add host_infos[host_info_new];
        host_info_hostid[host_id] = host_info_new;
    }

    # Retrieve the HostInfo Object for the respective host
    local host_info = host_info_hostid[host_id];

    if (resultInfo$utype == osquery::ADD)
    {
        add_to_interface_info(host_info, interface, to_addr(ip), mac);
    }

    if (resultInfo$utype == osquery::REMOVE)
    {
        remove_from_interface_info(host_info, interface, to_addr(ip), mac);
    }

    # Log the change
    Log::write(osquery::host_info::LOG, [$ts = network_time(),
                                         $host = host_id,
                                         $utype = resultInfo$utype,
                                         $interface = interface,
                                         $ip = to_addr(ip),
                                         $mac = mac]
    );


}

#event osquery::host_connected(host_id: string)
#{
#}

event osquery::host_disconnected(host_id: string)
{
    if (host_id ! in hosts)
    {
        return;
    }

    local host_info = host_info_hostid[host_id];

    # Remove HostInfo from lookup tables
    delete host_info_hostid[host_id];
    delete host_infos[host_info];
    delete hosts[host_id];
}

event bro_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="osq-host_info"]);

    Broker::enable();

    local ev = [$ev=host_info_net,$query="SELECT a.interface, a.address, d.mac from interface_addresses as a INNER JOIN interface_details as d ON a.interface=d.interface;", $utype=osquery::BOTH];
    osquery::subscribe(ev);
}
