#! Provides current interface information about hosts.

@load ./host_interfaces
@load ../main

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
}

event host_info_net(resultInfo: osquery::ResultInfo, interface: string, ip: string, mac: string)
{
    local host_id = resultInfo$host;
    print(fmt("Received new InterfaceInfo for host %s and interface %s", host_id, interface));

    if (resultInfo$utype == osquery::ADD)
    {
        # Update the interface
        osquery::host_interfaces::updateInterface(osquery::host_interfaces::ADD, host_id, interface, to_addr(ip), mac);

        # Check for groups to join
        local groups = osquery::send_joins_new_address(host_id, to_addr(ip));

        # Check for subscriptions that include the host (either by host_id or group)
        for (g in groups)
        {
            local group = groups[g];
            osquery::send_subscriptions_new_group(host_id, group);
        }
    }

    if (resultInfo$utype == osquery::REMOVE)
    {
        # Update the interface
        osquery::host_interfaces::updateInterface(osquery::host_interfaces::REMOVE, host_id, interface, to_addr(ip), mac);

        # Check for subscriptions to cancel
        #TODO

        # Check for groups to leave
        #TODO
    }

    # Log the change
    Log::write(LOG, [$ts = network_time(),
                                         $host = host_id,
                                         $utype = resultInfo$utype,
                                         $interface = interface,
                                         $ip = to_addr(ip),
                                         $mac = mac]
    );
}

event osquery::host_disconnected(host_id: string)
{
    osquery::host_interfaces::removeHost(host_id);
}

event bro_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="osq-host_info"]);

    local ev = [$ev=host_info_net,$query="SELECT a.interface, a.address, d.mac from interface_addresses as a INNER JOIN interface_details as d ON a.interface=d.interface;", $utype=osquery::BOTH];
    osquery::subscribe(ev);
}
