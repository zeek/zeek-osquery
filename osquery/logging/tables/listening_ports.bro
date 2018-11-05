#! Logs listening ports activity

@load osquery/framework

module osquery::logging::listening_ports;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
                fd: int &log;
                family: int &log;
                socket: int &log;
                protocol: int &log;
                address: addr &log;
                listening_port: int &log;
        };

	## Event to indicate that a new socket connection was created on a host
	##
	## <params missing>
	global listening_port_added: event(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int);
	
	## Event to indicate that an existing socket connection terminated on a host
	##
	## <params missing>
	global listening_port_removed: event(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int);
}

event host_listening_ports(resultInfo: osquery::ResultInfo,
pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
        if (resultInfo$utype != osquery::ADD) {
        	if (resultInfo$utype == osquery::REMOVE) {
			event listening_port_removed(network_time(), resultInfo$host, pid, fd, family, socket, protocol, local_address, local_port);
		}
                # Just want to log new socket connection existance.
                return;
	}
	else {
		event listening_port_added(network_time(), resultInfo$host, pid, fd, family, socket, protocol, local_address, local_port);
	}
	
	local local_addr: addr;
	if (local_address != "") local_addr = to_addr(local_address);

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
               	$pid = pid,
                $fd = fd,
                $socket = socket,
                $family = family,
                $protocol = protocol,
                $address = local_addr,
                $listening_port = local_port
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-listening_ports"]);

        local query = [$ev=host_listening_ports,$query="SELECT pid, fd, family, socket, protocol, address, port from listening_ports WHERE family=2;", $utype=osquery::BOTH];
        osquery::subscribe(query);
        }
