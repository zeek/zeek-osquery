#! Logs process open sockets activity

@load osquery/framework

module osquery::logging::process_open_sockets;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
                fd: int &log;
                family: int &log;
                protocol: int &log;
                local_address: addr &log;
                remote_address: addr &log;
                local_port: int &log;
                remote_port: int &log;
        };

	## Event to indicate that a new socket connection was created on a host
	##
	## <params missing>
	global process_open_socket_added: event(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int);
	
	## Event to indicate that an existing socket connection terminated on a host
	##
	## <params missing>
	global process_open_socket_removed: event(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int);
}

event host_process_open_sockets(resultInfo: osquery::ResultInfo,
pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	
        if (resultInfo$utype != osquery::ADD) {
        	if (resultInfo$utype == osquery::REMOVE) {
			event process_open_socket_removed(network_time(), resultInfo$host, pid, fd, family, protocol, local_address, remote_address, local_port, remote_port);
		}
                # Just want to log new socket connection existance.
                return;
	}
	else {
		if (pid == -1) {
			return;
		}
		event process_open_socket_added(network_time(), resultInfo$host, pid, fd, family, protocol, local_address, remote_address, local_port, remote_port);
	}

	local local_addr: addr;
	local remote_addr: addr;
	if (local_address != "") local_addr = to_addr(local_address);
	if (remote_address != "") remote_addr = to_addr(remote_address);

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
               	$pid = pid,
                $fd = fd,
                $family = family,
                $protocol = protocol,
                $local_address = local_addr,
                $remote_address = remote_addr,
                $local_port = local_port,
                $remote_port = remote_port
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-process_open_sockets"]);

        local query = [$ev=host_process_open_sockets,$query="SELECT pid, fd, family, protocol, local_address, remote_address, local_port, remote_port from process_open_sockets WHERE family=2", $utype=osquery::BOTH];
        osquery::subscribe(query);
        }
