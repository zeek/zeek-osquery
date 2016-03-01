#! Logs socket activity.

module osqueryListeningPorts;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		pid: int &log;
		rport: int &log;
		protocol: int &log;
		family: int &log;
		address: string &log;
		};
}

event listening_ports(host: string, mode: string, utype: string, 
		pid: int, rport: int, protocol: int,
		family: int, address: string)
	{
	
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $pid = pid,
				$rport = rport,
				$protocol = protocol,
				$family = family,
				$address = address
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-listeningPorts"]);
	
	local ev = [$ev=listening_ports,
		    $query="SELECT pid, port, protocol, family, address FROM listening_ports",
			$init_dump = F];
osquery::subscribe(ev, 0.0.0.0/0);
	}
