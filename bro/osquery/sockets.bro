#! Logs socket activity.

module osquerySockets;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		proto: transport_proto &log;
		local_h: addr &log;
		local_p: port &log;
		remote_h: addr &log;
		remote_p: port &log;
		pid: int &log;
		};
}

event process_open_sockets(host: string, utype: string, pid:int,
			   protocol: int, local_address: string, remote_address: string,
			   local_port: int, remote_port: int)
	{
	if ( protocol == 0 )
		 # Interested only in network sockets.
		return;
	
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
		
	local tproto: transport_proto;

	switch ( int_to_count(protocol) ) {
	case IPPROTO_TCP:
		tproto = tcp;
		break;
	
	case IPPROTO_UDP:
		tproto = udp;
		break;
	
	case IPPROTO_ICMP:
		tproto = icmp;
		break;

	default:
		tproto =  unknown_transport;
		break;
	}
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
			    $proto = tproto,
			    $local_h = to_addr(local_address),
			    $local_p = count_to_port(int_to_count(local_port), tproto),
			    $remote_h = to_addr(remote_address),
			    $remote_p = count_to_port(int_to_count(remote_port), tproto),
			    $pid = pid
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-sockets"]);
	
	local ev = [$ev=process_open_sockets,
		    $query="SELECT pid, protocol, local_address, remote_address, local_port, remote_port from process_open_sockets"];
	osquery::subscribe(ev);
	}
