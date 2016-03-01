#! Logs iptables activity.

module osqueryIpTables;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		filter_name: string &log;
		chain: string &log;
		policy: string &log;
		target: string &log;
		protocol: int &log;
		src_ip: string &log;
		src_mask: string &log;
		iniface: string &log;
		iniface_mask: string &log;
		dst_ip: string &log;
		dst_mask: string &log;
		outiface: string &log;
		outiface_mask: string &log;
		match: string &log;
		packets: int &log;

	};
}

event iptables(host: string, mode: string, utype: string,
		filter_name: string, chain: string, policy: string, target: string,
		protocol: int, src_ip: string, src_mask: string, iniface: string, 
		iniface_mask: string, dst_ip: string, dst_mask: string, outiface: string,
		outiface_mask: string, match: string, packets: int)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $filter_name = filter_name,
			    $chain = chain,
				$policy = policy,
				$target = target,
				$protocol = protocol,
				$src_ip = src_ip,
				$src_mask = src_mask,
				$iniface = iniface,
				$iniface_mask = iniface_mask,
				$dst_ip = dst_ip,
				$dst_mask = dst_mask,
				$outiface = outiface,
				$outiface_mask = outiface_mask,
				$match = match,
				$packets = packets
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-iptables"]);
	
	local ev = [$ev=iptables,
		    $query="SELECT filter_name,chain,policy,target,protocol,src_ip,src_mask,iniface,iniface_mask,dst_ip,dst_mask,outiface,outiface_mask,match,packets FROM disk_encryption"];
	osquery::subscribe(ev);
	}
