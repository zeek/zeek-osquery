#! Logs etc_hosts activity.

module osqueryEtcHosts;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		address: string &log;
		hostnames: string &log;
	};
}

event etc_hosts(host: string, mode: string, utype: string,
		address: string, hostnames: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $address = address,
			    $hostnames = hostnames
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-etc-hosts"]);
	
	local ev = [$ev=etc_hosts,
		    $query="SELECT address,hostnames FROM etc_hosts"];
	osquery::subscribe(ev);
	}
