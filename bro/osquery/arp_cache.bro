#! Logs disk-encryption activity.

module osqueryArpCache;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		address: string &log;
		mac: string &log;
		interface: string &log;
		permanent: string &log;
	};
}

event arp_cache(host: string, mode: string, utype: string,
		address: string, mac: string, interface: string, permanent: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $address = address,
			    $mac = mac,
				$interface = interface,
				$permanent = permanent
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-arp-cache"]);
	
	local ev = [$ev=arp_cache,
		    $query="SELECT address,mac,interface,permanent FROM arp_cache"];
osquery::subscribe(ev, 0.0.0.0/0);
	}
