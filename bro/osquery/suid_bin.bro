#! Logs suid_bin activity.

module osquerySuidBin;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		path: string &log;
		username: string &log;
		groupname: string &log;
		permissions: string &log;
	};
}

event suid_bin(host: string, mode: string, utype: string,
		path: string, username: string, groupname: string, permissions: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $path = path,
			    $username = username,
				$groupname = groupname,
				$permissions = permissions
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-suid-bin"]);
	
	local ev = [$ev=suid_bin,
		    $query="SELECT path,username,groupname,permissions FROM suid_bin"];
	osquery::subscribe(ev);
	}
