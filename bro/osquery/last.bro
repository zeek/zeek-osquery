#! Logs last activity.

module osqueryLast;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		username: string &log;
		tty: string &log;
		pid: int &log;
		typ: int &log;
		tim: int &log;
		lhost: string &log;
	};
}

event last(host: string, mode: string, utype: string,
		username: string, tty: string, pid: int,
		typ: int, tim: int, lhost: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $username = username,
			    $tty = tty,
			    $pid = pid,
				$typ = typ,
				$tim = tim,
				$lhost = lhost
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-last"]);
	
	local ev = [$ev=last,
		    $query="SELECT username,tty,pid,type,time,host FROM last"];
	osquery::subscribe(ev);
	}
