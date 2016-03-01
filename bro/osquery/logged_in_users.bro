#! Logs socket activity.

module osqueryloggedUsers;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		user: string &log;
		tty: string &log;
		rhost: string &log;
		rt: int &log;
		pid: int &log;
		};
}

event logged_in_users(host: string, mode: string, utype: string, 
		user: string, tty: string, rhost: string,
		rt: int, pid: int)
	{
	
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $user = user,
				$tty = tty,
				$rhost = rhost,
				$rt = rt,
				$pid = pid
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-logged_in_User"]);
	
	local ev = [$ev=logged_in_users,
		    $query="SELECT user, tty, host, time, pid FROM logged_in_users",
			$init_dump = T];
osquery::subscribe(ev, 0.0.0.0/0);
	}
