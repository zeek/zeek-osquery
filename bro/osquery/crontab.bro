#! Logs crontab activity.

module osqueryArpCache;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		evt: string &log;
		minute: string &log;
		hour: string &log;
		command: string &log;
		path: string &log;
	};
}

event crontab(host: string, mode: string, utype: string,
		evt: string, minute: string, hour: string, command: string,
		path: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $evt = evt,
			    $minute = minute,
				$hour = hour,
				$command = command,
				$path = path
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-crontab"]);
	
	local ev = [$ev=crontab,
		    $query="SELECT event,minute,hour,command,path FROM crontab"];
	osquery::subscribe(ev);
	}
