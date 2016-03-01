#! Logs process-envs activity.

module osqueryProcessEnvs;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		pid: int &log;
		key: string &log;
		value: string &log;
	};
}

event process_envs(host: string,  mode: string, utype: string,
		pid: int, key: string, value: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $pid = pid,
			    $key = key,
				$value = value
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-process-envs"]);
	
	local ev = [$ev=process_envs,
		    $query="SELECT pid,key,value FROM process_envs"];
	osquery::subscribe(ev);
	}
