#! Logs Process-memory-map activity.

module osqueryProcessMemoryMap;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		pid: int &log;
		start: string &log;
		end: string &log;
		permissions: string &log;
		device: string &log;
		path: string &log;
	};
}

event process_memory_map(host: string, mode: string, utype: string,
		pid: int, start: string, end: string, permissions: string,
		device: string, path: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $pid = pid,
			    $start = start,
				$end = end,
				$permissions = permissions,
				$device = device,
				$path = path
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-process-memory"]);
	
	local ev = [$ev=process_memory_map,
		    $query="SELECT pid,start,end,permissions,device,path FROM process_memory_map"];
	osquery::subscribe(ev);
	}
