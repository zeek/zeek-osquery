#! Logs socket activity.

module osqueryFiles;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		pid: int &log;
		fd: int &log;
		path: string &log;
	};
}

event process_open_files(host: string, utype: string,
		pid: int, fd: int, path: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
			    $pid = pid,
			    $fd = fd,
			    $path = path
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-openfiles"]);
	
	local ev = [$ev=process_open_files,
		    $query="SELECT pid, fd, path FROM process_open_files"];
	osquery::subscribe(ev);
	}

