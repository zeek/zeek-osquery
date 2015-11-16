#! Logs socket activity.

module osqueryProcesses;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		pid: int &log;
		ppid: int &log;
		path: string &log;
		uid: int &log;
		euid: int &log;
		gid: int &log;
		egid: int &log;
		argv: string &log;
	};
}

event processes(host: string, utype: string,
		pid: int, path: string, cmdline: string, uid: int, gid: int,
		euid: int, egid: int, parent: int)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
			    $pid = pid,
			    $ppid = parent,
			    $path = path,
			    $uid = uid,
			    $euid = euid,
			    $gid = gid,
			    $egid = euid,
			    $argv = cmdline
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-processes"]);
	
	local ev = [$ev=processes,
		    $query="SELECT pid, path, cmdline, uid, gid, euid, egid, parent FROM processes"];
	osquery::subscribe(ev);
	}

