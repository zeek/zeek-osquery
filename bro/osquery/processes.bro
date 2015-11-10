#! Logs socket activity.

module osqueryProcesses;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		pid: count &log;
		ppid: count &log;
		path: string &log;
		uid: count &log;
		euid: count &log;
		gid: count &log;
		egid: count &log;
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
			    $pid = int_to_count(pid),
			    $ppid = int_to_count(parent),
			    $path = path,
			    $uid = int_to_count(uid),
			    $euid = int_to_count(euid),
			    $gid = int_to_count(gid),
			    $egid = int_to_count(euid),
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

