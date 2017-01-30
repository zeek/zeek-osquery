#! Logs processes activity.

module osquery::processes;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
                name: string &log;
		path: string &log;
		cmdline: string &log;
		cwd: string &log;
		root: string &log;
		uid: int &log;
		gid: int &log;
		on_disk: int &log;
		start_time: int &log;
		parent: int &log;
		pgroup: int &log;
        };
}

event host_processes(host: string, utype: string,
		pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int)
        {
        if ( utype != "ADDED" )
                # Just want to log process existance.
                return;

        local info: Info = [
		$t=network_time(),
		$host=host,
               	$pid = pid,
                $name = name,
                $path = path,
                $cmdline = cmdline,
                $cwd = cwd,
                $root = root,
                $uid = uid,
                $gid = gid,
                $on_disk = on_disk,
                $start_time = start_time,
                $parent = parent,
                $pgroup = pgroup
        ];

	#print fmt("Writing process with PID '%d' and name '%s'", pid, name);
        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-processes"]);

	Broker::enable();

        local ev = [$ev=host_processes,$query="SELECT pid,name,path,cmdline,cwd,root,uid,gid,on_disk,start_time,parent,pgroup FROM processes"];
        osquery::subscribe(ev);
        }
