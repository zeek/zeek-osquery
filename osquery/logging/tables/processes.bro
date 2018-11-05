#! Logs processes activity.

module osquery::logging::processes;

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

	## Event to indicate that a new process was created on a host
	##
	## <param missing>
	global process_added: event(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int);

	## Event to indicate that an existing process terminated on a host
	##
	## <param missing>
	global process_removed: event(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int);

}

event host_processes(resultInfo: osquery::ResultInfo,
		pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int)
        {
        if (resultInfo$utype != osquery::ADD) {
		if (resultInfo$utype == osquery::REMOVE) {
			#print(fmt("Raising event to remove process with pid %d", pid));
			event process_removed(network_time(), resultInfo$host, pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup);
		}
                # Just want to log new process existance.
                return;
	}
	else {
		event process_added(network_time(), resultInfo$host, pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup);
	}

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
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

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-processes"]);

        local query = [$ev=host_processes,$query="SELECT pid,name,path,cmdline,cwd,root,uid,gid,on_disk,start_time,parent,pgroup FROM processes", $utype=osquery::BOTH];
        osquery::subscribe(query);
        }
