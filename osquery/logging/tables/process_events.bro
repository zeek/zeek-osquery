#! Logs process events activity

@load osquery/framework

module osquery::logging::process_events;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
		path: string &log;
		cmdline: string &log;
		cwd: string &log;
		uid: int &log;
		gid: int &log;
		start_time: int &log;
		parent: int &log;
        };

	## Event to indicate that a new process was created on a host
	##
	## <params missing>
	global process_event_added: event(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int);
}

event host_process_events(resultInfo: osquery::ResultInfo,
		pid: int, path: string, cmdline: string, cwd: string, uid: int, gid: int,
		start_time: int, parent: int) {
        if (resultInfo$utype != osquery::ADD) {
                # Just want to log new process existance.
                return;
	}
	else {
		event process_event_added(network_time(), resultInfo$host, pid, path, cmdline, cwd, uid, gid, start_time, parent);
	}

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
               	$pid = pid,
                $path = path,
                $cmdline = cmdline,
                $cwd = cwd,
                $uid = uid,
                $gid = gid,
                $start_time = start_time,
                $parent = parent
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-process_events"]);

        local query = [$ev=host_process_events,$query="SELECT pid,path,cmdline,cwd,uid,gid,time,parent FROM process_events"];
        osquery::subscribe(query);
        }
