#! Provide current process information about hosts.

@load osquery/framework
@load osquery/logging/tables/processes
@load osquery/logging/tables/process_events

module osquery::processes;

export {
	type ProcessInfo: record {
		pid: int &optional;
		path: string &optional;
		cmdline: string &optional;
		uid: int &optional;
		parent: int &optional;
	};

	## Get the ProcessInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getProcessInfosByHostID: function(host_id: string): set[ProcessInfo];

	## Get the ProcessInfo of a host by its id
	##
	## host_id: The identifier of the host
	## pid: The identifier of the process
	global getProcessInfoByHostID: function(host_id: string, pid: int): ProcessInfo;

	## Check if two process infos are equal
	##
	## <params missing>
	global equalProcessInfos: function(proc1: ProcessInfo, proc2: ProcessInfo): bool;

	## Event when added to the state of processes
	##
	## <params missing>
	global process_state_added: event(host_id: string, process_info: ProcessInfo);
	
	## Event when removing a host from the state of processes
	##
	## <params missing>
	global process_host_state_removed: event(host_id: string);
	
	## Event when removing from the state of processes
	##
	## <params missing>
	global process_state_removed: event(host_id: string, process_info: ProcessInfo);
}

# Table to access ProcessInfo by HostID
global host_processes: table[string] of table[int] of ProcessInfo;

function equalProcessInfos(proc1: ProcessInfo, proc2: ProcessInfo): bool {
	if (proc1?$pid != proc2?$pid) {
		return F;
	}
	if (proc1?$pid && proc1$pid != proc2$pid) {
		return F;
	}
	if (proc1?$path != proc2?$path) {
		return F;
	}
	if (proc1?$path && proc1$path != proc2$path) {
		return F;
	}
	if (proc1?$cmdline != proc2?$cmdline) {
		return F;
	}
	if (proc1?$cmdline && proc1$cmdline != proc2$cmdline) {
		return F;
	}
	if (proc1?$uid != proc2?$uid) {
		return F;
	}
	if (proc1?$uid && proc1$uid != proc2$uid) {
		return F;
	}
	if (proc1?$parent != proc2?$parent) {
		return F;
	}
	if (proc1?$parent && proc1$parent != proc2$parent) {
		return F;
	}
	
	return T;
}


function _add_process_state(host_id: string, pid: int, path: string, cmdline: string, uid: int, parent: int) {
	local process_info: ProcessInfo = [$pid=pid, $path=path, $cmdline=cmdline, $uid=uid, $parent=parent];

	# Update Info
	if (host_id in host_processes && pid in host_processes[host_id]) {
		local existing_process_info = host_processes[host_id][pid];
		
		# Path
		if ((!process_info?$path || process_info$path == "") && existing_process_info?$path) {
			process_info$path = existing_process_info$path;
		}
		
		# Cmdline
		if ((!process_info?$cmdline || process_info$cmdline == "") && existing_process_info?$cmdline) {
			process_info$cmdline = existing_process_info$cmdline;
		}
		
		# UID
		if ((!process_info?$uid || process_info$uid == 0 || process_info$uid == -1) && existing_process_info?$uid) {
			process_info$uid = existing_process_info$uid;
		}
		
		# Parent
		if ((!process_info?$parent || process_info$parent == 0 || process_info$parent == -1) && existing_process_info?$parent) {
			process_info$parent = existing_process_info$parent;
		}
	}

	if (host_id in host_processes) {
		host_processes[host_id][pid] = process_info;
	} else {
		host_processes[host_id] = table([pid] = process_info);
	}
	#print(fmt("Added process with pid %d", pid));
	event process_state_added(host_id, process_info);
}

function _remove_process_state(host_id: string, pid: int, path: string, cmdline: string, uid: int, parent: int) {
	local process_info: ProcessInfo = [$pid=pid, $path=path, $cmdline=cmdline, $uid=uid, $parent=parent];
	if (host_id !in host_processes) { return; }
	if (pid !in host_processes[host_id]) { return; }

	process_info = host_processes[host_id][pid];
	delete host_processes[host_id][pid];
	event process_state_removed(host_id, process_info);
}

event scheduled_remove_process_state(host_id: string, pid: int, path: string, cmdline: string, uid: int, parent: int) {
	_remove_process_state(host_id, pid, path, cmdline, uid, parent);
}

event initial_process_state(resultInfo: osquery::ResultInfo,
		pid: int, path: string, cmdline: string, cwd: string, uid: int, gid: int,
		parent: int) {
	_add_process_state(resultInfo$host, pid, path, cmdline, uid, parent);
}

event process_event_added(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int) {
	#print(fmt("Added process with pid %d", pid));
	_add_process_state(host_id, pid, path, cmdline, uid, parent);
}

event process_added(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, 
				 cwd: string,root: string,  uid: int, gid: int, on_dist: int, start_time: int, parent: int, pgroup: int) {
	_add_process_state(host_id, pid, path, cmdline, uid, parent);
}

event process_removed(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, 
				 cwd: string,root: string,  uid: int, gid: int, on_dist: int, start_time: int, parent: int, pgroup: int) {
			#print(fmt("Received event to remove process with pid %d", pid));
	schedule 30sec { scheduled_remove_process_state(host_id, pid, path, cmdline, uid, parent) };
}

event osquery::host_connected(host_id: string) {
        local ev_processes = [$ev=initial_process_state, $query="SELECT pid,path,cmdline,cwd,uid,gid,parent FROM processes WHERE 1=1;"];
	osquery::execute(ev_processes, host_id);
}

function _remove_process_host_state(host_id: string) {
	if (host_id !in host_processes) { return; }

	delete host_processes[host_id];
}

event scheduled_remove_process_host_state(host_id: string) {
	#print(fmt("Removing process state for host %s", host_id));
	_remove_process_host_state(host_id);
	event process_host_state_removed(host_id);
}

event osquery::host_disconnected(host_id: string) {
	schedule 30sec { scheduled_remove_process_host_state(host_id) };
}

function getProcessInfosByHostID(host_id: string): set[ProcessInfo] {
	local process_infos: set[ProcessInfo] = set();
	if (host_id !in host_processes) { return process_infos; }

	for (pid in host_processes[host_id]) {
		add process_infos[host_processes[host_id][pid]];
	}

	return process_infos;
}

function getProcessInfoByHostID(host_id: string, pid: int): ProcessInfo {
	if (host_id !in host_processes) { return []; }
	if (pid !in host_processes[host_id]) { return []; }

	return host_processes[host_id][pid];
}

event process_died(resultInfo: osquery::ResultInfo, pid_str: string) {
	local pid = to_int(pid_str);
	schedule 30sec { scheduled_remove_process_state(resultInfo$host, pid, "", "", -1, -1) };
}

event verify_process_state(host_id: string) {
	local query: osquery::Query;
	local select_pids: vector of string = vector();
	local query_string: string;

	if (!osquery::hosts::isHostAlive(host_id)) { return; }

	if (host_id !in host_processes) { 
		schedule 60sec { verify_process_state(host_id) };
		return; 
	}

	# Collect process state
	for (pid in host_processes[host_id]) {
		if (!host_processes[host_id][pid]?$pid) { next; }
		select_pids[|select_pids|] = fmt("SELECT %d AS x", pid);
	}

	if (|select_pids| != 0) {
		# Select query
		query_string = fmt("SELECT x FROM (%s) WHERE x NOT IN (SELECT pid from processes)" , join_string_vec(select_pids, " UNION "));
	
		# Send query
		query = [$ev=process_died, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Schedule next verification
	schedule 60sec { verify_process_state(host_id) };
}

event osquery::host_connected(host_id: string) {
	event verify_process_state(host_id);
}
