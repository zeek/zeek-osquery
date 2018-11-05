#! 

module osquery::host_network;

@load osquery/host_info/hosts_interfaces
@load osquery/host_info/process_connections

# Add user fields to the connection log record.
redef record Conn::Info += {
    # Process info on the originating system
    orig_hosts: set[string] &optional &log;
    orig_pids: set[int] &optional &log;
    orig_paths: set[string] &optional &log;
    orig_users: set[int] &optional &log;
    # Process info on the responsive system
    resp_hosts: set[string] &optional &log;
    resp_pids: set[int] &optional &log;
    resp_paths: set[string] &optional &log;
    resp_users: set[int] &optional &log;
};

function extend_connection_info(c: connection): bool {

	# Check the origin of the connection
	# - Get list of hosts with this source IP
	local srcHost_infos = osquery::hosts::getHostInfosByAddress(c$conn$id$orig_h);
	# - Get list of hosts with this target IP
	local dstHost_infos = osquery::hosts::getHostInfosByAddress(c$conn$id$resp_h);

	if (|srcHost_infos| + |dstHost_infos| == 0) {
		#print(fmt("No osquery host found for connection (%s:%s -> %s:%s) ", c$conn$id$orig_h, c$conn$id$orig_p, c$conn$id$resp_h, c$conn$id$resp_p));
		return F;
	}

	local result = F;
	local host_id: string;
	local process_connections: vector of osquery::process_connections::ProcessConnection;
	local process_info: osquery::processes::ProcessInfo;
	local socket_info: osquery::sockets::SocketInfo;

	# - Lookup if any of the source candidates connected to the target
	for (host_info_idx in srcHost_infos) {
		host_id = srcHost_infos[host_info_idx]$host;
		process_connections = osquery::process_connections::getProcessConnectionsByHostIDByConnection(host_id, c);
		#if (|process_connections| > 0) { print("Found at least one process connection as source candidate"); }

		# Host
		if (host_id != "") {
			if (!c$conn?$orig_hosts) { c$conn$orig_hosts = set(host_id); }
			else { add c$conn$orig_hosts[host_id]; }
		}

		for (idx in process_connections) {
			process_info = process_connections[idx]$process_info;
			socket_info = process_connections[idx]$socket_info;
	
			local conn = socket_info$connection;
			local srcAddr = "";
 			if (conn?$local_address) { srcAddr = fmt("%s", conn$local_address); }
			local srcPort = "";
 			if (conn?$local_port) { srcPort = fmt("%d", conn$local_port); }
			local dstAddr = "";
 			if (conn?$remote_address) { dstAddr = fmt("%s", conn$remote_address); }
			local dstPort = "";
 			if (conn?$remote_port) { dstPort = fmt("%d", conn$remote_port); }
			local proto = "";
 			if (conn?$protocol) { proto = fmt("%d", conn$protocol); }
		
			#print(fmt("Found source connection for host %s: %s:%s -> %s:%s (%s)", host_id, srcAddr, srcPort, dstAddr, dstPort, proto));
			
			# PID
			if (process_info?$pid) {
				if (!c$conn?$orig_pids) { c$conn$orig_pids = set(process_info$pid); }
				else { add c$conn$orig_pids[process_info$pid]; }
			}
			# Path
			if (process_info?$path) {
				if (!c$conn?$orig_paths) { c$conn$orig_paths = set(process_info$path); }
				else { add c$conn$orig_paths[process_info$path]; }
			}
			# User
			if (process_info?$uid) {
				if (!c$conn?$orig_users) { c$conn$orig_users = set(process_info$uid); }
				else { add c$conn$orig_users[process_info$uid]; }
			}

			result = T;
		}
	}

	# - Lookup if any of the target candidates bound on the target port
	for (host_info_idx in dstHost_infos) {
		host_id = dstHost_infos[host_info_idx]$host;
		process_connections = osquery::process_connections::getProcessConnectionsByHostIDByConnection(host_id, c, T);

		# Host
		if (host_id != "") {
			if (!c$conn?$resp_hosts) { c$conn$resp_hosts = set(host_id); }
			else { add c$conn$resp_hosts[host_id]; }
		}

		for (idx in process_connections) {
			process_info = process_connections[idx]$process_info;
			socket_info = process_connections[idx]$socket_info;
			
			# PID
			if (process_info?$pid) {
				if (!c$conn?$resp_pids) { c$conn$resp_pids = set(process_info$pid); }
				else { add c$conn$resp_pids[process_info$pid]; }
			}
			# Path
			if (process_info?$path) {
				if (!c$conn?$resp_paths) { c$conn$resp_paths = set(process_info$path); }
				else { add c$conn$resp_paths[process_info$path]; }
			}
			# User
			if (process_info?$uid) {
				if (!c$conn?$resp_users) { c$conn$resp_users = set(process_info$uid); }
				else { add c$conn$resp_users[process_info$uid]; }
			}

			result = T;
		}
	}

	return result;
}

event connection_state_remove(c: connection)
{
    if (c$conn$proto != tcp) { return; }

    local success = extend_connection_info(c);

    if (!c$conn?$orig_users && !c$conn?$resp_users) {
        #print(fmt("No User found for connection with id %s (%s:%d -> %s:%d)", c$conn$uid, c$conn$id$orig_h,c$conn$id$orig_p,c$conn$id$resp_h,c$conn$id$resp_p));
    return;
    }

    if (c$conn?$orig_users) {
        #print(fmt("Source user '%s' found for connection with id %s (%s:%d -> %s:%d)", c$conn$orig_user, c$conn$uid, c$conn$id$orig_h,c$conn$id$orig_p,c$conn$id$resp_h,c$conn$id$resp_p));
    
    } 
    if (c$conn?$resp_users) {
        #print(fmt("Target user '%s' found for connection with id %s (%s:%d -> %s:%d)", c$conn$resp_user, c$conn$uid, c$conn$id$orig_h,c$conn$id$orig_p,c$conn$id$resp_h,c$conn$id$resp_p));
    
    }
}
