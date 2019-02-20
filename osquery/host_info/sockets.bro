#! Provide current socket information about hosts.

@load osquery/framework
#@load osquery/logging/tables/listening_ports
@load osquery/logging/tables/process_open_sockets
@load osquery/logging/tables/socket_events

module osquery::sockets;

export {
	type ConnectionTuple: record {
		local_address: addr &optional;
		remote_address: addr &optional;
		local_port: int &optional;
		remote_port: int &optional;
		protocol: int &optional;
	};

	type SocketInfo: record {
		action: string &optional;
		pid: int &optional;
		fd: int &optional;
		path: string &optional;
		family: int &optional;
		connection: ConnectionTuple &default=[];
		start_time: int &optional;
		success: int &optional;
	};

	## Get the SocketInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getSocketInfosByHostID: function(host_id: string): vector of SocketInfo;

	## Get the SocketInfos of a host by its id
	##
	## host_id: The identifier of the host
	## connPattern: The pattern of a connection tuple
	global getSocketInfosByHostIDByConnectionTuple: function(host_id: string, connPattern: ConnectionTuple): vector of SocketInfo;

	## Get the SocketInfos of a host by its id
	##
	## connPattern: The pattern of a connection tuple
	global getSocketInfosByConnectionTuple: function(connPattern: ConnectionTuple): vector of SocketInfo;

	## Checks if the connection is described by the connection pattern
	##
	## <params missing>
	global matchConnectionTuplePattern: function(conn: ConnectionTuple, conn_pattern: ConnectionTuple): bool;

	## Check if two socket infos are equal
	##
	## <params missing>
	global equalSocketInfos: function(sock1: SocketInfo, sock2: SocketInfo): bool;

	## Event when added to the state of sockets
	##
	## <params missing>
	global socket_state_added: event(host_id: string, socket_info: SocketInfo);
	
	## Event when removing a host from the state of sockets
	##
	## <params missing>
	global socket_host_state_removed: event(host_id: string);
	
	## Event when removing from the state of sockets
	##
	## <params missing>
	global socket_state_removed: event(host_id: string, socket_info: SocketInfo);
}

# Table to access SocketInfo by HostID
global host_sockets: table[string] of vector of SocketInfo;

# SocketInfos to delete
global host_sockets_idx_delete: table[string] of set[int];

function equalConnectionTuples(conn1: ConnectionTuple, conn2: ConnectionTuple): bool {
	if (conn1?$local_address != conn2?$local_address) {
		return F;
	}
	if (conn1?$local_address && conn1$local_address != conn2$local_address) {
		return F;
	}
	if (conn1?$remote_address != conn2?$remote_address) {
		return F;
	}
	if (conn1?$remote_address && conn1$remote_address != conn2$remote_address) {
		return F;
	}
	if (conn1?$local_port != conn2?$local_port) {
		return F;
	}
	if (conn1?$local_port && conn1$local_port != conn2$local_port) {
		return F;
	}
	if (conn1?$remote_port != conn2?$remote_port) {
		return F;
	}
	if (conn1?$remote_port && conn1$remote_port != conn2$remote_port) {
		return F;
	}
	if (conn1?$protocol != conn2?$protocol) {
		return F;
	}
	if (conn1?$protocol && conn1$protocol != conn2$protocol) {
		return F;
	}
	return T;
}

function matchConnectionTuplePattern(conn: ConnectionTuple, conn_pattern: ConnectionTuple): bool {
	if (conn_pattern?$local_address && conn_pattern$local_address != 0.0.0.0 && (!conn?$local_address || conn$local_address != conn_pattern$local_address)) {
		return F;
	}
	if (conn_pattern?$remote_address && conn_pattern$remote_address != 0.0.0.0 && (!conn?$remote_address || conn$remote_address != conn_pattern$remote_address)) {
		return F;
	}
	if (conn_pattern?$local_port && conn_pattern$local_port != 0 && (!conn?$local_port || conn$local_port != conn_pattern$local_port)) {
		return F;
	}
	if (conn_pattern?$remote_port && conn_pattern$remote_port != 0 && (!conn?$remote_port || conn$remote_port != conn_pattern$remote_port)) {
		return F;
	}
	if (conn_pattern?$protocol && conn_pattern$protocol != 0 && (!conn?$protocol || conn$protocol != conn_pattern$protocol)) {
		return F;
	}
	return T;
}

function equalSocketInfos(sock1: SocketInfo, sock2: SocketInfo): bool {
	if (sock1?$action != sock2?$action) {
		return F;
	}
	if (sock1?$action && sock1$action != sock2$action) {
		return F;
	}
	if (sock1?$pid != sock2?$pid) {
		return F;
	}
	if (sock1?$pid && sock1$pid != sock2$pid) {
		return F;
	}
	if (sock1?$fd != sock2?$fd) {
		return F;
	}
	if (sock1?$fd && sock1$fd != sock2$fd) {
		return F;
	}
	return equalConnectionTuples(sock1$connection, sock2$connection);
}

function _add_socket_state(host_id: string, action: string, pid: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
	local local_addr: addr;
	local remote_addr: addr;
	if (local_address != "") local_addr = to_addr(local_address);
	if (remote_address != "") remote_addr = to_addr(remote_address);

	local conn: ConnectionTuple;
	if (action == "snapshot") {
		if (local_address == "" || local_port == 0) {
			#print("Add Snapshot: Local address or port is not given");
			return;
		}
		if (remote_address == "" || remote_port == 0) {
			#print("Add Snapshot: Remote address or port is not given");
			return;
		}
		conn = [$local_address=local_addr, $remote_address=remote_addr, $local_port=local_port, $remote_port=remote_port, $protocol=protocol];
	} else if (action == "bind") {
		if (local_address == "" || local_port == 0) {
			#print("Add Bind: Local address or port is not given");
			return;
		}
		conn = [$local_address=local_addr, $local_port=local_port, $protocol=protocol];
	} else if (action == "connect") {
		if (remote_address == "" || remote_port == 0) {
			#print("Add Connect: Remote address or port is not given");
			return;
		}
		conn = [$remote_address=remote_addr, $remote_port=remote_port, $protocol=protocol];
	}

	local socket_info: SocketInfo = [$action=action, $pid=pid, $path=path, $family=family, $connection=conn, $start_time=start_time, $success=success];
	if (host_id in host_sockets) {
		host_sockets[host_id][|host_sockets[host_id]|] = socket_info;
	} else {
		#print(fmt("Adding new host for sockets: %s", host_id));
		host_sockets[host_id] = vector(socket_info);
	}
	event socket_state_added(host_id, socket_info);
	#print(fmt("Added socket with tuple (%s:%d -> %s:%d) and protocol %d", local_address, local_port, remote_address, remote_port, protocol));
}

function _invalidate_socket_state(host_id: string, action: string, pid: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
	#print(fmt("About to remove socket with tuple (%s:%d -> %s:%d) and protocol %d", local_address, local_port, remote_address, remote_port, protocol));
	local local_addr: addr;
	local remote_addr: addr;
	if (local_address != "") local_addr = to_addr(local_address);
	if (remote_address != "") remote_addr = to_addr(remote_address);

	local conn: ConnectionTuple;
	if (action == "snapshot") {
		if (local_address == "" || local_port == 0) {
			#print("Remove Snapshot: Local address or port is not given");
			return;
		}
		if (remote_address == "" || remote_port == 0) {
			#print("Remove Snapshot: Remote address or port is not given");
			return;
		}
		conn = [$local_address=local_addr, $remote_address=remote_addr, $local_port=local_port, $remote_port=remote_port, $protocol=protocol];
	} else if (action == "bind") {
		if (local_address == "" || local_port == 0) {
			#print("Remove Bind: Local address or port is not given");
			return;
		}
		conn = [$local_address=local_addr, $local_port=local_port, $protocol=protocol];
	} else if (action == "connect") {
		if (remote_address == "" || remote_port == 0) {
			#print("Remove Connect: Remote address or port is not given");
			return;
		}
		conn = [$remote_address=remote_addr, $remote_port=remote_port, $protocol=protocol];
	}

	local socket_infos = getSocketInfosByHostIDByConnectionTuple(host_id, conn);
	if (|socket_infos| != 1) {
		#print(fmt("Not exactely 1 SocketInfo (is %d)", |socket_infos|));
		#return;
	}

	# Identify Indexes
	for (idx in host_sockets[host_id]) {
		for (jdx in socket_infos) {
			if (equalSocketInfos(host_sockets[host_id][idx], socket_infos[jdx])) {
				#print(fmt("Removed socket with tuple (%s:%d -> %s:%d) and protocol %d", local_address, local_port, remote_address, remote_port, protocol));
				if (host_id !in host_sockets_idx_delete) {
					host_sockets_idx_delete[host_id] = set();
				}
				add host_sockets_idx_delete[host_id][idx];
			}
		}
	}
}

event _clear_socket_state(host_id: string) {
	if (!osquery::hosts::isHostAlive(host_id)) { return; }

	if (host_id !in host_sockets_idx_delete) { 
		schedule 60sec { _clear_socket_state(host_id) };
		return; 
	}

	local idx_delete: count;
	local socket_infos_new: vector of SocketInfo = vector();
	for (idx in host_sockets[host_id]) {
		if (idx in host_sockets_idx_delete[host_id]) {
			#print(fmt("Removed socket with tuple (%s:%d -> %s:%d) and protocol %d", local_address, local_port, remote_address, remote_port, protocol));
			event socket_state_removed(host_id, host_sockets[host_id][idx]);
			next;
		}
		socket_infos_new[|socket_infos_new|] = host_sockets[host_id][idx];
	}
	host_sockets[host_id] = socket_infos_new;
	delete host_sockets_idx_delete[host_id];
	schedule 60sec { _clear_socket_state(host_id) };
}

event initial_socket_state(resultInfo: osquery::ResultInfo, action: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local path: string = "";
	local start_time = 0;
	local success: int = 1;
	_add_socket_state(resultInfo$host, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success);
}

event scheduled_remove_socket_state(host_id: string, action: string, pid: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
	_invalidate_socket_state(host_id, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success);
}

event socket_event_added(t: time, host_id: string, action: string, pid: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int;) {
	#print("socket_event_added");
	_add_socket_state(host_id, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success);
}

event process_open_socket_added(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local action: string = "snapshot";
	local path: string = "";
	local start_time = 0;
	local success: int = 1;
	#print("process_open_socket_added");
	_add_socket_state(host_id, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success);
}

event process_open_socket_removed(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local action: string = "snapshot";
	local path: string = "";
	local start_time = 0;
	local success: int = 1;
	#print(fmt("Received event to remove socket with tuple (%s:%d -> %s:%d) and protocol %d", local_address, local_port, remote_address, remote_port, protocol));
	schedule 30sec {scheduled_remove_socket_state(host_id, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success)};
}

event listening_port_added(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local action: string = "bind";
	local path: string = "";
	local start_time = 0;
	local success: int = 1;
	local remote_address = "0.0.0.0";
	local remote_port = 0;
	_add_socket_state(host_id, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success);
}

event listening_port_removed(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local action: string = "bind";
	local path: string = "";
	local start_time = 0;
	local success: int = 1;
	local remote_address = "0.0.0.0";
	local remote_port = 0;
	#print(fmt("Received event to remove socket with tuple (%s:%d -> %s:%d) and protocol %d", local_address, local_port, remote_address, remote_port, protocol));
	#schedule 30sec {scheduled_remove_socket_state(host_id, action, pid, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success)};
}

function _remove_socket_host_state(host_id: string) {
	if (host_id !in host_sockets) { return; }
	delete host_sockets[host_id];
}

event scheduled_remove_socket_host_state(host_id: string) {
	_remove_socket_host_state(host_id);
	event socket_host_state_removed(host_id);
}

event osquery::host_disconnected(host_id: string) {
	schedule 30sec { scheduled_remove_socket_host_state(host_id) };
}

event osquery::host_connected(host_id: string) {
        local query = [$ev=initial_socket_state, $query="SELECT 'snapshot' AS action, pid, fd, family, protocol, local_address, remote_address, local_port, remote_port from process_open_sockets WHERE family=2 AND 1=1"];
	osquery::execute(query, host_id);
}

function getSocketInfosByHostID(host_id: string): vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();
	
	if (host_id !in host_sockets) {
		return socket_infos;
	}

	for (idx in host_sockets[host_id]) {
		socket_infos[|socket_infos|] = host_sockets[host_id][idx];
	}

	return socket_infos;
}

function getSocketInfosByHostIDByConnectionTuple(host_id: string, connPattern: ConnectionTuple): vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();

	if (host_id !in host_sockets) {
		return socket_infos;
	}

	for (idx in host_sockets[host_id]) {
		if (matchConnectionTuplePattern(host_sockets[host_id][idx]$connection, connPattern)) {
			socket_infos[|socket_infos|] = host_sockets[host_id][idx];
		}
	}

	return socket_infos;
}

function getSocketInfosByConnectionTuple(connPattern: ConnectionTuple):  vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();

	for (host_id in host_sockets) {
		for (idx in host_sockets[host_id]) {
			if (matchConnectionTuplePattern(host_sockets[host_id][idx]$connection, connPattern)) {
				socket_infos[|socket_infos|] = host_sockets[host_id][idx];
			}
		}
	}
	return socket_infos;
}

event socket_died_bind(resultInfo: osquery::ResultInfo, pid_str: string, family_str: string, local_addr: string, local_port_str: string) {
	local pid = to_int(pid_str);
	local family = to_int(family_str);
	local local_port = to_int(local_port_str);
	
	local action: string = "bind";
	local path: string = "";
	local protocol: int = 0;
	local remote_addr: string = "0.0.0.0";
	local remote_port: int = 0;
	local start_time: int = 0;
	local success: int = 1;
	schedule 30sec { scheduled_remove_socket_state(resultInfo$host, action, pid, path, family, protocol, local_addr, remote_addr, local_port, remote_port, start_time, success) };
}

event socket_died_bind_proto(resultInfo: osquery::ResultInfo, pid_str: string, family_str: string, local_addr: string, local_port_str: string, proto_str: string) {
	local pid = to_int(pid_str);
	local family = to_int(family_str);
	local local_port = to_int(local_port_str);
	local protocol = to_int(proto_str);
	
	local action: string = "bind";
	local path: string = "";
	local remote_addr: string = "0.0.0.0";
	local remote_port: int = 0;
	local start_time: int = 0;
	local success: int = 1;
	schedule 30sec { scheduled_remove_socket_state(resultInfo$host, action, pid, path, family, protocol, local_addr, remote_addr, local_port, remote_port, start_time, success) };
}

event socket_died_conn(resultInfo: osquery::ResultInfo, pid_str: string, family_str: string, remote_addr: string, remote_port_str: string) {
	local pid = to_int(pid_str);
	local family = to_int(family_str);
	local remote_port = to_int(remote_port_str);
	
	local action: string = "connect";
	local path: string = "";
	local protocol: int = 0;
	local local_addr: string = "0.0.0.0";
	local local_port: int = 0;
	local start_time: int = 0;
	local success: int = 1;
	schedule 30sec { scheduled_remove_socket_state(resultInfo$host, action, pid, path, family, protocol, local_addr, remote_addr, local_port, remote_port, start_time, success) };
}

event socket_died_snap(resultInfo: osquery::ResultInfo, pid_str: string, family_str: string, local_addr: string, remote_addr: string, local_port_str: string, remote_port_str: string, proto_str: string) {
	local pid = to_int(pid_str);
	local family = to_int(family_str);
	local local_port = to_int(local_port_str);
	local remote_port = to_int(remote_port_str);
	local protocol = to_int(proto_str);
	
	local action: string = "snapshot";
	local path: string = "";
	local start_time: int = 0;
	local success: int = 1;
	schedule 30sec { scheduled_remove_socket_state(resultInfo$host, action, pid, path, family, protocol, local_addr, remote_addr, local_port, remote_port, start_time, success) };
}

event verify_socket_state(host_id: string) {
	local query: osquery::Query;
	local select_conns_bind: vector of string = vector();
	local select_conns_bind_proto: vector of string = vector();
	local select_conns_connect: vector of string = vector();
	local select_conns_snapshot: vector of string = vector();
	local query_string: string;
	local socket_info: SocketInfo;
	local conn: ConnectionTuple;

	if (!osquery::hosts::isHostAlive(host_id)) { return; }

	if (host_id !in host_sockets) { 
		schedule 60sec { verify_socket_state(host_id) };
		return; 
	}

	# Collect socket state
	for (idx in host_sockets[host_id]) {
	
		socket_info = host_sockets[host_id][idx];
		if (!socket_info?$action) { next; }
		conn = socket_info$connection;
			
		# Bind
		if (socket_info$action == "bind") {
			if (conn?$protocol) {
				select_conns_bind_proto[|select_conns_bind_proto|] = fmt("SELECT %d AS pid, %d AS family, \"%s\" AS local_address, %d AS local_port, %d AS protocol", socket_info$pid, socket_info$family, conn$local_address, conn$local_port, conn$protocol);
			} else {
				select_conns_bind[|select_conns_bind|] = fmt("SELECT %d AS pid, %d AS family, \"%s\" AS local_address, %d AS local_port", socket_info$pid, socket_info$family, conn$local_address, conn$local_port);
			}
		} 
		# Connect
		else if (socket_info$action == "connect") {
			select_conns_connect[|select_conns_connect|] = fmt("SELECT %d AS pid, %d AS family, \"%s\" AS remote_address, %d AS remote_port", socket_info$pid, socket_info$family, conn$remote_address, conn$remote_port);
		}
		# Snapshot
		else if (socket_info$action == "snapshot") {
			select_conns_snapshot[|select_conns_snapshot|] = fmt("SELECT %d AS pid, %d AS family, \"%s\" AS local_address, \"%s\" AS remote_address, %d AS local_port, %d AS remote_port, %d AS protocol", socket_info$pid, socket_info$family, conn$local_address, conn$remote_address, conn$local_port, conn$remote_port, conn$protocol);
		}
	}

	# Bind
	if (|select_conns_bind| != 0) {
		# Select query
		query_string = fmt("SELECT b.pid, b.family, b.local_address, b.local_port FROM (%s) AS b LEFT JOIN (SELECT pid, family, local_address, local_port FROM listening_ports WHERE family = 2 AND pid != -1) AS o ON b.pid = o.pid AND b.family = o.family AND b.local_address = o.local_address AND b.local_port = o.local_port WHERE o.pid IS NULL" , join_string_vec(select_conns_bind, " UNION "));
	
		# Send query
		query = [$ev=socket_died_bind, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Bind with Proto
	if (|select_conns_bind_proto| != 0) {
		# Select query
		query_string = fmt("SELECT b.pid, b.family, b.local_address, b.local_port, b.protocol FROM (%s) AS b LEFT JOIN (SELECT pid, family, local_address, local_port, protocol FROM listening_ports WHERE family = 2 AND pid != -1) AS o ON b.pid = o.pid AND b.family = o.family AND b.local_address = o.local_address AND b.local_port = o.local_port AND b.protocol = o.protocol WHERE o.pid IS NULL" , join_string_vec(select_conns_bind_proto, " UNION "));
	
		# Send query
		query = [$ev=socket_died_bind_proto, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Connect
	if (|select_conns_connect| != 0) {
		# Select query
		query_string = fmt("SELECT b.pid, b.family, b.remote_address, b.remote_port FROM (%s) AS b LEFT JOIN (SELECT pid, family, remote_address, remote_port FROM process_open_sockets WHERE family = 2 AND pid != -1) AS o ON b.pid = o.pid AND b.family = o.family AND b.remote_address = o.remote_address AND b.remote_port = o.remote_port WHERE o.pid IS NULL" , join_string_vec(select_conns_connect, " UNION "));
	
		# Send query
		query = [$ev=socket_died_conn, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Snapshot
	if (|select_conns_snapshot| != 0) {
		# Select query
		query_string = fmt("SELECT b.pid, b.family, b.local_address, b.remote_address, b.local_port, b.remote_port, b.protocol FROM (%s) AS b LEFT JOIN (SELECT pid, family, local_address, remote_address, local_port, remote_port, protocol FROM process_open_sockets WHERE family = 2 AND pid != -1) AS o ON b.pid = o.pid AND b.family = o.family AND b.local_address = o.local_address AND b.remote_address = o.remote_address AND b.local_port = o.local_port AND b.remote_port = o.remote_port AND b.protocol = o.protocol WHERE o.pid IS NULL" , join_string_vec(select_conns_snapshot, " UNION "));
	
		# Send query
		query = [$ev=socket_died_snap, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Schedule next verification
	schedule 60sec { verify_socket_state(host_id) };
}

event osquery::host_connected(host_id: string) {
	event verify_socket_state(host_id);
	schedule 30sec { _clear_socket_state(host_id) };
}

