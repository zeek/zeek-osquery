#! Logs process connections activity

module osquery::process_connections;

@load osquery/host_info/processes
@load osquery/host_info/sockets

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		host: string &log;
		pid: int &log;
		parent: int &log;
		path: string &log;
		cmdline: string &log;
		uid: int &log;
		# Missing User Info
		family: int &log;
		local_address: addr &log &optional;
		remote_address: addr &log &optional;
		local_port: int &log &optional;
		remote_port: int &log &optional;
		protocol: int &log &optional;
	};

	type ProcessConnection: record {
		process_info: osquery::processes::ProcessInfo &optional;
		socket_info: osquery::sockets::SocketInfo &optional;
	};

	type ProcessConnections: record {
		process_info: osquery::processes::ProcessInfo &optional;
		socket_infos: vector of osquery::sockets::SocketInfo &optional;
	};

	## Get all Process Connections of a host that match a connection
	##
	## <params missing>
	global getProcessConnectionsByHostIDByConnection: function(host_id: string, conn: connection, reverse: bool &default=F): vector of ProcessConnection;

	## Event to indicate that a processes was correlated with a socket connection
	##
	## <params missing>
	global process_connection_added: event(host_id: string, process_info: osquery::processes::ProcessInfo, socket_info: osquery::sockets::SocketInfo);
}

global host_process_connections: table[string] of vector of ProcessConnections;

function convert_conn_to_conntuple(c: connection, reverse: bool): osquery::sockets::ConnectionTuple {
	local local_port: int = port_to_count(c$conn$id$orig_p) + 0;
	local remote_port: int = port_to_count(c$conn$id$resp_p) + 0;
	local proto = -1;
	if (c$conn$proto == tcp) { proto = 6; }
	else if (c$conn$proto == udp) { proto = 17; }

	if (reverse) {
		return [$local_address=c$conn$id$resp_h, $remote_address=c$conn$id$orig_h, $local_port=remote_port, $remote_port=local_port, $protocol=proto];
	}

	return [$local_address=c$conn$id$orig_h, $remote_address=c$conn$id$resp_h, $local_port=local_port, $remote_port=remote_port, $protocol=proto];

}

function getProcessConnectionsByHostIDByProcessID(host_id: string, pid: int): ProcessConnections {
	if (host_id !in host_process_connections) { return []; }

	for (idx in host_process_connections[host_id]) {
		local process_connections = host_process_connections[host_id][idx];
		if (process_connections$process_info$pid != pid) { next; }

		return process_connections;
	}
	return [];
}

event osquery::process_connections::process_connection_added(host_id: string, process_info: osquery::processes::ProcessInfo, socket_info: osquery::sockets::SocketInfo) {
	local info: Info = [
		$host = host_id,
		$pid = process_info$pid,
		$parent = process_info$parent,
		$path = process_info$path,
		$cmdline = process_info$cmdline,
		$uid = process_info$uid,
		$family = socket_info$family
#		$local_address = socket_info$connection$local_address,
#		$remote_address = socket_info$connection$remote_address,
#		$local_port = socket_info$connection$local_port,
#		$remote_port = socket_info$connection$remote_port,
#		$protocol = socket_info$connection$protocol
	];

	if (socket_info$connection?$local_address) { info$local_address = socket_info$connection$local_address; }
	if (socket_info$connection?$remote_address) { info$remote_address = socket_info$connection$remote_address; }
	if (socket_info$connection?$local_port) { info$local_port = socket_info$connection$local_port; }
	if (socket_info$connection?$remote_port) { info$remote_port = socket_info$connection$remote_port; }
	if (socket_info$connection?$protocol) { info$protocol = socket_info$connection$protocol; }

	Log::write(LOG, info);
}

event socket_state_added(host_id: string, socket_info: osquery::sockets::SocketInfo) {
	if (!socket_info?$pid) { return; }
	local pid: int = socket_info$pid;

	# Try to extend the Process Connections
	local process_connections = getProcessConnectionsByHostIDByProcessID(host_id, pid);
	if (process_connections?$process_info) {
		process_connections$socket_infos[|process_connections$socket_infos|] = socket_info;
		event osquery::process_connections::process_connection_added(host_id, process_connections$process_info, socket_info);
		return;
	}

	# Try to find the Process in state
	local process_info = osquery::processes::getProcessInfoByHostID(host_id, pid);
	if (!process_info?$pid) { return; }
	
	if (host_id in host_process_connections) {
		host_process_connections[host_id][|host_process_connections[host_id]|] = [$process_info=process_info, $socket_infos=vector(socket_info)];
	} else {
		host_process_connections[host_id] = vector([$process_info=process_info, $socket_infos=vector(socket_info)]);;
	}
	event osquery::process_connections::process_connection_added(host_id, process_info, socket_info);
}


event socket_state_removed(host_id: string, socket_info: osquery::sockets::SocketInfo) {
	if (host_id !in host_process_connections) { return; }
	local connection_socket_info: osquery::sockets::SocketInfo;
	local delete_idxs: set[int] = set();
	local socket_infos_new: vector of osquery::sockets::SocketInfo;

	for (process_connections_idx in host_process_connections[host_id]) {

		# Check if process has connection
		for (socket_info_idx in host_process_connections[host_id][process_connections_idx]$socket_infos)	{
			connection_socket_info = host_process_connections[host_id][process_connections_idx]$socket_infos[socket_info_idx];
			if (osquery::sockets::equalSocketInfos(connection_socket_info, socket_info)) { add delete_idxs[socket_info_idx]; }
		}
		if (|delete_idxs| == 0) { next; }

		# Delete from socket infos
		socket_infos_new = vector();
		for (socket_info_idx in host_process_connections[host_id][process_connections_idx]$socket_infos)	{
			connection_socket_info = host_process_connections[host_id][process_connections_idx]$socket_infos[socket_info_idx];
			if (socket_info_idx in delete_idxs) { next; }
			socket_infos_new[|socket_infos_new|] = connection_socket_info;
		}
		host_process_connections[host_id][process_connections_idx]$socket_infos = socket_infos_new;
	}
}

event socket_host_state_removed(host_id: string) {
	if (host_id !in host_process_connections) { return; }
	delete host_process_connections[host_id];
}

event process_state_added(host_id: string, process_info: osquery::processes::ProcessInfo) {
	if (!process_info?$pid) { return; }
	local pid: int = process_info$pid;

	# Check if Process already exists
	local process_connections= getProcessConnectionsByHostIDByProcessID(host_id, pid);
	if (process_connections?$process_info) { return; }

	# Try to find the corresponding sockets
	local socket_infos = osquery::sockets::getSocketInfosByHostID(host_id);
	for (idx in socket_infos) {
		local socket_info = socket_infos[idx];
		if (socket_info$pid != process_info$pid) { next; }

		if (host_id in host_process_connections) {
			host_process_connections[host_id][|host_process_connections[host_id]|] = [$process_info=process_info, $socket_infos=vector(socket_info)];
		} else {
			host_process_connections[host_id] = vector([$process_info=process_info, $socket_infos=vector(socket_info)]);
		}
		event osquery::process_connections::process_connection_added(host_id, process_info, socket_info);
	}
}

event process_state_removed(host_id: string, process_info: osquery::processes::ProcessInfo) {
	if (host_id !in host_process_connections) { return; }
	local connection_process_info: osquery::processes::ProcessInfo;
	local delete_idxs: set[int] = set();
	local process_connections_new: vector of ProcessConnections;

	# Check if process is known
	for (process_connections_idx in host_process_connections[host_id]) {
		connection_process_info = host_process_connections[host_id][process_connections_idx]$process_info;

		if (osquery::processes::equalProcessInfos(connection_process_info, process_info)) { add delete_idxs[process_connections_idx]; }
	}
	if (|delete_idxs| == 0) { return; }

	# Delete from process connections
	process_connections_new = vector();
	for (process_connections_idx in host_process_connections[host_id]) {
		if (process_connections_idx in delete_idxs) { next; }
		process_connections_new[|process_connections_new|] = host_process_connections[host_id][process_connections_idx];
	}
	host_process_connections[host_id] = process_connections_new;
}

event process_host_state_removed(host_id: string) {
	if (host_id !in host_process_connections) { return; }
	delete host_process_connections[host_id];
}

function getProcessConnectionsByHostIDByConnection(host_id: string, conn: connection, reverse: bool): vector of ProcessConnection {
	if (host_id !in host_process_connections) { return vector();}
	local results: vector of ProcessConnection = vector();

	# Iterate all processes of this host
	for (idx_i in host_process_connections[host_id]) {
		local process_connections = host_process_connections[host_id][idx_i];
		
		# Iterate all connections of this process
		for (idx_j in process_connections$socket_infos) {
			local socket_info = process_connections$socket_infos[idx_j];
			local conn_pattern = convert_conn_to_conntuple(conn, reverse);

			# Switch arguments
			local c = socket_info$connection;
			local srcAddr = "";
 			if (c?$local_address) { srcAddr = fmt("%s", c$local_address); }
			local srcPort = "";
 			if (c?$local_port) { srcPort = fmt("%d", c$local_port); }
			local dstAddr = "";
 			if (c?$remote_address) { dstAddr = fmt("%s", c$remote_address); }
			local dstPort = "";
 			if (c?$remote_port) { dstPort = fmt("%d", c$remote_port); }
			local proto = "";
 			if (c?$protocol) { proto = fmt("%d", c$protocol); }
			#print(fmt("Checking for host %s if %s:%d -> %s:%d (%s) matches %s:%s -> %s:%s (%s)", host_id, conn_pattern$local_address, conn_pattern$local_port, conn_pattern$remote_address, conn_pattern$remote_port, conn_pattern$protocol, srcAddr, srcPort, dstAddr, dstPort, proto));
			if (!osquery::sockets::matchConnectionTuplePattern(conn_pattern, socket_info$connection)) { next; }
			
			results[|results|] = [$process_info=process_connections$process_info, $socket_info=socket_info];
		}
		
	}

	return results;
}

event bro_init() {
	Log::create_stream(LOG, [$columns=Info, $path="osq-process_connections"]);
}

