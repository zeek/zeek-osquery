redef exit_only_after_terminate = T;

@load osquery/host_info/process_connections

type AddedEvents: record {
	host_id: string;
	process_info: osquery::processes::ProcessInfo;
	socket_info: osquery::sockets::SocketInfo;
};

global added_event_args: vector of AddedEvents;

function _pc_create_connection(conn: osquery::sockets::ConnectionTuple): connection {
	local c: connection;
	local c_info: Conn::Info;
	local c_id: conn_id;
	local endp: endpoint;
	local service: set[string] = set();
	local proto_conv = table([+6] = tcp, [+17] = udp);

	if (conn?$local_address) { c_id$orig_h = conn$local_address; }
	if (conn?$remote_address) { c_id$resp_h = conn$remote_address; }
	if (conn?$local_port && conn$local_port != 0 && conn?$protocol) {
		c_id$orig_p = count_to_port(int_to_count(conn$local_port), proto_conv[conn$protocol]);
	}
	if (conn?$remote_port && conn$remote_port != 0 && conn?$protocol) {
		c_id$resp_p = count_to_port(int_to_count(conn$remote_port), proto_conv[conn$protocol]);
	}

	local proto_enum: transport_proto = unknown_transport;
	if (conn?$protocol) { proto_enum = proto_conv[conn$protocol]; }
	c_info = [$ts=current_time(), $uid="", $id=c_id, $proto=proto_enum];

	endp = [$size=0, $state=0, $flow_label=0];

	c = [$id=c_id, $conn=c_info, $orig=endp, $resp=endp, $start_time=c_info$ts, $duration=0sec, $service=service, $history="", $uid=c_info$uid];
	
	return c;
}

event osquery::process_connections::process_connection_added(host_id: string, process_info: osquery::processes::ProcessInfo, socket_info: osquery::sockets::SocketInfo) {
	added_event_args[|added_event_args|] = [$host_id=host_id, $process_info=process_info, $socket_info=socket_info];
}

function _pc_evaluate_added_event_args(n: count): bool {
	if (|added_event_args| != n) { return F; }
	if (n == 0) { return T; }

	return T;
}

function _pc_evaluate_retrieve_connections(n: count, host_id: string, conn: connection, reverse: bool): bool {
	local process_connections: vector of osquery::process_connections::ProcessConnection;
	process_connections = osquery::process_connections::getProcessConnectionsByHostIDByConnection(host_id, conn, reverse);
	if (|process_connections| != n) { return F; }
	if (n == 0) { return T; }

	return T;
}

event pc_test_1_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(0);
	if (!success) {
		print("[FAIL] pc_test_1 failed");
	}

	local conn = [];
	success = _pc_evaluate_retrieve_connections(0, "", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_1 failed");
	}
}

event pc_test_1() {
	print("Starting Test 1");

	# Clear added process connections
	added_event_args = vector();

	# No state added
	print("- Adding state");
	# <nothing>

	# Verify extension of connection
	schedule 1sec { pc_test_1_verify() };
}

event pc_test_2_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(0);
	if (!success) {
		print("[FAIL] pc_test_2 failed");
	}

	local conn = [];
	success = _pc_evaluate_retrieve_connections(0, "", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_2 failed");
	}

	if (|osquery::processes::getProcessInfosByHostID("orig_host_id_string")| == 0) {
		success = T;
	} else { success = F;}
	if (!success) {
		print("[FAIL] pc_test_2 failed");
	}

	event scheduled_remove_socket_host_state("orig_host_id_string");
}

event pc_test_2() {
	print("Starting Test 2");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_process_state([$host="orig_host_id_string",$utype=osquery::SNAPSHOT], +42, "", "", "", +0, +0, +0) };
	schedule 0.1sec { scheduled_remove_process_state("orig_host_id_string", +42, "", "", +0, +0) };
	schedule 0.2sec { process_open_socket_added(current_time(), "orig_host_id_string", +42, +0, +2, +6, "1.1.1.1", "2.2.2.2", +8080, +80) };

	# Verify extension of connection
	schedule 1sec { pc_test_2_verify() };
}

event pc_test_3_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(0);
	if (!success) {
		print("[FAIL] pc_test_3 failed");
	}

	local conn = [];
	success = _pc_evaluate_retrieve_connections(0, "", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_3 failed");
	}

	if (|osquery::sockets::getSocketInfosByHostID("orig_host_id_string")| == 0) {
		success = T;
	} else { success = F; print("False"); }
	if (!success) {
		print("[FAIL] pc_test_3 failed");
	}

	event scheduled_remove_process_host_state("orig_host_id_string");
}

event pc_test_3() {
	print("Starting Test 3");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_socket_state([$host="orig_host_id_string",$utype=osquery::SNAPSHOT], "snapshot", +42, +0, +2, +6, "1.1.1.1", "2.2.2.2", +8080, +80) };
	schedule 0.1sec { scheduled_remove_socket_state("orig_host_id_string", "snapshot", +42, "", +2, +6, "1.1.1.1", "2.2.2.2", +8080, +80, 0, 0) };
	schedule 0.2sec { process_added(current_time(), "orig_host_id_string", +42, "", "", "", "", "", +0, +0, +0, +0, +0, +0) };

	# Verify extension of connection
	schedule 1sec { pc_test_3_verify() };
}

event pc_test_4_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(1);
	if (!success) {
		print("[FAIL] pc_test_4 failed");
	}

	local conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "orig_host_id_string", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_4 failed");
	}

	event scheduled_remove_process_host_state("orig_host_id_string");
	event scheduled_remove_socket_host_state("orig_host_id_string");
}

event pc_test_4() {
	print("Starting Test 4");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_process_state([$host="orig_host_id_string",$utype=osquery::SNAPSHOT], +42, "", "", "", +0, +0, +0) };
	schedule 0.1sec { process_open_socket_added(current_time(), "orig_host_id_string", +42, +0, +2, +6, "1.1.1.1", "2.2.2.2", +8080, +80) };

	# Verify extension of connection
	schedule 1sec { pc_test_4_verify() };
}

event pc_test_5_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(1);
	if (!success) {
		print("[FAIL] pc_test_5 failed");
	}

	local conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "orig_host_id_string", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_5 failed");
	}

	event scheduled_remove_process_host_state("orig_host_id_string");
	event scheduled_remove_socket_host_state("orig_host_id_string");
}

event pc_test_5() {
	print("Starting Test 5");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_socket_state([$host="orig_host_id_string",$utype=osquery::SNAPSHOT], "snapshot", +42, +0, +2, +6, "1.1.1.1", "2.2.2.2", +8080, +80) };
	schedule 0.1sec { process_added(current_time(), "orig_host_id_string", +42, "", "", "", "", "", +0, +0, +0, +0, +0, +0) };

	# Verify extension of connection
	schedule 1sec { pc_test_5_verify() };
}

event pc_test_6_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(1);
	if (!success) {
		print("[FAIL] pc_test_6 failed");
	}

	local conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "orig_host_id_string", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_6 failed");
	}

	event scheduled_remove_process_host_state("orig_host_id_string");
	event scheduled_remove_socket_host_state("orig_host_id_string");
}

event pc_test_6() {
	print("Starting Test 6");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_process_state([$host="orig_host_id_string",$utype=osquery::SNAPSHOT], +42, "", "", "", +0, +0, +0) };
	schedule 0.1sec { socket_event_added(current_time(), "orig_host_id_string", "connect", +42, "", +2, +0, "", "2.2.2.2", +0, +80, +0, +0) };

	# Verify extension of connection
	schedule 1sec { pc_test_6_verify() };
}

event pc_test_7_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(1);
	if (!success) {
		print("[FAIL] pc_test_7 failed");
	}

	local conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "resp_host_id_string", _pc_create_connection(conn), T);
	if (!success) {
		print("[FAIL] pc_test_7 failed");
	}

	event scheduled_remove_process_host_state("resp_host_id_string");
	event scheduled_remove_socket_host_state("resp_host_id_string");
}

event pc_test_7() {
	print("Starting Test 7");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_process_state([$host="resp_host_id_string",$utype=osquery::SNAPSHOT], +1337, "", "", "", +0, +0, +0) };
	schedule 0.1sec { socket_event_added(current_time(), "resp_host_id_string", "bind", +1337, "", +2, +0, "2.2.2.2", "", +80, +0, +0, +0) };

	# Verify extension of connection
	schedule 1sec { pc_test_7_verify() };
}

event pc_test_8_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(1);
	if (!success) {
		print("[FAIL] pc_test_8 failed");
	}

	local conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "orig_host_id_string", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_8 failed");
	}

	event scheduled_remove_process_host_state("orig_host_id_string");
	event scheduled_remove_socket_host_state("orig_host_id_string");
}

event pc_test_8() {
	print("Starting Test 8");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { initial_socket_state([$host="orig_host_id_string",$utype=osquery::SNAPSHOT], "snapshot", +42, +0, +2, +6, "1.1.1.1", "2.2.2.2", +8080, +80) };
	schedule 0.1sec { process_event_added(current_time(), "orig_host_id_string", +42, "", "", "", +0, +0, +0, +0) };

	# Verify extension of connection
	schedule 1sec { pc_test_8_verify() };
}

event pc_test_9_verify() {
	print("- Verifying extension of connection");

	local success = _pc_evaluate_added_event_args(2);
	if (!success) {
		print("[FAIL] pc_test_9 failed");
	}

	local conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "orig_host_id_string", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_9 failed");
	}

	# Wrong Flow Direction
	conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(0, "orig_host_id_string", _pc_create_connection(conn), T);
	if (!success) {
		print("[FAIL] pc_test_9 failed");
	}

	conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(1, "resp_host_id_string", _pc_create_connection(conn), T);
	if (!success) {
		print("[FAIL] pc_test_9 failed");
	}

	# Wrong Flow Direction
	conn = [$local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6];
	success = _pc_evaluate_retrieve_connections(0, "resp_host_id_string", _pc_create_connection(conn), F);
	if (!success) {
		print("[FAIL] pc_test_9 failed");
	}

	event scheduled_remove_process_host_state("orig_host_id_string");
	event scheduled_remove_socket_host_state("orig_host_id_string");
	event scheduled_remove_process_host_state("resp_host_id_string");
	event scheduled_remove_socket_host_state("resp_host_id_string");
}

event pc_test_9() {
	print("Starting Test 9");

	# Clear added process connections
	added_event_args = vector();

	# State 
	print("- Adding state");
	schedule 0.0sec { process_added(current_time(), "orig_host_id_string", +42, "", "", "", "", "", +0, +0, +0, +0, +0, +0) };
	schedule 0.1sec { socket_event_added(current_time(), "orig_host_id_string", "connect", +42, "", +2, +0, "", "2.2.2.2", +0, +80, +0, +0) };
	schedule 0.2sec { process_event_added(current_time(), "resp_host_id_string", +1337, "", "", "", +0, +0, +0, +0) };
	schedule 0.3sec { process_open_socket_added(current_time(), "resp_host_id_string", +1337, +0, +2, +6, "2.2.2.2", "1.1.1.1", +80, +8080) };

	# Verify extension of connection
	schedule 1sec { pc_test_9_verify() };
}

event pc_scheduled_terminate() {
	terminate();
}

event bro_init() {

	print("Executing 9 process connection tests");

	# No state
	#
	schedule 0sec { pc_test_1() };

	# Process state removal
	#
	schedule 2sec { pc_test_2() };

	# Socket state removal
	#
	schedule 4sec { pc_test_3() };

	# Initial Process + Open Socket state
	#
	schedule 6sec { pc_test_4() };

	# Initial Socket + Process state
	#
	schedule 8sec { pc_test_5() };

	#Diese Tests sind noch zu schreiben!

	# Initial Process + Socket Connect state
	#
	schedule 10sec { pc_test_6() };

	# Initial Process + Socket Bind state
	#
	schedule 12sec { pc_test_7() };

	# Initial Socket + Process Event state
	#
	schedule 14sec { pc_test_8() };

	# Both direction mix snapshot and events
	#
	schedule 16sec { pc_test_9() };
	
	schedule 18sec { pc_scheduled_terminate() };
}
