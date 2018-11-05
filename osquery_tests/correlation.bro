redef exit_only_after_terminate = T;

@load osquery/detection/host_network

function _create_connection(): connection {
	local c: connection;
	local c_id: conn_id;
	local endp: endpoint;
	local service: set[string] = set();

	c_id = [$orig_h=1.1.1.1, $orig_p=8080/tcp, $resp_h=2.2.2.2, $resp_p=80/tcp];

	endp = [$size=0, $state=0, $flow_label=0];

	c = [$id=c_id, $orig=endp, $resp=endp, $start_time=current_time(), $duration=0sec, $service=service, $history="", $uid=""];
	
	return c;
}

function _test_single_common(c: connection, orig_hosts: bool, orig_pids: bool, orig_paths: bool, orig_users: bool, resp_hosts: bool, resp_pids: bool, resp_paths: bool, resp_users: bool): bool {
	local success = T;

	# Orig Hosts
	if (orig_hosts) {
		if (!c$conn?$orig_hosts || |c$conn$orig_hosts| != 1 || "host_orig_id_string" !in c$conn$orig_hosts) { success = F; }
	} else {
		if (c$conn?$orig_hosts) { success = F; }
	}

	# Orig Pids
	if (orig_pids) {
		if (!c$conn?$orig_pids || |c$conn$orig_pids| != 1 || +42 !in c$conn$orig_pids) { success = F; }
	} else {
		if (c$conn?$orig_pids) { success = F; }
	}

	# Orig Paths
	if (orig_paths) {
		if (!c$conn?$orig_paths) { success = F; }
	} else {
		if (c$conn?$orig_paths) { success = F; }
	}

	# Orig Users
	if (orig_users) {
		if (!c$conn?$orig_users) { success = F; }
	} else {
		if (c$conn?$orig_users) { success = F; }
	}

	# Resp Hosts
	if (resp_hosts) {
		if (!c$conn?$resp_hosts || |c$conn$resp_hosts| != 1 || "host_resp_id_string" !in c$conn$resp_hosts) { success = F; }
	} else {
		if (c$conn?$resp_hosts) { success = F; }
	}

	# Resp Pids
	if (resp_pids) {
		if (!c$conn?$resp_pids || |c$conn$resp_pids| != 1 || +1337 !in c$conn$resp_pids) { success = F; }
	} else {
		if (c$conn?$resp_pids) { success = F; }
	}

	# Resp Paths
	if (resp_paths) {
		if (!c$conn?$resp_paths) { success = F; }
	} else {
		if (c$conn?$resp_paths) { success = F; }
	}

	# Resp Users
	if (resp_users) {
		if (!c$conn?$resp_users) { success = F; }
	} else {
		if (c$conn?$resp_users) { success = F; }
	}

	return success;
}

function _test_multiple_common(c: connection, orig_hosts: bool, orig_pids: bool, orig_paths: bool, orig_users: bool, resp_hosts: bool, resp_pids: bool, resp_paths: bool, resp_users: bool): bool {
	local success = T;

	# Orig Hosts
	if (orig_hosts) {
		if (!c$conn?$orig_hosts || |c$conn$orig_hosts| != 3 || "host_orig_id_string1" !in c$conn$orig_hosts || "host_orig_id_string2" !in c$conn$orig_hosts || "host_orig_id_string3" !in c$conn$orig_hosts) { success = F; }
	} else {
		if (c$conn?$orig_hosts) { success = F; }
	}

	# Orig Pids
	if (orig_pids) {
		if (!c$conn?$orig_pids || |c$conn$orig_pids| != 1 || +42 !in c$conn$orig_pids) { success = F; }
	
	} else {
		if (c$conn?$orig_pids) { success = F; }
	}

	# Orig Paths
	if (orig_paths) {
		if (!c$conn?$orig_paths) { success = F; }
	} else {
		if (c$conn?$orig_paths) { success = F; }
	}

	# Orig Users
	if (orig_users) {
		if (!c$conn?$orig_users) { success = F; }
	} else {
		if (c$conn?$orig_users) { success = F; }
	}

	# Resp Hosts
	if (resp_hosts) {
		if (!c$conn?$resp_hosts || |c$conn$resp_hosts| != 2 || "host_resp_id_string1" !in c$conn$resp_hosts || "host_resp_id_string2" !in c$conn$resp_hosts) { success = F; }
	} else {
		if (c$conn?$resp_hosts) { success = F; }
	}

	# Resp Pids
	if (resp_pids) {
		if (!c$conn?$resp_pids || |c$conn$resp_pids| != 2 || +1337 !in c$conn$resp_pids || +1338 !in c$conn$resp_pids) { success = F; }
	} else {
		if (c$conn?$resp_pids) { success = F; }
	}

	# Resp Paths
	if (resp_paths) {
		if (!c$conn?$resp_paths) { success = F; }
	} else {
		if (c$conn?$resp_paths) { success = F; }
	}

	# Resp Users
	if (resp_users) {
		if (!c$conn?$resp_users) { success = F; }
	} else {
		if (c$conn?$resp_users) { success = F; }
	}

	return success;
}

event test_1_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_single_common(c, F, F, F, F, F, F, F, F);

	if (!success) {
		print("[FAIL] test_1 failed");
	}
}

event test_1() {
	print("Starting Test 1");

	# Create a connection
	local c: connection = _create_connection();

	# No state to extend connection
	# <nothing>
	
	# Try to extend connection
	print("- Trying to extend connection");
	event connection_state_remove(c);

	# Verify extension of connection
	schedule 1sec { test_1_verify(c) };
}

event test_2_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_single_common(c, T, F, F, F, F, F, F, F);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");

	if (!success) {
		print("[FAIL] test_2 failed");
	}
}

event test_2() {
	print("Starting Test 2");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");

	# Try to extend connection
	print("- Trying to extend connection");
	event connection_state_remove(c);

	# Verify extension of connection
	schedule 1sec { test_2_verify(c) };
}

event test_3_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_single_common(c, F, F, F, F, T, F, F, F);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	if (!success) {
		print("[FAIL] test_3 failed");
	}
}

event test_3() {
	print("Starting Test 3");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	# Try to extend connection
	print("- Trying to extend connection");
	event connection_state_remove(c);

	# Verify extension of connection
	schedule 1sec { test_3_verify(c) };
}


event test_4_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_single_common(c, T, F, F, F, T, F, F, F);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	if (!success) {
		print("[FAIL] test_4 failed");
	}
}

event test_4() {
	print("Starting Test 4");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	# Try to extend connection
	print("- Trying to extend connection");
	event connection_state_remove(c);

	# Verify extension of connection
	schedule 1sec { test_4_verify(c) };
}

event test_5_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_multiple_common(c, T, F, F, F, T, F, F, F);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string1", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string2", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string3", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string1", "interface_name", 2.2.2.2, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string2", "interface_name", 2.2.2.2, "mac_string");

	if (!success) {
		print("[FAIL] test_5 failed");
	}
}

event test_5() {
	print("Starting Test 5");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string1", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string2", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string3", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string1", "interface_name", 2.2.2.2, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string2", "interface_name", 2.2.2.2, "mac_string");

	# Try to extend connection
	print("- Trying to extend connection");
	event connection_state_remove(c);

	# Verify extension of connection
	schedule 1sec { test_5_verify(c) };
}

event test_6_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_single_common(c, T, T, T, T, T, T, T, T);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	event scheduled_remove_process_state("host_orig_id_string", +42, "orig_path_string1", "", +99, +66);
	event scheduled_remove_process_state("host_resp_id_string", +1337, "resp_path_string1", "", +11, +22);
	event socket_state_removed("host_orig_id_string", [$pid=+42, $family=+2, $connection=record($local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6)]);
	event socket_state_removed("host_resp_id_string", [$pid=+1337, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$remote_address=1.1.1.1,$remote_port=+8080,$protocol=+6)]);

	if (!success) {
		print("[FAIL] test_6 failed");
	}
}

event test_6() {
	print("Starting Test 6");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	# Process Connection state to extend connection
	schedule 0.0sec { initial_process_state([$host="host_orig_id_string", $utype=osquery::ADD], +42, "orig_path_string1", "", "", +99, +0, +66) };
	schedule 0.1sec { initial_process_state([$host="host_resp_id_string", $utype=osquery::ADD], +1337, "resp_path_string1", "", "", +11, +0, +22) };
	schedule 0.2sec { socket_state_added("host_orig_id_string", [$pid=+42, $family=+2, $connection=record($local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+6)]) };
	schedule 0.3sec { socket_state_added("host_resp_id_string", [$pid=+1337, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$remote_address=1.1.1.1,$remote_port=+8080,$protocol=+6)]) };

	# Try to extend connection
	print("- Trying to extend connection");
	schedule 0.5sec { connection_state_remove(c) };

	# Verify extension of connection
	schedule 1sec { test_6_verify(c) };
}

event test_7_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_single_common(c, T, T, T, T, T, T, T, T);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	event scheduled_remove_process_state("host_orig_id_string", +42, "orig_path_string1", "", +99, +66);
	event scheduled_remove_process_state("host_resp_id_string", +1337, "resp_path_string1", "", +11, +22);
	event socket_state_removed("host_orig_id_string", [$pid=+42, $family=+2, $connection=record($remote_address=2.2.2.2,$remote_port=+80,$protocol=+0)]);
	event socket_state_removed("host_resp_id_string", [$pid=+1337, $family=+2, $connection=record($local_address=0.0.0.0, $local_port=+80,$protocol=+0)]);

	if (!success) {
		print("[FAIL] test_7 failed");
	}
}

event test_7() {
	print("Starting Test 7");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string", "interface_name", 2.2.2.2, "mac_string");

	# Process Connection state to extend connection
	schedule 0.0sec { initial_process_state([$host="host_orig_id_string", $utype=osquery::ADD], +42, "orig_path_string1", "", "", +99, +0, +66) };
	schedule 0.1sec { initial_process_state([$host="host_resp_id_string", $utype=osquery::ADD], +1337, "resp_path_string1", "", "", +11, +0, +22) };
	schedule 0.2sec { socket_state_added("host_orig_id_string", [$pid=+42, $family=+2, $connection=record($remote_address=2.2.2.2,$remote_port=+80,$protocol=+0)]) };
	schedule 0.4sec { socket_state_added("host_resp_id_string", [$pid=+1337, $family=+2, $connection=record($local_address=0.0.0.0,$local_port=+80,$protocol=+0)]) };

	# Try to extend connection
	print("- Trying to extend connection");
	schedule 0.5sec { connection_state_remove(c) };

	# Verify extension of connection
	schedule 1sec { test_7_verify(c) };
}

event scheduled_terminate() {
	terminate();
}

event test_8_verify(c: connection) {
	print("- Verifying extension of connection");

	local success = _test_multiple_common(c, T, T, T, T, T, T, T, T);
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string1", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string2", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_orig_id_string3", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string1", "interface_name", 2.2.2.2, "mac_string");
	osquery::hosts::updateInterface(osquery::REMOVE, "host_resp_id_string2", "interface_name", 2.2.2.2, "mac_string");

	event socket_state_removed("host_orig_id_string1", [$pid=+42, $family=+2, $connection=record($local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+0)]);
	event socket_state_removed("host_orig_id_string1", [$pid=+43, $family=+2, $connection=record($local_address=1.1.1.1,$local_port=+80,$remote_address=2.2.2.2,$remote_port=+8080,$protocol=+6)]); # Wrong - swapped ports
	event socket_state_removed("host_resp_id_string1", [$pid=+1337, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$remote_address=1.1.1.1,$remote_port=+8080,$protocol=+6)]);
	event socket_state_removed("host_resp_id_string1", [$pid=+1337, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$protocol=+0)]);
	event socket_state_removed("host_resp_id_string1", [$pid=+1338, $family=+2, $connection=record($local_address=0.0.0.0,$local_port=+8080,$protocol=+0)]); # Wrong - swapped ports
	event socket_state_removed("host_resp_id_string1", [$pid=+1338, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$remote_address=1.1.1.1,$remote_port=+8080,$protocol=+6)]);
	event scheduled_remove_process_state("host_orig_id_string1", +42, "orig_path_string1", "", +99, +66);
	event scheduled_remove_process_state("host_orig_id_string1", +43, "orig_path_string2", "", +99, +66);
	event scheduled_remove_process_state("host_resp_id_string1", +1337, "resp_path_string1", "", +11, +22);
	event scheduled_remove_process_state("host_resp_id_string1", +1338, "resp_path_string2", "", +11, +22);

	if (!success) {
		print("[FAIL] test_8 failed");
	}
}

event test_8() {
	print("Starting Test 8");

	# Create a connection
	local c: connection = _create_connection();

	# Host state to extend connection
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string1", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string2", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_orig_id_string3", "interface_name", 1.1.1.1, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string1", "interface_name", 2.2.2.2, "mac_string");
	osquery::hosts::updateInterface(osquery::ADD, "host_resp_id_string2", "interface_name", 2.2.2.2, "mac_string");

	# Process Connection state to extend connection
	schedule 0.0sec { initial_process_state([$host="host_orig_id_string1", $utype=osquery::ADD], +42, "orig_path_string1", "", "", +99, +0, +66) };
	schedule 0.1sec { initial_process_state([$host="host_orig_id_string1", $utype=osquery::ADD], +43, "orig_path_string2", "", "", +99, +0, +66) };
	schedule 0.2sec { initial_process_state([$host="host_resp_id_string1", $utype=osquery::ADD], +1337, "resp_path_string1", "", "", +11, +0, +22) };
	schedule 0.3sec { initial_process_state([$host="host_resp_id_string1", $utype=osquery::ADD], +1338, "resp_path_string2", "", "", +11, +0, +22) };
	schedule 0.4sec { socket_state_added("host_orig_id_string1", [$pid=+42, $family=+2, $connection=record($local_address=1.1.1.1,$local_port=+8080,$remote_address=2.2.2.2,$remote_port=+80,$protocol=+0)]) };
	schedule 0.5sec { socket_state_added("host_orig_id_string1", [$pid=+43, $family=+2, $connection=record($local_address=1.1.1.1,$local_port=+80,$remote_address=2.2.2.2,$remote_port=+8080,$protocol=+6)]) }; # Wrong - swapped ports
	schedule 0.6sec { socket_state_added("host_resp_id_string1", [$pid=+1337, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$remote_address=1.1.1.1,$remote_port=+8080,$protocol=+6)]) };
	schedule 0.7sec { socket_state_added("host_resp_id_string1", [$pid=+1337, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$protocol=+0)]) };
	schedule 0.8sec { socket_state_added("host_resp_id_string1", [$pid=+1338, $family=+2, $connection=record($local_address=0.0.0.0,$local_port=+8080,$protocol=+0)]) }; # Wrong - swapped ports
	schedule 0.9sec { socket_state_added("host_resp_id_string1", [$pid=+1338, $family=+2, $connection=record($local_address=2.2.2.2,$local_port=+80,$remote_address=1.1.1.1,$remote_port=+8080,$protocol=+6)]) };

	# Try to extend connection
	print("- Trying to extend connection");
	schedule 1.0sec { connection_state_remove(c) };

	# Verify extension of connection
	schedule 1.2sec { test_8_verify(c) };
}

event bro_init() {

	print("Executing 8 correlation tests");

	# No state
	#
	schedule 0sec { test_1() };
	

	# Orig host state only
	#
	schedule 2sec { test_2() };

	# Resp host state only
	#
	schedule 4sec { test_3() };

	# Orig+Resp host state only
	#
	schedule 6sec { test_4() };

	# Multiple hosts state only
	#
	schedule 8sec { test_5() };


	# Full Orig+Resp Process Connection state
	#
	schedule 10sec { test_6() };

	# Partly Orig+Resp Process Connection state
	#
	schedule 12sec { test_7() };

	# Multiple Mixed Orig+Resp Process Connection state
	#
	schedule 14sec { test_8() };

	schedule 16sec { scheduled_terminate() };
}
