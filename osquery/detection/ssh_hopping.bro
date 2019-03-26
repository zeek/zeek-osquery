#! Logs the detection of ssh hopping.

@load base/protocols/ssh

module osquery::ssh_hopping;

# TODO: 

export {

    # SSH Source Candidate
    type SSH_Source: record {
        host_id: string;
        pid_out: int;
        user_out: int;
    };

    # SSH Destination Candidate
    type SSH_Destination: record {
        host_id: string;
        pid_in: int;
    };

    # SSH Connection
    type SSH_connection: record {
        sid: string;
        c: connection;
        src_candidates: table[string] of vector of SSH_Source;
        dst_candidates: table[string] of vector of SSH_Destination;
    };

    # SSH Hop
    type SSH_hop: record {
        host_id: string;
        c_in: connection;
        c_out: connection;
        pid_in: int;
        pid_out: int;
        user_out: int;
    };

}

# Set of ssh connections by connection id
global ssh_connections: table[string] of SSH_connection = table();
# Set of incoming ssh connections by host id
global ssh_conns_in: table[string] of set[string] = table();
# Set of outgoing ssh connections by host id
global ssh_conns_out: table[string] of set[string] = table();
# SSH Hop by session id and host id
global ssh_hops: table[string, string] of SSH_hop = table();

global attributed_ssh_source: event(c: connection, src: SSH_Source);
global attributed_ssh_destination: event(c: connection, src: SSH_Destination);

event ssh_auth_successful(c: connection, auth_method_none: bool) {
    local host_infos: vector of osquery::hosts::HostInfo;
    local host_id: string;
    local pid: int;
    local uid: int;
    local rev: bool;
    local x: vector of osquery::process_connections::ProcessConnection;
    local srcs: table[string] of vector of SSH_Source;
    local dsts: table[string] of vector of SSH_Destination;
    local h_idx: count;

    # Remember ssh connection
    local src_candidates: table[string] of vector of SSH_Source = table();
    local dst_candidates: table[string] of vector of SSH_Destination = table();
    ssh_connections[c$uid] = [$sid=c$uid, $c=c, $src_candidates=src_candidates, $dst_candidates=dst_candidates];

    # Check the origin of the connection
    # - Get list of hosts with this source IP
    host_infos = osquery::hosts::getHostInfosByAddress(c$id$orig_h);
    rev = F;
    for (h_idx in host_infos) {
        # - Find host connections to destination
        host_id = host_infos[h_idx]$host;
        x = osquery::process_connections::getProcessConnectionsByHostIDByConnection(host_id, c, rev);
        for (pc_idx in x) {
            # Remember process and user
            pid = x[pc_idx]$process_info$pid;
            uid = x[pc_idx]$process_info$uid;
            srcs = ssh_connections[c$uid]$src_candidates;
            if (host_id !in srcs) { srcs[host_id] = vector(); }
            srcs[host_id][|srcs[host_id]|] = [$host_id=host_id, $pid_out=pid, $user_out=uid];
            # Update
            if (host_id !in ssh_conns_out) { ssh_conns_out[host_id] = set(); }
            add ssh_conns_out[host_id][c$uid];
            #print "Found outgoing ssh";
            event osquery::ssh_hopping::attributed_ssh_source(c, srcs[host_id][|srcs[host_id]|-1]);
        }
    }

    # Check the destination of the connection
    # - Get list of hosts with this target IP
    host_infos = osquery::hosts::getHostInfosByAddress(c$id$resp_h);
    rev = T;
    for (h_idx in host_infos) {
        # - Find host connections from source
        host_id = host_infos[h_idx]$host;
        x = osquery::process_connections::getProcessConnectionsByHostIDByConnection(host_id, c, rev);
        for (pc_idx in x) {
            # Remember process
            pid = x[pc_idx]$process_info$pid;
            dsts = ssh_connections[c$uid]$dst_candidates;
            if (host_id !in dsts) { dsts[host_id] = vector(); }
            dsts[host_id][|dsts[host_id]|] = [$host_id=host_id, $pid_in=pid];
            # Update
            if (host_id !in ssh_conns_in) { ssh_conns_in[host_id] = set(); }
            add ssh_conns_in[host_id][c$uid];
            #print "Found incoming ssh";
            event osquery::ssh_hopping::attributed_ssh_destination(c, dsts[host_id][|dsts[host_id]|-1]);
        }
    }
}

event osquery::process_connections::process_connection_added(host_id: string, process_info: osquery::processes::ProcessInfo, socket_info: osquery::sockets::SocketInfo) {
    local ssh_conn: SSH_connection;
    local host_infos: vector of osquery::hosts::HostInfo;
    local conn: osquery::sockets::ConnectionTuple;
    local conn_rev: osquery::sockets::ConnectionTuple;
    local srcs: table[string] of vector of SSH_Source;
    local dsts: table[string] of vector of SSH_Destination;
    local pid: int;
    local uid: int;

    # Browse SSH Connections
    for (sid in ssh_connections) {
        ssh_conn = ssh_connections[sid];

        # Check the origin of the conection
        # - Get list of hosts with this source IP
    	conn = osquery::sockets::convert_conn_to_conntuple(ssh_conn$c, F);
        host_infos = osquery::hosts::getHostInfosByAddress(ssh_conn$c$id$orig_h);
        for (h_idx in host_infos) {
            if (host_infos[h_idx]$host != host_id) { next; }

            # - Find host connections to destination
            if (!osquery::sockets::matchConnectionTuplePattern(conn, socket_info$connection)) { next; }

            # Remember process and user
            pid = process_info$pid;
            uid = process_info$uid;
            srcs = ssh_conn$src_candidates;
            if (host_id !in srcs) { srcs[host_id] = vector(); }
            srcs[host_id][|srcs[host_id]|] = [$host_id=host_id, $pid_out=pid, $user_out=uid];
            # Update
            if (host_id !in ssh_conns_out) { ssh_conns_out[host_id] = set(); }
            add ssh_conns_out[host_id][sid];
            #print "Found outgoing ssh";
            event osquery::ssh_hopping::attributed_ssh_source(ssh_conn$c, srcs[host_id][|srcs[host_id]|-1]);
        }

        # Check the destination of the conection
        # - Get list of hosts with this target IP
    	conn_rev = osquery::sockets::convert_conn_to_conntuple(ssh_conn$c, T);
        host_infos = osquery::hosts::getHostInfosByAddress(ssh_conn$c$id$resp_h);
        for (h_idx in host_infos) {
            if (host_infos[h_idx]$host != host_id) { next; }

            # - Find host connections from source
            if (!osquery::sockets::matchConnectionTuplePattern(conn_rev, socket_info$connection)) { next; }

            # Remember process and user
            pid = process_info$pid;
            dsts = ssh_conn$dst_candidates;
            if (host_id !in dsts) { dsts[host_id] = vector(); }
            dsts[host_id][|dsts[host_id]|] = [$host_id=host_id, $pid_in=pid];
            # Update
            if (host_id !in ssh_conns_in) { ssh_conns_in[host_id] = set(); }
            add ssh_conns_in[host_id][sid];
            #print "Found incoming ssh";
            event osquery::ssh_hopping::attributed_ssh_destination(ssh_conn$c, dsts[host_id][|dsts[host_id]|-1]);
        }
    }
}


event ssh_parent_process(resultInfo: osquery::ResultInfo, sid: string, pid_out: int, user_out: int, pid: int, p_name: string, cmdline: string) {
    # Has parent process incoming ssh connection?
    local host_id: string = resultInfo$host;
    local c_out: connection = ssh_connections[sid]$c;
    local candidates: vector of SSH_Destination;

    for (id in ssh_conns_in[host_id]) {
        candidates = ssh_connections[id]$dst_candidates[host_id];
        for (idx in candidates) {
            if (candidates[idx]$pid_in != pid) { next; }
            local c_in: connection = ssh_connections[id]$c;
            
            # Most direct parent only
            if ([host_id, sid] in ssh_hops) { next; }
            ssh_hops[host_id, sid] = [$host_id=host_id, $c_in=c_in, $c_out=c_out, $pid_in=pid , $pid_out=pid_out, $user_out=user_out];
            print fmt("Found ssh hopping on host %s for user %s (pids %s -> %s)", host_id, user_out, pid, pid_out);
        }
    }
}

event osquery::ssh_hopping::attributed_ssh_source(c: connection, src: SSH_Source) {
    #print "SSH Source", src;

    # Check for incoming ssh sessions to this host
    local host_id: string = src$host_id;
    if (host_id !in ssh_conns_in) { return; }

    # Request Parent processes
    local query_string = fmt("WITH RECURSIVE parents(pid) AS (SELECT parent FROM processes WHERE pid=%s UNION ALL SELECT parent FROM processes JOIN parents USING(pid)) SELECT '%s', %s, %s, p.pid, p.name, p.cmdline FROM parents, processes p WHERE parents.pid=p.pid", src$pid_out, c$uid, src$pid_out, src$user_out);

    local query = [$ev=ssh_parent_process, $query=query_string];
    osquery::execute(query, host_id);
}

event osquery::ssh_hopping::attributed_ssh_destination(c: connection, dst: SSH_Destination) {
    #print "SSH Destination", dst;
}

event connection_state_remove(c: connection) {
    if (c$uid !in ssh_connections) { return; }

    # TODO: Check source hosts
    # TODO: Check destination hosts

    #delete ssh_connections[c$uid];
}

