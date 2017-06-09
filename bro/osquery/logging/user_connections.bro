#! Logs user connection activity.

module osquery::user_connection;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        t: time &log;
        host: string &log;
        local_address: addr &log;
        local_port: int &log;
        remote_address: addr &log;
        remote_port: int &log;
        protocol: int &log;
        pid: int &log;
        path: string &log;
        cmdline: string &log;
        uid: int &log;
        username: string &log;
    };

    const cache_size: int = 1000 &redef;
}

# Add a field to the connection log record.
redef record Conn::Info += {
    # Name of the user on the originating system
    orig_u: string &optional &log;
};

# Maps connection to user
global connection_cache: table[addr, port, addr, port] of string;

function convertPort(p: int, n: int): port
{
    local n_str = fmt("%d", n);

    if (p==1)
        return to_port(n_str+"/icmp");
    if (p==6)
        return to_port(n_str+"/tcp");
    if (p==17)
        return to_port(n_str+"/udp");
}

function addNewUserConnection(local_address: string, local_port: int, remote_address: string, remote_port: int, protocol: int, username: string): bool
{
    local valid_protocols: set[int] = set(1, 6, 17);
    if (protocol in valid_protocols)
    {
        # Add a maximum cache size. How to chose 'old' entries that should be replaced?
        connection_cache[to_addr(local_address), convertPort(protocol, local_port), to_addr(remote_address), convertPort(protocol, remote_port)] = username;
        return T;
    }
    return F;
}

function extendConnectionInfo(c: connection): bool
{
    # Checks for connections initiated by the host only
    if ([c$conn$id$orig_h, c$conn$id$orig_p, c$conn$id$resp_h, c$conn$id$resp_p] in connection_cache)
    {
        c$conn$orig_u = connection_cache[c$conn$id$orig_h, c$conn$id$orig_p, c$conn$id$resp_h, c$conn$id$resp_p];
        delete connection_cache[c$conn$id$orig_h, c$conn$id$orig_p, c$conn$id$resp_h, c$conn$id$resp_p];
        return T;
    }
    return F;
}

event connection_state_remove(c: connection)
{
    local ex_succ = extendConnectionInfo(c);
    if (ex_succ)
        print(fmt("User '%s' found for connection with id %s (%s:%d -> %s:%d)", c$conn$orig_u, c$conn$uid, c$conn$id$orig_h,c$conn$id$orig_p,c$conn$id$resp_h,c$conn$id$resp_p));
}

event host_user_connection(resultInfo: osquery::ResultInfo,
            local_address: string, local_port: int, remote_address: string, remote_port: int, protocol: int,
            pid: int, path: string, cmdline: string, uid: int, username:string)
{
    if ( resultInfo$utype != osquery::ADD )
        return;

    local info: Info = [
        $t=network_time(),
        $host=resultInfo$host,
        $local_address=to_addr(local_address),
        $local_port=local_port,
        $remote_address=to_addr(remote_address),
        $remote_port=remote_port,
        $protocol=protocol,
        $pid=pid,
        $path=path,
        $cmdline=cmdline,
        $uid=uid,
        $username=username
    ];

    Log::write(LOG, info);

    local add_succ = addNewUserConnection(local_address, local_port, remote_address, remote_port, protocol, username);
    if (! add_succ)
        print(fmt("Invalid protocol with number '%d'", protocol));
}

event bro_init()
{
    Log::create_stream(LOG, [$columns=Info, $path="osq-user_connections"]);

    Broker::enable();

    local ev = [$ev=host_user_connection,$query="SELECT pos.local_address, pos.local_port, pos.remote_address, pos.remote_port, pos.protocol, pos.pid, p.path, p.cmdline, p.uid, u.username FROM process_open_sockets as pos LEFT JOIN processes as p ON pos.pid = p.pid LEFT JOIN users as u ON p.uid = u.uid WHERE local_address!='' AND remote_address!=''"];
    osquery::subscribe(ev);
}

