
redef exit_only_after_terminate = T;

@load ./osquery

event listening_ports(host: string, user: string, ev_type: string,
		      pid: int, prt: int, protocol: int)
	{
	print "|| listening_ports", host, user, ev_type, pid, prt, protocol;
	}

event bro_init()
	{
	local ev = [$ev=listening_ports, $query="SELECT pid,port,protocol FROM listening_ports"];
	osquery::subscribe(ev);
	}

