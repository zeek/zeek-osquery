
redef exit_only_after_terminate = T;

@load osquery

event listening_ports(host: string, user: string, ev_type: string,
		      pid: int, prt: int, protocol: int)
	{
	print "|| listening_ports", host, user, ev_type, pid, prt, protocol;
	}

event change(t: count)
	{
	local ev = [$ev=listening_ports, $query="SELECT pid,port,protocol FROM listening_ports"];
	
	if ( t == 1 ) 
		{
		print "subscribing and waiting 10secs";
		osquery::subscribe(ev);
		schedule 10secs { change(2) };
		}
	
	if ( t == 2 ) 
		{
		print "unsubscribing";
		osquery::unsubscribe(ev);
		}
	}


event bro_init()
	{
	print "waiting 10secs";
	schedule 10secs { change(1) };
	}


