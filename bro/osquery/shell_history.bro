#! Logs socket activity.

module osqueryShellHistory;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		username: string &log;
		command: string &log;
		history_file: string &log;
		};
}

event shell_history(host: string, mode: string, utype: string, 
		username: string, command: string,
		history_file: string)
	{
	
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $username = username,
				$command = command,
				$history_file = history_file
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-shellhistory"]);
	
	local ev = [$ev=shell_history,
		    $query="SELECT username, command, history_file FROM shell_history"];
osquery::subscribe(ev, 0.0.0.0/0);
	}
