#! Logs kernel_modules activity.

module osqueryKernelModules;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		name: string &log;
		size: string &log;
		used_by: string &log;
		status: string &log;
		address: string &log;
	};
}

event kernel_modules(host: string, mode: string, utype: string,
		name: string, size: string, used_by: string,
		status: string, address: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $name = name,
			    $size = size,
			    $used_by = used_by,
				$status = status,
				$address = address
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-kernel-modules"]);
	
	local ev = [$ev=kernel_modules,
		    $query="SELECT name,size,used_by,status,adderss FROM kernel_modules"];
	osquery::subscribe(ev);
	}
