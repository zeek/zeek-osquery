#! Logs kernel_info activity.

module osqueryKernelInfo;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		version: string &log;
		arguments: string &log;
		path: string &log;
		device: string &log;
	};
}

event kernel_info(host: string, mode: string, utype: string,
		version: string, arguments: string, path: string,
		device: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $version = version,
			    $arguments = arguments,
			    $path = path,
				$device = device
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-kernel-modules"]);
	
	local ev = [$ev=kernel_info,
		    $query="SELECT version,arguments,path,device FROM kernel_info"];
	osquery::subscribe(ev);
	}
