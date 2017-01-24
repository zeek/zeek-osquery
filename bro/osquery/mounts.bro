#! Logs mounts activity.

module osquery::mounts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		device: string &log;
		device_alias: string &log;
		path: string &log;
		typ: string &log;
		blocks_size: int &log;
		blocks_available: int &log;
		flags: string &log;
	};
}

event mounts(host: string, utype: string,
		device: string, device_alias: string, path: string, typ: string,
		blocks_size: int, block_available: int, flags: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			                $t=network_time(),
			                $host=host,
                      $device = device,
                      $device_alias = device_alias,
                      $path = path,
                      $typ = typ,
                      $blocks_size = blocks_size,
                      $blocks_available = blocks_available,
                      $flags = flags
			               ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-mounts"]);
	
	local ev = [$ev=mounts,$query="SELECT device,device_alias,path,type,blocks_size,blocks_available,flags FROM mounts"];
	osquery::subscribe(ev);
	}
