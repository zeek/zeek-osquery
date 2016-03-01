#! Logs hardware_events activity.

module osqueryHardwareEvents;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;  
		mode: string &log;
		action: string &log;
		path: string &log;
		typ: string &log;
		driver: string &log;
		vendor: string &log;
		vendor_id: string &log;
		model: string &log;
		model_id: string &log;
	};
}

event hardware_events(host: string, mode: string, utype: string,
		action: string, path: string, typ: string,
		driver: string, vendor: string, vendor_id: string,
		model: string, model_id: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $action = action,
			    $path = path,
			    $typ = typ,
				$driver = driver,
				$vendor = vendor,
				$vendor_id = vendor_id,
				$model = model,
				$model_id = model_id
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-hardware-events"]);
	
	local ev = [$ev=hardware_events,
		    $query="SELECT action,path,type,driver,vendor,vendor_id,model,model_id FROM hardware_events"];
	osquery::subscribe(ev);
	}
