#! Logs smbios_tables activity.

module osquerySmbiosTables;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		number: int &log;
		typ: int &log;
		description: string &log;
		handle: int &log;
		size: int &log;
		md5: string &log;
	};
}

event smbios_tables(host: string, mode: string, utype: string,
		number: int, typ: int, description: string,
		handle: int, size: int, md5: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $number = number,
			    $typ = typ,
			    $description = description,
				$handle = handle,
				$size = size,
				$md5 = md5
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-smbios-tables"]);
	
	local ev = [$ev=smbios_tables,
		    $query="SELECT number,type,description,handle,size,md5 FROM smbios_tables"];
	osquery::subscribe(ev);
	}
