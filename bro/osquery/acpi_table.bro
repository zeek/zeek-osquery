#! Logs acpi_tables activity.

module osqueryAcpiTables;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		name: string &log;
		size: int &log;
		md5: string &log;
	};
}

event acpi_tables(host: string, mode: string, utype: string,
		name: string, size: int, md5: string)
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
			    $md5 = md5
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-acpi_tables"]);
	
	local ev = [$ev=acpi_tables,
		    $query="SELECT name,size,md5 FROM acpi_tables"];
osquery::subscribe(ev, 0.0.0.0/0);
	}
