#! Logs disk-encryption activity.

module osqueryDiskEncryption;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		name: string &log;
		uuid: string &log;
		encrypted: int &log;
		typ: string &log;
	};
}

event disk_encryption(host: string, mode: string, utype: string,
		name: string, uuid: string, encrypted: int, typ: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $name = name,
			    $uuid = uuid,
				$encrypted = encrypted,
				$typ = typ
			];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-disk-encryption"]);
	
	local ev = [$ev=disk_encryption,
		    $query="SELECT name,uuid,encryption,type FROM disk_encryption"];
	osquery::subscribe(ev);
	}
