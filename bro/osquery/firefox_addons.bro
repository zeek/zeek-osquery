#! Logs socket activity.

module osqueryFirefox;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		name: string &log;
		identifier: string &log;
		typ: string &log;
		description: string &log;
		source_url: string &log;
		active: int &log;
		path: string &log;
		};
}

event firefox_addons(host: string, mode: string, utype: string, 
		name: string, identifier: string, typ: string,
		description: string, source_url: string,
		active: int, path: string)
	{
	
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $name = name,
				$identifier = identifier,
				$typ = typ,
				$description = description,
				$source_url = source_url,
				$active = active,
				$path = path
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-firefox"]);
	
	local ev = [$ev=firefox_addons,
		    $query="SELECT name, identifier, type, description, source_url, active, path FROM firefox_addons"];
osquery::subscribe(ev, 0.0.0.0/0);
	}
