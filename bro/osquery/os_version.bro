#! Logs os_version activity.

module osqueryFirefoxAddons;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		name: string &log;
		major: int &log;
		minor: int &log;
		patch: int &log;
		build: string &log;
	};
}

event os_version(host: string, mode: string, utype: string,
		name: string, major: int, minor: int, patch: int,
		build: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $name = name,
			    $major = major,
				$minor = minor,
				$patch = patch,
				$build = build
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-os-version"]);
	
	local ev = [$ev=os_version,
		    $query="SELECT name,major,minor,patch,build FROM os_version"];
	osquery::subscribe(ev);
	}
