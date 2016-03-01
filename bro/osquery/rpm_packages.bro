#! Logs rpm-packages activity.

module osqueryFirefoxAddons;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		name: string &log;
		version: string &log;
		release: string &log;
		source: string &log;
		sha1: string &log;
		arch: string &log;
	};
}

event rpm_packages(host: string, mode: string, utype: string,
		name: string, version: string, release: string, source: string,
		sha1: string, arch: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $name = name,
			    $version = version,
				$release = release,
				$source = source,
				$sha1 = sha1,
				$arch = arch
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-rpm-packages"]);
	
	local ev = [$ev=rpm_packages,
		    $query="SELECT name,version,release,source,sha1,arch FROM rpm_packages"];
	osquery::subscribe(ev);
	}
