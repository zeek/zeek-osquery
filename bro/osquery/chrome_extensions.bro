#! Logs chrome_extensions activity.

module osqueryChromeExtensions;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		uid: int &log;
		name: string &log;
		identifier: string &log;
		version: string &log;
		description: string &log;
		locale: string &log;
		update_url: string &log;
		author: string &log;
		path: string &log;
	};
}

event chrome_extensions(host: string, mode: string, utype: string,
		uid: int, name: string, identifier: string,
		version: string, description: string, locale: string,
		update_url: string, author: string, path: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $uid = uid,
			    $name = name,
			    $identifier = identifier,
				$version = version,
				$description = description,
				$locale = locale,
				$update_url = update_url,
				$author = author,
				$path = path
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-chrome-extensions"]);
	
	local ev = [$ev=chrome_extensions,
		    $query="SELECT uid, name,identifier,version,description,locale,update_url,author,path FROM chrome_extensions"];
	osquery::subscribe(ev);
	}
