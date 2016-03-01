#! Logs socket activity.

module osqueryKernelIntegrity;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		addr_modified: int &log;
		txt_hash: string &log;
		};
}

event kernel_integrity(host: string, mode: string, utype: string, 
		addr_modified: int, txt_hash: string)
	{
	
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $addr_modified = addr_modified,
				$txt_hash = txt_hash
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-kernel_integrity"]);
	
	local ev = [$ev=kernel_integrity,
		    $query="SELECT sycall_addr_modified, text_segment_hash FROM kernel_integrity",
			$init_dump = T];
osquery::subscribe(ev, 0.0.0.0/0);
	}
