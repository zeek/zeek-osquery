#! Logs cpuid activity.

module osqueryCpuid;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;  
		mode: string &log;
		feature: string &log;
		value: string &log;
		output_register: string &log;
		output_bit: int &log;
		input_eax: string &log;
	};
}

event cpuid(host: string, mode: string, utype: string,
		feature: string, value: string, output_register: string,
		output_bit: int, input_eax: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $feature = feature,
			    $value = value,
			    $output_register = output_register,
			    $output_bit = output_bit,
				$input_eax = input_eax
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-cpuid"]);
	
	local ev = [$ev=cpuid,
		    $query="SELECT feature,value,output_register,output_bit,input_eax FROM cpuid"];
	osquery::subscribe(ev);
	}
