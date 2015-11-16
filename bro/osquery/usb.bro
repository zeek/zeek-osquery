#! Logs socket activity.

module osqueryUsbDevices;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		vendor: string &log;
		model: string &log;
		serial: string &log;
		removable: int &log;
	};
}

event usb_devices(host: string, utype: string,
		vendor: string, model: string,
		serial: string, removable: int)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
			    $vendor = vendor,
				$model= model,
				$serial = serial,
			    $removable= removable
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-usbdevices"]);
	
	local ev = [$ev=usb_devices,
		    $query="SELECT vendor,model, serial, removable FROM usb_devices"];
	osquery::subscribe(ev);
	}

