#! Logs pci_devices activity.

module osqueryPciDevices;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		mode: string &log;
		pci_slot: string &log;
		pci_class: string &log;
		driver: string &log;
		vendor: string &log;
		vendor_id: string &log;
		model: string &log;
		model_id: string &log;
	};
}

event pci_devices(host: string, mode: string, utype: string,
		pci_slot: string, pci_class: string, driver: string,
		vendor: string, vendor_id: string, model: string,
		model_id: string)
	{
	if ( utype != "ADDED" )
		# Just want to log socket existance.
		return;
	
	local info: Info = [
			    $t=network_time(),
			    $host=host,
				$mode=mode,
			    $pci_slot = pci_slot,
			    $pci_class = pci_class,
			    $driver = driver,
				$vendor = vendor,
				$vendor_id = vendor_id,
				$model = model,
				$model_id = model_id
			   ];
	
	Log::write(LOG, info);
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-pci-devices"]);
	
	local ev = [$ev=pci_devices,
		    $query="SELECT pci_slot,pci_class,driver,vendor,vendor_id,model,model_id FROM pci_devices"];
	osquery::subscribe(ev);
	}
