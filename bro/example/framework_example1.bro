@load base/frameworks/broker

redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro";

module osqueryExampleFramework;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                utype: string &log;
                unix_time: int &log;
        };
}

global c: int;

event host_osVersion(client_id: string, utype: string,
                major: int, name: string)
        {
                print fmt("The host '%s' is running '%s' major version '%d'", client_id, name, major);
        }

event host_unixTime(client_id: string, utype: string,
                unix_time: int)
        {
        if ( utype != "ADDED" )
                # Just want to log socket existance.
                return;
	print fmt("Received unix_time %d", unix_time);
        local info: Info = [
                      $t=network_time(),
                      $host=client_id,
                      $utype=utype,
                      $unix_time = unix_time
        ];

        Log::write(LOG, info);

	local topics: vector of string = {osquery::HostBroadcastTopic};
	if ( c == 2 ) 
		{
		# Let's execute a one-time query
		local ev_onetime = [$ev=host_osVersion,$query="SELECT name, major FROM os_version;"];
		osquery::execute_query(ev_onetime, topics);
		}

	if (c == 4 ) 
		{
		# We dont want to receive any more unixTimes
		local ev_unsub = [$ev=host_unixTime,$query="SELECT unix_time FROM time"];
		osquery::unsubscribe(ev_unsub, topics);
		}

	c += 1;
        }

event bro_init()
        {
	c = 0;

        Log::create_stream(LOG, [$columns=Info, $path="osq-example-framework"]);

        local ev = [$ev=host_unixTime,$query="SELECT unix_time FROM time"];
	local topics: vector of string = {osquery::HostBroadcastTopic};
        osquery::subscribe(ev, topics);
        }
