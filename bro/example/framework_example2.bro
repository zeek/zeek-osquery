@load base/frameworks/broker
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http

redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro";

module osquery::ExampleFramework;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                username: string &log;
                name: string &log;
		agent: string &log;
        };
}

global http_agent: string;

event host_browser(client_id: string, utype: string,
                name: string, username: string)
        {
	#print fmt("User %s is running %s as browser", username, name);

	local info: Info = [
                $t=network_time(),
                $host=client_id,
		$username=username,
		$name=name,
		$agent=http_agent
        ];

        Log::write(LOG, info);
        }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	local ip = addr_to_uri(c$id$orig_h);
	local p = port_to_count(c$id$orig_p);
	#print fmt("http_request seen from %s:%d", ip, p);

	local query = fmt("SELECT p.name, u.username FROM process_open_sockets s, processes p, users u WHERE s.local_port=%d AND s.pid=p.pid AND p.uid=u.uid",p);
	osquery::execute([$ev=host_browser,$query=query]);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) 
	{
	if (name == "USER-AGENT") 
		{
		#print fmt("http_header: name=%s, value=%s", name, value);
		http_agent = value;
		}
	}


event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-example-framework2"]);

	Broker::enable();
        }
