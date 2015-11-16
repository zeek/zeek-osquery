
module osquery;

export {
	## The osquery logging stream identifier.
	redef enum Log::ID += { LOG };

	## Type defining the type of osquery change we are interested in.
	type UpdateType: enum {
		ADD,	##< Report new elements.
		REMOVE,	##< Report removed element.
		BOTH	##< Report both new and removed elements.
	};

	## Type defining a single event to subscribe to.
	type Event: record {
		## The Bro event to execute when receiving updates.
		ev: any &optional;
		## The osquery SQL query selecting the activity to subscribe to.
		query: string;
		## The type of update to report.
		utype: UpdateType &default=BOTH;
		## If true, report all current elements once at connecting to client.
		init_dump: bool &default=F;
	};

	## Subscribe to an event from clients. Whenever an osquery client
	## connects to us, we'll subscribe to all matching activity from it.
	##
	## ev: The event to subscribe to.
	##
	## net: IP space this subscription applies to. If a client outside of
	## this range connects, the subscription won't be applied to it.
	global subscribe: function(ev: Event, net: subnet &default=0.0.0.0/0);

	## Unsubscribe to an event from clients. This will get sent to all clients
        ## that are currently connected and would match a similar subscribe
        ## call.
	##
	## ev: The event to unsubscribe from.
	##
	## net: IP space this unsubscription applies to.
        global unsubscribe: function(ev: Event, net: subnet &default=0.0.0.0/0);

	## Subscribe to multiple events. Whenever an osquery client connects to us, we'll
	## subscribe to all matching activity from it.
	##
	## ev: The events to subscribe to.
	##
	## net: IP space this subscription applies to. If a client outside of this range
	## connects, the subscriptions won't be applied to it.
	global subscribe_multiple: function(evs: vector of Event, net: subnet &default=0.0.0.0/0);

	## Unsubscribe from multiple events. This will get sent to all clients
        ## that are currently connected and would match a similar subscribe
        ## call.
	##
	## ev: The events to unsubscribe from.
	##
	## net: IP space this unsubscription applies to.
        global unsubscribe_multiple: function(evs: vector of Event, net: subnet &default=0.0.0.0/0);

        ## Associate a group with a host. This will tell the host to post to a
        ## corresponding group topic. The local Bro will automatically subscribe to that,
        ## but other receivers potentially talking to the same host will ignore the
        ## activity. 
	global set_host_group: function(peer_name: string, group: string);

	## Event sent by clients to signal that they are now going to start
	## events per their subscriptions.
	##
	## peer_name: The name of the endsystem.
	##
	## TODO: Right now the peer_name must be the IP address. Relax that
	## constraint (and probably switch to hostname) once Broker can supply
	## the IP directly.
	global host_ready: event(peer_name: string);

	# Event sent by clients to report an error.
	#
	# TODO: Add peer_name.
	global host_error: event(peer_name: string, msg: string);

	# Event sent by clients to report a warning.
	#
	# TODO: Add peer_name.
	global host_warning: event(peer_name: string, msg: string);

	# Event sent by clients to report an informational log message.
	#
	# TODO: Add peer_name.
	global host_log: event(peer_name: string, msg: string);

	## A record type containing the column fields of the osquery log.
	type Info: record {
		## The network time at which a osquery activity occurred.
		ts:                  time   &log;
		## ``bro`` or ``osquery`` depending on whether Bro generated the
		## message locally, or an osquery host sent it.
		source: string &log;
		## The peer name (if any) with which a communication event is
		## concerned.
		peer:                string &log &optional;
		## The severity of the communication event message.
		level:               string &log &optional;
		## The main log message.
		message:             string &log;
	};


}

# Sent by us to the client for subscribing to an event.
global host_subscribe: event(ev: string, query: string, utype: string, initdump: bool);

# Sent by us to the client to signal end of the subscription list.
global host_subscribe_end: event();

# Sent by us to the client for unsubscribing from an event.
global host_unsubscribe: event(ev: string, query: string, utype: string, initdump: bool);

# Sent by us to the client to signal end of the unsubscription list.
global host_unsubscribe_end: event();

# Sent by us to set the topic for the client to publish its events with.
global host_set_topic: event(topic: string);

# Internal record for tracking a subscription.
type Subscription: record {
	net: subnet;
	ev: Event;
};

global hosts: set[addr, string]; # All currently connected and "ready" osquery clients.
global subscriptions: vector of Subscription;
global groups: set[string];
global host_groups: table[string] of string &default="default";

function log_host(level: string, peer: string, msg: string)
	{
	Log::write(osquery::LOG, [$ts = network_time(),
				  $level = level,
				  $source = "osquery",
				  $peer = peer,
				  $message = msg]);
	}

function log_peer(level: string, peer: string, msg: string)
	{
	Log::write(osquery::LOG, [$ts = network_time(),
				  $level = level,
				  $source = "bro",
				  $peer = peer,
				  $message = msg]);
	}

function log_local(level: string, msg: string)
	{
	Log::write(osquery::LOG, [$ts = network_time(),
				  $level = level,
				  $source = "bro",
				  $peer = "localhost",
				  $message = msg]);
	}


function send_subscribe_or_unsubscribe(peer_name: string, ev: Event, subscribe: bool, add_end_event: bool)
	{
	local init_dump = ev$init_dump;
	local ev_name = split_string(fmt("%s", ev$ev), /\n/)[0];
	local host_topic = fmt("/bro/osquery/host/%s", peer_name);
	
	log_peer("info", peer_name, fmt("%s event %s() with '%s'",
					subscribe ? "subscribing to" : "unsubscribing from",
					ev_name, ev$query));

	local update_type = "BOTH";

	if ( ev$utype == ADD )
		update_type = "ADD";

	if ( ev$utype == REMOVE )
		update_type = "REMOVED";

	local ev_args1 = subscribe ? BrokerComm::event_args(host_subscribe, ev_name, ev$query, update_type, init_dump)
	                           : BrokerComm::event_args(host_unsubscribe, ev_name, ev$query, update_type, init_dump);

	BrokerComm::event(host_topic, ev_args1);
	
	}

function same_event(ev1: Event, ev2: Event) : bool
	{
	return fmt("%s", ev1$ev) == fmt("%s", ev2$ev) && ev1$query == ev2$query &&
	       ev1$utype == ev2$utype && ev1$init_dump == ev2$init_dump;
	}

function subscribe(ev: Event, net: subnet)
	{
	subscriptions[|subscriptions|] = [$net=net, $ev=ev];

	# Subscribe from current clients.
        for ( [ip, peer_name] in hosts ) 
		{
		if ( ip !in net )
			next;
		
		send_subscribe_or_unsubscribe(peer_name, ev, T, F);
		}
	}

function unsubscribe(ev: Event, net: subnet)
	{
	for ( i in subscriptions )
		{
		if ( same_event(subscriptions[i]$ev, ev) )
			# Don't have a delete for vector, so set it to no-op
                        # by leaving the event empty.
                        subscriptions[i]$ev = [$query=""];
		}

	# Unsubscribe from current clients.
        for ( [ip, peer_name] in hosts ) 
		{
		if ( ip !in net )
			next;
		
		send_subscribe_or_unsubscribe(peer_name, ev, F, T);
		}
	}

function subscribe_multiple(evs: vector of Event, net: subnet)
	{
	for ( i in evs )
		subscribe(evs[i], net);
	}

function unsubscribe_multiple(evs: vector of Event, net: subnet)
	{
	for ( i in evs )
		unsubscribe(evs[i], net);
	}

function send_subscriptions(ip: addr, peer_name: string)
	{
	for ( i in subscriptions )
		{
		local s = subscriptions[i];

		if ( ! s?$ev )
			next;

		if ( ip !in s$net )
			next;

		send_subscribe_or_unsubscribe(peer_name, s$ev, T, F);
		}
	}

function set_host_group(peer_name: string, group: string)
	{
	if ( group !in groups )
		{
		local topic = fmt("/bro/osquery/group/%s", group);
		log_local("info", fmt("subscribing to topic %s", topic));
		BrokerComm::subscribe_to_events(topic);
		add groups[group];
		}

	host_groups[peer_name] = group;
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osquery"]);

	# TODO: Not sure this should stay here. We still need to figure out a way
	# for different applications to use Broker jointly without messing up
	# whatever another one is doing.
	BrokerComm::enable();

	local topic = "/bro/osquery/group/default";
	log_local("info", fmt("subscribing to topic %s", topic));
	BrokerComm::subscribe_to_events(topic);

	BrokerComm::listen(9999/tcp, "0.0.0.0");
	}

event host_log(peer_name: string, msg: string)
	{
	log_host("info", peer_name, msg);
	}

event host_warning(peer_name: string, msg: string)
	{
	log_host("warning", peer_name, msg);
	}

event host_error(peer_name: string, msg: string)
	{
	log_host("error", peer_name, msg);
	}

event host_ready(peer_name: string)
	{
	log_peer("info", peer_name, "host ready");

	local ip = to_addr(peer_name);
	send_subscriptions(ip, peer_name);

	add hosts[ip, peer_name];
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	log_peer("info", peer_name, "incoming connection established");

	local ip = to_addr(peer_name);

	local ours = F;

	for ( i in subscriptions )
		{
		local s = subscriptions[i];

		if ( ! s?$ev )
			next;
		
		if ( ip in s$net )
			{
			ours = T;
			break;
			}
		}

	if ( ! ours )
		return;

	local group = host_groups[peer_name];

	local host_topic = fmt("/bro/osquery/host/%s", peer_name);
	local group_topic = fmt("/bro/osquery/group/%s", group);

	log_peer("info", peer_name, fmt("setting topic %s", group_topic));
	local ev_args = BrokerComm::event_args(host_set_topic, group_topic);
	BrokerComm::event(host_topic, ev_args);
	}

event BrokerComm::connection_incoming_connection_broken(peer_name: string)
	{
	local ip = to_addr(peer_name);
	delete hosts[ip, peer_name];
	}
