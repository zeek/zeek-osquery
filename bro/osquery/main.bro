@load base/frameworks/broker

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro";

module osquery;

export {
	# Topic prefix used for all topics in osquery communication
	const TopicPrefix: string = "/bro/osquery" &redef;
	# Topic to address all hosts (default to send query requests)
	const HostBroadcastTopic: string = fmt("%s/all",TopicPrefix) &redef;
	# Undividual channel of this bro instance (default to receive query results)
	const BroID_Topic: string = fmt("%s/uid/%s",TopicPrefix,"BroMaster") &redef;

###
### Logging
###

	## The osquery logging stream identifier.
	redef enum Log::ID += { LOG };

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


###############################
#                             #
# Main Framework Interface    #
#                             #
###############################

###
### Structures
###

	## Type defining 

	## Type defining the type of osquery change we are interested in.
	type UpdateType: enum {
		ADD,	##< Report new elements.
		REMOVE,	##< Report removed element.
		BOTH,	##< Report both new and removed elements.
		SNAPSHOT##< Report the current status at query time.
	};

	## Type defining a single event to subscribe to.
	type Event: record {
		## The osquery SQL query selecting the activity to subscribe to.
		query: string;
		## The type of update to report.
		utype: UpdateType &default=BOTH;
		## The interval of the query
		inter: count &optional;
		## The Broker topic THEY send the query result to
		resT: string &default=BroID_Topic;
		## The Bro event to execute when receiving updates.
		ev: any &optional;
	};


###
### Functions
###

	## Subscribe to an event from clients. Whenever an osquery client
	## connects to us, we'll subscribe to all matching activity from it.
	##
	## ev: The event to subscribe to.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
	global subscribe: function(ev: Event, topics: vector of string);

	## Unsubscribe to an event from clients. This will get sent to all clients
        ## that are currently connected and would match a similar subscribe
        ## call.
	##
	## ev: The event to unsubscribe from.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
        global unsubscribe: function(ev: Event, topics: vector of string);

	## Subscribe to multiple events. Whenever an osquery client connects to us, we'll
	## subscribe to all matching activity from it.
	##
	## ev: The events to subscribe to.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
	global subscribe_multiple: function(evs: vector of Event, topics: vector of string);

	## Unsubscribe from multiple events. This will get sent to all clients
        ## that are currently connected and would match a similar subscribe
        ## call.
	##
	## ev: The events to unsubscribe from.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
        global unsubscribe_multiple: function(evs: vector of Event, topics: vector of string);

	## Send a one-time query to all current clients in a specific group.
	##
	## ev: The event to execute.
        ##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
	global execute_query: function(ev: Event, topics: vector of string);

        ## Associate a group with a host. This will tell the host to post to a
        ## corresponding group topic. The local Bro will automatically subscribe to that,
        ## but other receivers potentially talking to the same host will ignore the
        ## activity. 
#	global set_host_group: function(peer_name: string, group: string);

###
### Events from Clients
###

	## Event that signals the connection of a new osquery host
	##
	## client_id: An id that uniquely identifies an osquery host 
        ## addr_list: A list of IP addresses of that osquery host
#        global host_new: event(client_id: string, group_list: vector of string, addr_list: vector of addr);

	# Event sent by clients to report an error.
	#
	# TODO: Add peer_name.
	global host_error: event(client_id: string, msg: string);

	# Event sent by clients to report a warning.
	#
	# TODO: Add peer_name.
	global host_warning: event(client_id: string, msg: string);

	# Event sent by clients to report an informational log message.
	#
	# TODO: Add peer_name.
	global host_log: event(client_id: string, msg: string);

}

###
### Events to Clients
###

# Sent by us to the client for subscribing to an event.
global host_subscribe: event(ev: string, query: string, resT: string, utype: string, inter: count);

# Sent by us to the client for unsubscribing from an event.
global host_unsubscribe: event(ev: string, query: string, resT: string, utype: string, inter: count);

# Sent by us to the client for one-time query execution
global host_query: event(ev: string, query: string, resT: string, utype: string);

# Sent by us to set the topic for the client to publish its events with.
#global host_set_topic: event(topic: string);

###
### Internal Structures
###

# Internal record for tracking a subscription.
type Subscription: record {
	topics: vector of string;
	ev: Event;
};

# Internal vector of subscriptions
global subscriptions: vector of Subscription;

# Internal set for tracing client ids
global hosts: set[string];

# Internal table for tracking client (ids) and their respective addresses
global host_addresses: table[string] of vector of addr;

global groups: set[string] = {HostBroadcastTopic};

# Internal table for tracking client (ids) and their respective groups
global host_groups: table[string] of vector of string;# &default="default";
#global groups: set[string, vector of string];


###############################
#                             #
# Implementation              #
#                             #
###############################

###
### Logging
###

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

###
### Subscription Sending
###

## Sends the interest given by ev to the client
##
## client_id: The client ID
## ev: The event of type Event
function send_subscribe(topic: string, ev: Event)
	{
	local ev_name = split_string(fmt("%s", ev$ev), /\n/)[0];
        local host_topic = topic;
	
	log_peer("info", "osquery", fmt("%s event %s() with '%s'",
					"subscribing to", ev_name, ev$query));
        print fmt("%s event %s() with '%s'",
                                        "subscribing to", ev_name, ev$query);

	local update_type = "BOTH";
	if ( ev$utype == ADD )
		update_type = "ADD";

	if ( ev$utype == REMOVE )
		update_type = "REMOVED";

	local resT = topic;
	if ( ev?$resT )
		resT = ev$resT;
	Broker::subscribe_to_events(resT);

	local inter: count = 10;
	if ( ev?$inter )
		inter = ev$inter;

	local ev_args = Broker::event_args(host_subscribe, ev_name, ev$query, resT, update_type, inter);
	Broker::send_event(host_topic, ev_args);
	} 

function send_unsubscribe(topic: string, ev: Event)
	{
	local ev_name = split_string(fmt("%s", ev$ev), /\n/)[0];
	local host_topic = topic;
	
	log_peer("info", "osquery", fmt("%s event %s() with '%s'",
					"unsubscribing from", ev_name, ev$query));
	print fmt("%s event %s() with '%s'",
                                        "unsubscribing from", ev_name, ev$query);

	local update_type = "BOTH";
	if ( ev$utype == ADD )
		update_type = "ADD";

	if ( ev$utype == REMOVE )
		update_type = "REMOVED";

	local resT = topic;
        if ( ev?$resT )
                resT = ev$resT;

        local inter: count = 10;
        if ( ev?$inter )
                inter = ev$inter;

        local ev_args = Broker::event_args(host_unsubscribe, ev_name, ev$query, resT, update_type, inter);
        Broker::send_event(host_topic, ev_args);
        }

function same_event(ev1: Event, ev2: Event) : bool
	{
	if ( ev1$query!=ev2$query  )
		return F;
	if ( (ev1?$ev!=ev2?$ev) )
		return F;
	if ( ev1?$ev && fmt("%s", ev1$ev)!=fmt("%s", ev2$ev) )
		return F;
	if ( (ev1?$utype!=ev2?$utype) )
		return F;
	if ( ev1?$utype && ev1$utype!=ev2$utype )
		return F;
	if ( (ev1?$resT!=ev2?$resT) )
		return F;
	if ( ev1?$resT && ev1$resT!=ev2$resT )
		return F;
	if ( (ev1?$inter!=ev2?$inter) )
		return F;
	if ( ev1?$inter && ev1$inter!=ev2$inter )
		return F;

	return T;
	}

#function set_host_group(peer_name: string, group: string)
#	{
#	if ( group !in groups )
#		{
#		local topic = fmt("/bro/osquery/group/%s", group);
#		log_local("info", fmt("subscribing to topic %s", topic));
#		Broker::subscribe_to_events(topic);
#		add groups[group];
#		}
#
#	host_groups[peer_name] = group;
#	}

function send_query(topic: string, ev: Event)
        {
        local ev_name = split_string(fmt("%s", ev$ev), /\n/)[0];
        local host_topic = topic;

        log_peer("info", "osquery", fmt("%s event %s() with '%s'", 
                                        "subscribing to", ev_name, ev$query));
        print fmt("%s event %s() with '%s'",
                                        "executing", ev_name, ev$query);

	local resT = topic;
        if ( ev?$resT )
                resT = ev$resT;
	Broker::subscribe_to_events(resT);

        local ev_args = Broker::event_args(host_query, ev_name, ev$query, resT, "SNAPSHOT");
        Broker::send_event(host_topic, ev_args);
        }

## Sends current subscriptions to the osquery host (given by client_id)
## if the subscription topic filter matches at least one of the hosts groups.
##
## client_id: The client ID
function send_subscriptions(client_id: string)
        {
        for ( i in subscriptions )
                {
                local s = subscriptions[i];

                if ( ! s?$ev ) 
			{
                        print "Skipping Subscription because event was deleted";
                        next;
			}

		for ( j in s$topics )
		print fmt("Searching match for topic %s",s$topics[j]) ;
	                {
	                local topic: string = s$topics[j];
	                for ( group in groups)
	                        {
#		                local group: string = host_groups[client_id][k];
	                        # Send only to topics that match to at least one group
	                        if ( |group| <= |topic| && group == topic[:|group|] )
	                                {
					local host_topic = fmt("/bro/osquery/uid/%s", client_id);
	                                send_subscribe(host_topic, s$ev);
	                                break;
	                                }
	                        }
	                }
                }
        }

###
### Subscription Management
###
### The framework keeps track of subscriptions and clients to match them .
### We need functions whenever subscription or clients change.
###

function subscribe(ev: Event, topics: vector of string)
        {
        # Include new Subscription in the vector
        subscriptions[|subscriptions|] = [$topics=topics, $ev=ev];

	for ( i in topics )
		{
		local topic: string = topics[i];
		local group: string;
		for ( group in groups)
			{
			# Send only to topics that match to at least one host's group
			if ( |group| <= |topic| && group == topic[:|group|] )
				{
                                send_subscribe(topic, ev);
                                break;
				}
			}
		}
        }

function unsubscribe(ev: Event, topics: vector of string)
       {
       for ( i in subscriptions )
               {
               if ( same_event(subscriptions[i]$ev, ev) )
			# Don't have a delete for vector, so set it to no-op
      			# by leaving the event empty.
			subscriptions[i]$ev = [$query=""];
               }

	# Unsubscribe from current clients.
	for ( i in topics )
		{
		local topic: string = topics[i];
                send_unsubscribe(topic, ev);
                }

        }

function subscribe_multiple(evs: vector of Event, topics: vector of string)
        {
        for ( i in evs )
                subscribe(evs[i], topics);
        }

function unsubscribe_multiple(evs: vector of Event, topics: vector of string)
        {
        for ( i in evs )
                unsubscribe(evs[i], topics);
        }

function execute_query(ev: Event, topics: vector of string)
	{
	for ( i in topics )
                {
                local topic: string = topics[i];
                send_query(topic, ev);
                }

        }


###############################
#                             #
# Event Handling              #
#                             #
###############################

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osquery"]);

	# TODO: Not sure this should stay here. We still need to figure out a way
	# for different applications to use Broker jointly without messing up
	# whatever another one is doing.
	Broker::enable();

	local topic = "/bro/osquery/announces";
	log_local("info", fmt("subscribing to topic %s", topic));
	Broker::subscribe_to_events(topic);

	Broker::listen(9999/tcp, "0.0.0.0");
	}

###
### Logging Strings (log/warning/error)
###

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


###
### Host Tracking
###

event host_new(client_id: string, group_list: vector of string, addr_list: vector of addr)
	{
	print "New Host Annoucement", client_id, group_list, addr_list;
	log_local("info", fmt("Received new announce message with uid %s", client_id));
	log_peer("info", client_id, "New osquery host announcement");

	# Internal client tracking
	add hosts[client_id];
	host_addresses[client_id] = addr_list;
	for (i in group_list)
		add groups[group_list[i]];
	host_groups[client_id] = group_list;

	# Host individual topic
	local host_topic = fmt("/bro/osquery/uid/%s", client_id);

	Broker::subscribe_to_events(host_topic);
	send_subscriptions(client_id);
	}

#TODO: Handle peer_name and client_id
event Broker::incoming_connection_established(peer_name: string)
	{
	print "incoming connection";
	log_peer("info", peer_name, "incoming connection established");
	}

event Broker::connection_incoming_connection_broken(peer_name: string)
	{
	local ip = to_addr(peer_name);
	delete hosts[peer_name];
	}
