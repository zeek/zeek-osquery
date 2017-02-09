@load base/frameworks/broker
@load base/frameworks/logging

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro";

module osquery;

export {
	# Topic prefix used for all topics in osquery communication
	const TopicPrefix: string = "/bro/osquery" &redef;
	# Topic to which hosts send announce messages
	const HostAnnounceTopic: string = fmt("%s/announce",TopicPrefix) &redef;
	# Topic for individual hosts
	const HostIndividualTopic: string = fmt("%s/uid",TopicPrefix) &redef;
	# Topic for groups
	const HostGroupTopic: string = fmt("%s/group",TopicPrefix) &redef;
	# Topic to address all hosts (default to send query requests)
	const HostBroadcastTopic: string = fmt("%s/all",TopicPrefix) &redef;
	# Undividual channel of this bro instance (default to receive query results)
	const BroID_Topic: string = fmt("%s/%s",HostIndividualTopic,"BroMaster") &redef;

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

	## Type defining a SQL query and schedule/execution parameters to be send to hosts.
	type Query: record {
		## The osquery SQL query selecting the activity to subscribe to.
		query: string;
		## The type of update to report.
		utype: UpdateType &default=ADD;
		## The interval of the query
		inter: count &optional;
		## The Broker topic THEY send the query result to
		resT: string &default=BroID_Topic;
		## The Bro event to execute when receiving updates.
		ev: any &optional;
		## A cookie we can set to match the result event
		cookie: string &default="";
	};

	## Type defining the event header of responses
	type ResultInfo: record {
		host: string;
		utype: UpdateType;
		cookie: string &optional;
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
	global subscribe: function(q: Query, host: string &default="", group: string &default="");

	## Unsubscribe to an event from clients. This will get sent to all clients
        ## that are currently connected and would match a similar subscribe
        ## call.
	##
	## ev: The event to unsubscribe from.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
        global unsubscribe: function(q: Query, host: string &default="", group: string &default="");

	## Subscribe to multiple events. Whenever an osquery client connects to us, we'll
	## subscribe to all matching activity from it.
	##
	## ev: The events to subscribe to.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
	global subscribe_multiple: function(qs: vector of Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));

	## Unsubscribe from multiple events. This will get sent to all clients
        ## that are currently connected and would match a similar subscribe
        ## call.
	##
	## ev: The events to unsubscribe from.
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
        global unsubscribe_multiple: function(qs: vector of Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));

	## Send a one-time query to all current clients in a specific group.
	##
	## ev: The event to execute.
        ##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
	global execute: function(q: Query, host: string &default="", group: string &default="");
	
	## Send a multiple one-time queries to all current clients in a specific group.
	##
	## ev: The event to execute.
        ##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscriptions.
	global execute_multiple: function(qs: vector of Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));

	## Instruct a subnet to join a specific group. Respective clients subscribe
	## to the given topic
	##
	## range: the subnet that is addressed
	## group: the topic hosts should subscribe to 
	global set_host_group: function(range: subnet, group: string);
	
	## Instruct a subnet to join a specific group. Respective clients subscribe
	## to the given topic
	##
	## range: the subnet that is addressed
	## group: the topic hosts should subscribe to 
#	global set_host_group_multiple: function(range_list: vector of subnet, group_list: vector of string);

###
### Events from Clients
###

	## Event that signals the connection of a new osquery host
	##
	## client_id: An id that uniquely identifies an osquery host 
        ## addr_list: A list of IP addresses of that osquery host
        global host_new: event (host_id: string, group_list: vector of string, addr_list: vector of addr);

	# Event sent by clients to report an error.
	#
	# TODO: Add peer_name.
	global host_error: event(host_id: string, msg: string);

	# Event sent by clients to report a warning.
	#
	# TODO: Add peer_name.
	global host_warning: event(host_id: string, msg: string);

	# Event sent by clients to report an informational log message.
	#
	# TODO: Add peer_name.
	global host_log: event(host_id: string, msg: string);

}

###
### Events to Clients
###

# Sent by us to the client for subscribing to an event.
global host_subscribe: event(ev: string, query: string, cookie: string, resT: string, utype: string, inter: count);

# Sent by us to the client for unsubscribing from an event.
global host_unsubscribe: event(ev: string, query: string, cookie: string, resT: string, utype: string, inter: count);

# Sent by us to the client for one-time query execution.
global host_execute: event(ev: string, query: string, cookie: string, resT: string, utype: string);

# Sent by us to client to make him subscribe to the topic.
global host_join: event(group: string);
	
global host_test: event(utype: UpdateType);

###
### Internal Structures
###

# Internal record for tracking a subscription.
type Subscription: record {
	query: Query;
	hosts: vector of string;
	groups: vector of string;
};

# Internal vector of subscriptions
global subscriptions: vector of Subscription;

# Internal set for tracing client ids
global hosts: set[string];

# Internal table for tracking client (ids) and their respective addresses
global host_addresses: table[string] of vector of addr;

# Internal record for tracking dynamic groups
type Collection: record {
	group: string;
	ranges: vector of subnet;
};

# Internal vector of host collections
global collections: vector of Collection;

# Internal set for groups of clients
global groups: set[string] = {HostBroadcastTopic};

# Internal table for tracking client (ids) and their respective groups
global host_groups: table[string] of vector of string;


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
## Sends the interest given by ev to the client
##
## client_id: The client ID
## ev: The event of type Event
function send_subscribe(topic: string, query: Query)
	{
	local ev_name = split_string(fmt("%s", query$ev), /\n/)[0];
        local host_topic = topic;
	
	log_peer("info", "osquery", fmt("%s event %s() with '%s'",
					"subscribing to", ev_name, query$query));
        #print fmt("%s event %s() with '%s'",
        #                                "subscribing to", ev_name, query$query);

	local update_type = "BOTH";
	if ( query$utype == ADD )
		update_type = "ADDED";

	if ( query$utype == REMOVE )
		update_type = "REMOVED";

	local cookie = query$cookie;

	local resT = topic;
	if ( query?$resT )
		resT = query$resT;
	Broker::subscribe_to_events(resT);

	local inter: count = 10;
	if ( query?$inter )
		inter = query$inter;

	local ev_args = Broker::event_args(host_subscribe, ev_name, query$query, cookie, resT, update_type, inter);
	Broker::send_event(host_topic, ev_args);
	} 

function send_unsubscribe(topic: string, query: Query)
	{
	local ev_name = split_string(fmt("%s", query$ev), /\n/)[0];
	local host_topic = topic;
	
	log_peer("info", "osquery", fmt("%s event %s() with '%s'",
					"unsubscribing from", ev_name, query$query));
	#print fmt("%s event %s() with '%s'",
                                        #"unsubscribing from", ev_name, query$query);

	local update_type = "BOTH";
	if ( query$utype == ADD )
		update_type = "ADDED";

	if ( query$utype == REMOVE )
		update_type = "REMOVED";
	
	local cookie = query$cookie;

	local resT = topic;
        if ( query?$resT )
                resT = query$resT;

        local inter: count = 10;
        if ( query?$inter )
                inter = query$inter;

        local ev_args = Broker::event_args(host_unsubscribe, ev_name, query$query, cookie, resT, update_type, inter);
        Broker::send_event(host_topic, ev_args);
        }

function same_event(q1: Query, q2: Query) : bool
	{
	if ( q1$query!=q2$query  )
		return F;
	if ( (q1?$ev!=q2?$ev) )
		return F;
	if ( q1?$ev && fmt("%s", q1$ev)!=fmt("%s", q2$ev) )
		return F;
	if ( (q1?$utype!=q2?$utype) )
		return F;
	if ( q1?$utype && q1$utype!=q2$utype )
		return F;
	if ( (q1?$resT!=q2?$resT) )
		return F;
	if ( q1?$resT && q1$resT!=q2$resT )
		return F;
	if ( (q1?$inter!=q2?$inter) )
		return F;
	if ( q1?$inter && q1$inter!=q2$inter )
		return F;

	return T;
	}


function send_execute(topic: string, q: Query)
        {
        local ev_name = split_string(fmt("%s", q$ev), /\n/)[0];
        local host_topic = topic;

        log_peer("info", "osquery", fmt("%s event %s() with '%s'", 
                                        "subscribing to", ev_name, q$query));
        #print fmt("%s event %s() with '%s'",
                                        #"executing", ev_name, q$query);

	local cookie = q$cookie;

	local resT = topic;
        if ( q?$resT )
                resT = q$resT;
	Broker::subscribe_to_events(resT);

        local ev_args = Broker::event_args(host_execute, ev_name, q$query, cookie, resT, "SNAPSHOT");
        Broker::send_event(host_topic, ev_args);
        }


## Sends current subscriptions to the osquery host (given by client_id)
## if the subscription topic filter matches at least one of the hosts groups.
##
## client_id: The client ID
function send_subscriptions(host_id: string)
        {
	local host_topic = fmt("%s/%s", HostIndividualTopic, host_id);
        for ( i in subscriptions )
                {
                local s = subscriptions[i];
		local skip_subscription = F;

                if ( ! s$query?$ev ) 
			{
                        # Skip Subscription because it was deleted";
                        next;
			}

	        local sub_hosts: vector of string = s$hosts;
		for ( j in sub_hosts )
			{
			local sub_host = sub_hosts[j];	
			if (host_id == sub_host)
				{
				send_subscribe(host_topic, s$query);
				skip_subscription = T;
				break;
				}
			}
		if (skip_subscription)
			next;

		local sub_groups: vector of string = s$groups;
	        for ( j in host_groups[host_id] )
	        	{
			local host_group = host_groups[host_id][j];
			for ( k in sub_groups )
				{
				local sub_group = sub_groups[k];
				if ( |host_group| <= |sub_group| && host_group == sub_group[:|host_group|]);
					{
					send_subscribe(host_topic, s$query);
					skip_subscription = T;
					break;
					}
				}
			if (skip_subscription)
				break;
			}
		if (skip_subscription)
			next;
                }
        }

function send_test(host_topic: string)
	{
	local ev_args = Broker::event_args(host_test, ADD);
	Broker::send_event(host_topic, ev_args);
	}

function send_join(host_topic: string, group: string)
	{
        local ev_args = Broker::event_args(host_join, group);
        Broker::send_event(host_topic, ev_args);
	}

function send_collections(host_id: string)
	{
	local host_topic = fmt("%s/%s",HostIndividualTopic,host_id);
	for ( i in collections )
		{
		local c = collections[i];
		local skip_collection = F;

		if ( c$group=="" )
			# Skip because Collection was deleted
			next;

		for (j in host_addresses[host_id])
			{
			local address = host_addresses[host_id][j];
			for (k in c$ranges)
				{
				local range = c$ranges[k];
				if (address in range)
					{
					local new_group: string = c$group;
					log_host("info", host_id, fmt("joining new group %s", new_group));
					send_join( host_topic, new_group );
					host_groups[host_id][|host_groups[host_id]|] = new_group;
					add groups[new_group];
					skip_collection = T;
					break;
					}
				}
			if (skip_collection)
				break;
			}
		}
	}
###
### Subscription Management
###
### The framework keeps track of subscriptions and clients to match them .
### We need functions whenever subscription or clients change.
###

function subscribe(q: Query, host: string, group: string)
        {
	local qs: vector of Query = vector(q);
	local host_list: vector of string = vector(host);
	local group_list: vector of string = vector(group);
	subscribe_multiple(qs, host_list, group_list);
        }

function unsubscribe(q: Query, host: string, group: string)
       {
	local qs: vector of Query = vector(q);
	local host_list: vector of string = vector(host);
	local group_list: vector of string = vector(group);
	unsubscribe_multiple(qs, host_list, group_list);
	}

function subscribe_multiple(qs: vector of Query, host_list: vector of string, group_list: vector of string)
        {
        for ( i in qs )
		{
        	# Include new Subscription in the vector
	        subscriptions[|subscriptions|] = [$query=qs[i], $hosts=host_list, $groups=group_list];
		if (|host_list|<=1 && host_list[0]=="" && |group_list|<=1 && group_list[0]=="")
			{
			# To all if nothing specified
			send_subscribe(HostBroadcastTopic, qs[i]);
			}
		else
			{
			# To specific host
			for (j in host_list)
				if (host_list[j] != "")
					send_subscribe(fmt("%s/%s",HostIndividualTopic,host_list[j]), qs[i]);
			# To specific group
			for (j in group_list)
				if (group_list[j] != "")
					send_subscribe(fmt("%s/%s",HostGroupTopic,group_list[j]), qs[i]);
			}
		}
        }

function unsubscribe_multiple(qs: vector of Query, host_list: vector of string, group_list: vector of string)
	{
         for ( i in qs )
		{
		# Cancel internal subscription
		for ( j in subscriptions )
			{
	                if ( same_event(subscriptions[j]$query, qs[i]) )
				# Don't have a delete for vector, so set it to no-op
	      			# by leaving the event empty.
				subscriptions[j]$query = [$query=""];
	                }

		#  Send unsubscribe
		if (|host_list|<=1 && host_list[0]=="" && |group_list|<=1 && group_list[0]=="")
			{
			# To all if nothing specified
			send_unsubscribe(HostBroadcastTopic, qs[i]);
			}
		else
			{
			# To specific host
			for (j in host_list)
				if (host_list[j] != "")
					send_unsubscribe(fmt("%s/%s",HostIndividualTopic,host_list[j]), qs[i]);
			# To specific group
			for (j in group_list)
				if (group_list[j] != "")
					send_unsubscribe(fmt("%s/%s",HostGroupTopic,group_list[j]), qs[i]);
			}
		}
        }

function execute(q: Query, host: string, group: string)
	{
	local qs: vector of Query = {q};
	local host_list: vector of string = {host};
	local group_list: vector of string = {group};
	execute_multiple(qs, host_list, group_list);
        }

function execute_multiple(qs: vector of Query, host_list: vector of string, group_list: vector of string)
	{
	for ( i in qs )
		{
		if (|host_list|<=1 && host_list[0]=="" && |group_list|<=1 && group_list[0]=="")
			{
			# To all if nothing specified
			send_execute(HostBroadcastTopic, qs[i]);
			}
		else
			{
			# To specific host
			for (j in host_list)
				if (host_list[j] != "")
					send_execute(fmt("%s/%s",HostIndividualTopic,host_list[j]), qs[i]);
			# To specific group
			for (j in group_list)
				if (group_list[j] != "")
					send_execute(fmt("%s/%s",HostGroupTopic,group_list[j]), qs[i]);
			}
		}
	}

function set_host_group(range: subnet, group: string)
	{
	# Include new Collection in the vector
        collections[|collections|] = [$group=group, $ranges=vector(range)];

	for (host in hosts )
		{
		local host_topic = fmt("%s/%s",HostIndividualTopic,host);
		local skip_host = F;
		for (i in host_addresses[host])
			{
			local address = host_addresses[host][i];
			if (address in range)
				{
				local new_group = group;
				log_host("info", host, fmt("joining new group %s", new_group));
				send_join( host_topic, new_group );
				host_groups[host][|host_groups[host]|] = group;
				add groups[group];
				skip_host = T;
				break;
				}
			}
			if (skip_host)
				break;
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

	local topic = HostAnnounceTopic;
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

event osquery::host_new(host_id: string, group_list: vector of string, addr_list: vector of addr)
	{
	log_local("info", fmt("Received new announce message with uid %s", host_id));
	log_peer("info", host_id, "New osquery host announcement");

	# Internal client tracking
	add hosts[host_id];
	host_addresses[host_id] = addr_list;
	for (i in group_list)
		add groups[group_list[i]];
	host_groups[host_id] = group_list;
	host_groups[host_id][|host_groups[host_id]|] = HostIndividualTopic;

	# Host individual topic (not used)
	local host_topic = fmt("%s/%s", HostIndividualTopic, host_id);

	# Make host to join group and to schedule queries
	send_collections(host_id);
	send_subscriptions(host_id);

	send_test(host_topic);
	}

#TODO: Handle peer_name and client_id
event Broker::incoming_connection_established(peer_name: string)
	{
	log_peer("info", peer_name, "incoming connection established");
	}

event Broker::incoming_connection_broken(peer_name: string)
	{
	log_peer("info", peer_name, "incoming connection broken");

	# Internal client tracking
	delete hosts[peer_name];
	delete host_addresses[peer_name];

	# Check if anyone else is left in the groups
	local others_groups: set[string];
	# Collect set of groups others are in
	for (i in host_groups)
		{
		if ( i != peer_name ) {
			for ( j in host_groups[i]) {
				add others_groups[ host_groups[i][j] ] ;
				}
			}
		}
	# Remove group if no one else has the group
	for (k in host_groups[peer_name])
		{
		local host_g: string = host_groups[peer_name][k];
		if ( host_g !in others_groups )
			{
			delete groups[host_g];
			}
		}
	delete host_groups[peer_name];
	}
