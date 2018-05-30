@load base/frameworks/broker
@load base/frameworks/logging

@load ./utils/host_interfaces

const broker_port: port = 9999/tcp &redef;
#redef Broker::endpoint_name = "Bro";

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
### Structures used in requests and responses.
###

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
### Function signatures for subscribe, unsubscribe, execute and join.
###

    ## Subscribe to an event from clients. Whenever an osquery client connects to us, we'll subscribe to all matching
    ## activity from it.
    ##
    ## The query is a mandatory parameter. It is send to a specific host and/or group (if specified). Otherwise (if
    ## neither hosts nor group is given) the query is send to the broadcast group, such that all hosts will receive it.
    ##
    ## q: The query to subscribe to.
    ## host: A specific host to address (optional).
    ## group: A specific group to address (optional).
    global subscribe: function(q: Query, host: string &default="", group: string &default="");

    ## Unsubscribe to an event from clients. This is sent to all clients that are currently connected and would match a
    ## similar subscribe call.
    ##
    ## The query is a mandatory parameter. It is send to a specific host and/or group (if specified). Otherwise (if
    ## neither hosts nor group is given) the query is send to the broadcast group, such that all hosts will receive it.
    ##
    ## q: The query to revoke.
    ## host: A specific host to address (optional).
    ## group: A specific group to address (optional).
    global unsubscribe: function(q: Query, host: string &default="", group: string &default="");

    ## Subscribe to multiple events. Whenever an osquery client connects to us, we'll subscribe to all matching activity
    ## from it.
    ##
    ## The queries is an mandatory parameter and contains 1 or more queries. Each of them is send to the specified hosts
    ## and the specified groups. If neither is given, each query is broadcasted to all hosts.
    ##
    ## qs: The queries to subscribe to.
    ## host_list: Specific hosts to address per query (optional).
    ## group_list: Specific groups to address per query (optional).
    global subscribe_multiple: function(qs: vector of Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));

    ## Unsubscribe from multiple events. This will get sent to all clients that are currently connected and would match
    ## a similar subscribe call.
    ##
    ## The queries is an mandatory parameter and contains 1 or more queries. Each of them is send to the specified hosts
    ## and the specified groups. If neither is given, each query is broadcasted to all hosts.
    ##
    ## qs: The queries to revoke.
    ## host_list: Specific hosts to address per query (optional).
    ## group_list: Specific groups to address per query (optional).
    global unsubscribe_multiple: function(qs: vector of Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));

    ## Send a one-time query to all currently connected clients.
    ##
    ## The query is a mandatory parameter. It is send to a specific host and/or group (if specified). Otherwise (if
    ## neither hosts nor group is given) the query is send to the broadcast group, such that all hosts will receive it.
    ##
    ## q: The query to execute.
    ## host: A specific host to address (optional).
    ## group: A specific group to address (optional).
    ##
    ## topic: The topic where the subscription is send to. All hosts in this group will
    ## get the subscription.
    global execute: function(q: Query, host: string &default="", group: string &default="");

    ## Send multiple one-time queries to all currently connected clients.
    ##
    ## The queries is an mandatory parameter and contains 1 or more queries. Each of them is send to the specified hosts
    ## and the specified groups. If neither is given, each query is broadcasted to all hosts.
    ##
    ## qs: The queries to execute.
    ## host_list: Specific hosts to address per query (optional).
    ## group_list: Specific groups to address per query (optional).
    global execute_multiple: function(qs: vector of Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));

    ## Make a subnet to be addressed by a group. Whenever an osquery client connects to us, we'll instruct it to join
    ## the given group.
    ##
    ## range: the subnet that is addressed.
    ## group: the group hosts should join.
    global set_host_group: function(range: subnet, group: string);

    #TODO: unset_host_group

###
### Functions to update the framework
###

    ## Checks the new ip address of the given host against the group collections and makes it to join respective groups.
    ##
    ## host_id: the id of the host
    ## ip: the new ip address of the host
    global send_joins_new_address: function(host_id: string, ip: addr): vector of string;

    ## Checks the new group of the given host against the subscriptions and makes it to schedule respective queries.
    ##
    ## host_id: the id of the host
    ## group: the new group of the host
    global send_subscriptions_new_group: function(host_id: string, group: string);

###
### Events emitted by this framework
###

    ## Event that signals the connection of a new osquery host
    ##
    ## client_id: An id that uniquely identifies an osquery host
    global host_connected: event (host_id: string);

    ## Event that signals the disconnection of an osquery host
    ##
    ## client_id: An id that uniquely identifies an osquery host
    global host_disconnected: event (host_id: string);

}

###
### Events from clients
###

## Event that signals the connection of a new osquery host
##
## client_id: An id that uniquely identifies an osquery host
global host_new: event (host_id: string, group_list: vector of string);

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

###
### Events to clients
###

# Sent by us to the client for subscribing to an event.
global host_subscribe: event(ev: string, query: string, cookie: string, resT: string, utype: string, inter: count);

# Sent by us to the client for unsubscribing from an event.
global host_unsubscribe: event(ev: string, query: string, cookie: string, resT: string, utype: string, inter: count);

# Sent by us to the client for one-time query execution.
global host_execute: event(ev: string, query: string, cookie: string, resT: string, utype: string);

# Sent by us to client to make him subscribe to the topic.
global host_join: event(group: string);

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

##
## Helper
##

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

###
### Logging
###

function log_host(level: string, peer: string, msg: string)
{
    Log::write(osquery::LOG,
        [
        $ts = network_time(),
        $level = level,
        $source = "osquery",
        $peer = peer,
        $message = msg
        ]
    );
}

function log_peer(level: string, peer: string, msg: string)
{
    Log::write(osquery::LOG,
        [
        $ts = network_time(),
        $level = level,
        $source = "bro",
        $peer = peer,
        $message = msg
        ]
    );
}

function log_local(level: string, msg: string)
{
    Log::write(osquery::LOG,
        [
        $ts = network_time(),
        $level = level,
        $source = "bro",
        $peer = "localhost",
        $message = msg
        ]
    );
}

###
### Sending Events (Subscriptions, Executions and Joins)
###

## Sends the interest given by ev to the client
##
## client_id: The client ID
## ev: The event of type Event
function send_subscribe(topic: string, query: Query)
{
    local ev_name = split_string(fmt("%s", query$ev), /\n/)[0];
    local host_topic = topic;

    log_peer("info", "osquery", fmt("%s event %s() with '%s'", "subscribing to", ev_name, query$query));
    print fmt("%s event %s() with '%s'", "subscribing to", ev_name, query$query);

    local update_type = "BOTH";
    if ( query$utype == ADD )
        update_type = "ADDED";

    if ( query$utype == REMOVE )
        update_type = "REMOVED";

    local cookie = query$cookie;

    local resT = topic;
    if ( query?$resT )
        resT = query$resT;
    Broker::subscribe(resT);

    local inter: count = 10;
    if ( query?$inter )
        inter = query$inter;

    local ev_args = Broker::make_event(host_subscribe, ev_name, query$query, cookie, resT, update_type, inter);
    Broker::publish(host_topic, ev_args);
}

function send_unsubscribe(topic: string, query: Query)
{
    local ev_name = split_string(fmt("%s", query$ev), /\n/)[0];
    local host_topic = topic;

    log_peer("info", "osquery", fmt("%s event %s() with '%s'", "unsubscribing from", ev_name, query$query));
    #print fmt("%s event %s() with '%s'", "unsubscribing from", ev_name, query$query);

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

    local ev_args = Broker::make_event(host_unsubscribe, ev_name, query$query, cookie, resT, update_type, inter);
    Broker::publish(host_topic, ev_args);
}

function send_execute(topic: string, q: Query)
{
    local ev_name = split_string(fmt("%s", q$ev), /\n/)[0];
    local host_topic = topic;

    log_peer("info", "osquery", fmt("%s event %s() with '%s'", "subscribing to", ev_name, q$query));
    #print fmt("%s event %s() with '%s'", "executing", ev_name, q$query);

    local cookie = q$cookie;

    local resT = topic;
    if ( q?$resT )
        resT = q$resT;
    Broker::subscribe(resT);

    local ev_args = Broker::make_event(host_execute, ev_name, q$query, cookie, resT, "SNAPSHOT");
    Broker::publish(host_topic, ev_args);
}

function send_join(host_topic: string, group: string)
{
    local ev_args = Broker::make_event(host_join, group);
    Broker::publish(host_topic, ev_args);
}


###############################
#                             #
# Subscription Management     #
#                             #
###############################
###
### The framework keeps track of subscriptions and clients to match them.
### We need functions whenever subscription or clients change.
###

##
## Evaluating to send events to new hosts (Subscriptions, Executions and Joins)
##

## Sends current subscriptions to the new osquery host (given by client_id).
##
## This checks if any subscription matches the host restriction (or broadcast)
##
## client_id: The client ID
function send_subscriptions_new_host(host_id: string)
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

        # Check for broadcast
        local sub_hosts: vector of string = s$hosts;
        local sub_groups: vector of string = s$groups;
        if (|sub_hosts|<=1 && sub_hosts[0]=="" && |sub_groups|<=1 && sub_groups[0]=="")
        {
            # To all if nothing specified
            send_subscribe(host_topic, s$query);
            skip_subscription = T;
        }
        if (skip_subscription)
            next;

        # Check the hosts in the Subscriptions
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

        # Check the groups in the Subscriptions
        for ( j in host_groups[host_id] )
        {
            local host_group = host_groups[host_id][j];
            for ( k in sub_groups )
            {
                local sub_group = sub_groups[k];
                if ( |host_group| <= |sub_group| && host_group == sub_group[:|host_group|])
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


## Checks for subscriptions that match the recently joined group
##
##
##
function send_subscriptions_new_group(host_id: string, group: string)
{
    local host_topic = fmt("%s/%s", HostIndividualTopic, host_id);
    for ( i in subscriptions )
    {
        local s = subscriptions[i];

        if ( ! s$query?$ev )
        {
            # Skip Subscription because it was deleted";
            next;
        }

        # Check the groups in the Subscriptions
        local sub_groups: vector of string = s$groups;
        for ( k in sub_groups )
        {
            local sub_group = sub_groups[k];
            if (group == sub_group)
            {
                if ( |group| <= |sub_group| && group == sub_group[:|group|])
                {
                    send_subscribe(host_topic, s$query);
                    break;
                }
            }
        }

    }
}

## Checks for groups that match the recently added address
##
##
##
function send_joins_new_address(host_id: string, ip: addr): vector of string
{
    local host_topic = fmt("%s/%s",HostIndividualTopic,host_id);
    local new_groups: vector of string;
    for ( i in collections )
    {
        local c = collections[i];


        if ( c$group=="" )
        {
            # Skip because Collection was deleted
            next;
        }

        for (k in c$ranges)
        {
            local range = c$ranges[k];
            if (ip in range)
            {
                local new_group: string = c$group;
                log_host("info", host_id, fmt("joining new group %s", new_group));
                send_join( host_topic, new_group );
                host_groups[host_id][|host_groups[host_id]|] = new_group;
                new_groups[|new_groups|] = new_group;
                break;
            }
        }
    }
    return new_groups;
}

###
### Evaluating to send new events to hosts (Subscriptions, Executions and Joins)
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
            {
                if (host_list[j] != "")
                {
                    send_subscribe(fmt("%s/%s",HostIndividualTopic,host_list[j]), qs[i]);
                }
            }
            # To specific group
            for (j in group_list)
            {
                if (group_list[j] != "")
                {
                    send_subscribe(fmt("%s/%s",HostGroupTopic,group_list[j]), qs[i]);
                }
            }
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
            {
                # Don't have a delete for vector, so set it to no-op by leaving the event empty.
                subscriptions[j]$query = [$query=""];
            }
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
            {
                if (host_list[j] != "")
                {
                    send_unsubscribe(fmt("%s/%s",HostIndividualTopic,host_list[j]), qs[i]);
                }
            }
            # To specific group
            for (j in group_list)
            {
                if (group_list[j] != "")
                {
                    send_unsubscribe(fmt("%s/%s",HostGroupTopic,group_list[j]), qs[i]);
                }
            }
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
            {
                if (host_list[j] != "")
                {
                    send_execute(fmt("%s/%s",HostIndividualTopic,host_list[j]), qs[i]);
                }
            }
            # To specific group
            for (j in group_list)
            {
                if (group_list[j] != "")
                {
                    send_execute(fmt("%s/%s",HostGroupTopic,group_list[j]), qs[i]);
                }
            }
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

        local hostInfo = osquery::host_interfaces::getHostInfoByHostID(host);
        for (j in hostInfo$interface_info)
        {
            local interfaceInfo =  hostInfo$interface_info[j];
            if (interfaceInfo$ipv4 in range || interfaceInfo$ipv6 in range)
            {
                local new_group = group;
                log_host("info", host, fmt("joining new group %s", new_group));
                send_join( host_topic, new_group );
                host_groups[host][|host_groups[host]|] = new_group;
                add groups[new_group];
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

    
    local topic = HostAnnounceTopic;
    log_local("info", fmt("subscribing to topic %s", topic));
    Broker::subscribe(topic);
    
    # TODO: Not sure this should stay here. We still need to figure out a way
    # for different applications to use Broker jointly without messing up
    # whatever another one is doing.

    Broker::listen("0.0.0.0", 9999/tcp);
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

event osquery::host_new(host_id: string, group_list: vector of string)
{
    log_local("info", fmt("Received new announce message with uid %s", host_id));
    log_peer("info", host_id, "New osquery host announcement");

    # Internal client tracking
    add hosts[host_id];
    for (i in group_list)
    {
        add groups[group_list[i]];
    }
    host_groups[host_id] = group_list;
    #TODO: that is only the topic prefix
    host_groups[host_id][|host_groups[host_id]|] = HostIndividualTopic;

    # Host individual topic (not used)
    local host_topic = fmt("%s/%s", HostIndividualTopic, host_id);

    # Make host to join group and to schedule queries
    send_subscriptions_new_host(host_id);

    # raise event for new host
    event osquery::host_connected(host_id);
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

    # raise event for the disconnected host
    event osquery::host_disconnected(peer_name);
}
