module osquery;

export {

    const broker_port: port = 9999/tcp &redef;
    const endpoint_name: string = "BroMaster" &redef;

    # Topic prefix used for all topics in osquery communication
    const TopicPrefix: string = "/bro/osquery" &redef;
    # Topic to which hosts send announce messages
    const AnnounceTopic: string = fmt("%s/announce",TopicPrefix) &redef;
    # Topic for individual hosts
    const HostIndividualTopic: string = fmt("%s/host",TopicPrefix) &redef;
    # Topic for groups
    const HostGroupTopic: string = fmt("%s/group",TopicPrefix) &redef;
    # Topic to address all hosts (default to send query requests)
    const HostBroadcastTopic: string = fmt("%s/hosts",TopicPrefix) &redef;
    # Undividual channel of this bro instance (default to receive query results)
 
    ## The osquery logging stream identifier.
    redef enum Log::ID += { LOG };

   const BroID_Topic: string = fmt("%s/%s",HostIndividualTopic,endpoint_name) &redef;

    ## A record type containing the column fields of the osquery log.
    type Info: record {
        ## The network time at which a osquery activity occurred.
        ts:                  time   &log;
        ## The scope of the message. Can be 'local' to indicating a message relevant for
        ## this node only. 'bro' indicates interfaction with other bro nodes and
        ## 'osquery' indicates interaction with osquery hosts.
        source:              string &log;
        ## The peer name (if any) with which a communication event is
        ## concerned.
        peer:                string &log &optional;
        ## The severity of the communication event message.
        level:               string &log &optional;
        ## The main log message.
        message:             string &log;
    };

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

    ## Event that signals the connection of a new osquery host
    ##
    ## client_id: An id that uniquely identifies an osquery host
    global host_connected: event (host_id: string);

    ## Event that signals the disconnection of an osquery host
    ##
    ## client_id: An id that uniquely identifies an osquery host
    global host_disconnected: event (host_id: string);

    ## Log a message of local scope for this bro node
    ##
    ## level: the severity of the message
    ## msg: the message content
    global log_local: function(level: string, msg: string, log: any &default=LOG);

    ## Log a message with scope including other bro nodes
    ##
    ## level: the severity of the message
    ## peer: the identifier of the other bro
    ## msg: the message content
    global log_bro: function(level: string, peer: string, msg: string, log: any &default=LOG);
    
    ## Log a message with scope including osquery nodes
    ##
    ## level: the severity of the message
    ## peer: the identifier for the osquery host or group 
    ## msg: the message content
    global log_osquery: function(level: string, peer: string, msg: string, log: any &default=LOG);


    ## Comparison of two events to be equal
    global same_event: function (q1: Query, q2: Query): bool;
}

function log_local(level: string, msg: string, log: any)
{
    Log::write(log,
        [
        $ts = network_time(),
        $level = level,
        $source = "local",
        $peer = endpoint_name,
        $message = msg
        ]
    );
}

function log_bro(level: string, peer: string, msg: string, log: any)
{
    Log::write(log,
        [
        $ts = network_time(),
        $level = level,
        $source = "bro",
        $peer = peer,
        $message = msg
        ]
    );
}

function log_osquery(level: string, peer: string, msg: string, log: any)
{
    Log::write(log,
        [
        $ts = network_time(),
        $level = level,
        $source = "host",
        $peer = peer,
        $message = msg
        ]
    );
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

