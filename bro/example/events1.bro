@load base/frameworks/broker

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef Broker::endpoint_name = "Bro";

# Event to add a new SQL query to schedule
global add_osquery_query: event(event_name: string, query: string);
# Event to remove a SQL query from schedule
global remove_osquery_query: event(query: string);
# For this example, we keep track of a single osquery host with this global var
global client_id: string;
# Example queries
global query1: string = "SELECT unix_time FROM time";
global query2: string = "SELECT PID FROM processes";

event bro_init()
{
  Broker::enable();
  Broker::subscribe_to_events("/osquery/all");
  # Listen on channel for new host announcements (hosts post here if they boot up)
  Broker::subscribe_to_events("/osquery/announces");
  # Allow osquery hosts to connect to bro
  Broker::listen(broker_port, "0.0.0.0");
}

event Broker::incoming_connection_established(peer_name: string)
{
  print "Broker:incoming_connection_established to ", peer_name;
}

# A new osquery host announced that it is now available and awaiting orders
# Hosts will include their random/unique ID, such that a dedicated channel is available for each host
event new_osquery_host(uid: string)
{
  client_id = uid;
  print "Received new announce message with uid ", client_id;
  # Hosts will post the query results via their private channel
  Broker::subscribe_to_events("/osquery/uid/"+ client_id);

  # Here we schedule two queries with the event named "add_osquery_query" and send it to the host's private channel.
  # Further parameters are:
  #     The name of the response event
  #     The query to be scheduled
  Broker::send_event("/osquery/uid/"+client_id, Broker::event_args(add_osquery_query, "osquery_event_unix_time", query1));
  Broker::send_event("/osquery/uid/"+client_id, Broker::event_args(add_osquery_query, "osquery_event_pid", query2));
  # See the definition of receiving the responses by the given event name below
}

# Handling responses to query 1
event osquery_event_unix_time(t: int)
{
  print "Received unix_time: ", t;
}

# Handling responses to query 2
event osquery_event_pid(t: int)
{
  print "Received pid: ", t;
  # Let's say we would like to cancel a specific SQL query. The respective event is named "remove_osquery_query".
  # Parameter is the query string that was used when added to schedule
  print "Unsubscribing ", query2;
  Broker::send_event("/osquery/uid/"+client_id, Broker::event_args(remove_osquery_query, query2));
}

event Broker::incoming_connection_broken(peer_name: string)
{
  print "Broker::incoming_connection_broken", peer_name;
  terminate();
}

