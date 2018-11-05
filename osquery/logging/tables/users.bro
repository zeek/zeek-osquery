#! Logs users activity.

@load osquery/framework

module osquery::logging::users;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                uid: int &log;
                gid: int &log;
		uid_signed: int &log;
		gid_signed: int &log;
		username: string &log;
		description: string &log;
		directory: string &log;
		shell: string &log;
		uuid: string &log;
		user_type: string &log;
        };

	## Event to indicate that a new user was added on a host
	##
	## <params missing>
	global user_added: event(t: time, host: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string);
	
	## Event to indicate that a existing user was removed on a host
	##
	## <params missing>
	global user_removed: event(t: time, host: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string);
}

event host_users(resultInfo: osquery::ResultInfo,
		uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, 
		description: string, directory: string, shell: string, uuid: string, user_type: string) {
        if (resultInfo$utype != osquery::ADD) {
        	if (resultInfo$utype == osquery::REMOVE) {
			event user_removed(network_time(), resultInfo$host, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type);
		}
                # Just want to log new user existance.
                return;
	} else  {
		#print(fmt("Raising event for user %d", uid));
		event user_added(network_time(), resultInfo$host, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type);
	}

        local info: Info = [
		$t=network_time(),
		$host=resultInfo$host,
               	$uid = uid,
                $gid = gid,
                $uid_signed = uid_signed,
                $gid_signed = gid_signed,
                $username = username,
                $description = description,
                $directory = directory,
                $shell = shell,
                $uuid = uuid,
                $user_type = user_type
        ];

        Log::write(LOG, info);
        }

event bro_init()
        {
        Log::create_stream(LOG, [$columns=Info, $path="osq-users"]);

        local query = [$ev=host_users,$query="SELECT uid,gid,uid_signed,gid_signed,username,description,directory,shell,uuid,type FROM users;", $utype=osquery::BOTH];
        osquery::subscribe(query);
        }
