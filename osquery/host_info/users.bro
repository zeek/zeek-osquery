#! Provide current user information about hosts.

@load osquery/framework
@load osquery/logging/tables/users

module osquery::users;

export {
	type UserInfo: record {
		uid: int &optional;
		gid: int &optional;
		username: string &optional;
		user_type: string &optional;
	};

	## Get the UserInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getUserInfosByHostID: function(host_id: string): set[UserInfo];

	## Get the UserInfo of a host by its id
	##
	## host_id: The identifier of the host
	## uid: The identifier of the user
	global getUserInfoByHostID: function(host_id: string, uid: int): UserInfo;
}

# Table to access UserInfo by HostID
global host_users: table[string] of set[UserInfo];

event user_added(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string) {
	local user_info: UserInfo = [$uid=uid, $gid=gid, $username=username, $user_type=user_type];
	if (host_id in host_users) {
		add host_users[host_id][user_info];
	} else {
		host_users[host_id] = [user_info];
	}
	#print(fmt("Added user with uid %d", uid));
}

event remove_user(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string) {
	local user_info: UserInfo = [$uid=uid, $gid=gid, $username=username, $user_type=user_type];
	if (host_id !in host_users) {
		return;
	}

	if (user_info in host_users[host_id]) {
		delete host_users[host_id][user_info];
		#print(fmt("Removed user with uid %d", uid));
	}
}

event user_removed(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string) {
	schedule 30sec {remove_user(t, host_id, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type)};
}

function removeHost(host_id: string) {
	if (host_id in host_users) {
		delete host_users[host_id];
	}
}

event osquery::host_disconnected(host_id: string) {
	removeHost(host_id);
}

function getUserInfosByHostID(host_id: string): set[UserInfo] {
	if (host_id in host_users) {
		return host_users[host_id];
	}

	return set();
}

function getUserInfoByHostID(host_id: string, uid: int): UserInfo {
	if (host_id !in host_users) {
		return [];
	}

	for (user_info in host_users[host_id]) {
		if (user_info?$uid && user_info$uid == uid) {
			return user_info;
		}
	}

	return [];
}

