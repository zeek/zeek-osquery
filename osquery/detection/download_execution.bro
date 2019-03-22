#! Logs execution of downloaded files.

@load base/protocols/pop3

module osquery::download_execution;

# TODO: clean smtp_attachments upon session removal
# TODO: clean smtp_hashes after some time

export {

    # SMTP Attachment
    type SMTP_attachment: record {
        sid: string;
        to: string &default = "";
        content_type: string &default = "";
        content_disposition: string &default = "";
        file_name: string &default = "";
        file_hash: string &default = "";
    };

    global smtp_attachment_recv: event(smtp_attachment: SMTP_attachment);
}


# SMTP Attachment per session
global smtp_attachments: table[string] of SMTP_attachment = table();
global smtp_hashes: table[string] of vector of SMTP_attachment = table();

global att_header_names: set[string] = {"TO", "CONTENT-TYPE", "CONTENT-DISPOSITION"};

# Track incoming emails and their attachment infos
event mime_one_header(c: connection, h: mime_header_rec) {
    # SMTP only
    if ("SMTP" !in c$service) { return; }

    # Some headers only
    if (h$name !in att_header_names) { return; }

    # New or existing attachment
    local att: SMTP_attachment;
    if (c$uid in smtp_attachments) {
        att = smtp_attachments[c$uid];
    } else {
        att = [$sid=c$uid];
    }

    # TO
    if (h$name == "TO") {
        att$to = h$value;
        att$content_type = "";
        att$content_disposition = "";
        att$file_name = "";
    }
    # CONTENT-TYPE
    if (h$name == "CONTENT-TYPE") {
        local tname_idx = strstr(h$value, ";");
        if (tname_idx != 0) {
            att$content_type = h$value[:tname_idx-1];
        } else {
            att$content_type = h$value;
        }
        att$content_disposition = "";
        att$file_name = "";
    }
    # CONTENT_DISPOSITION
    if (h$name == "CONTENT-DISPOSITION") {
        # disposition == attachment
        if (strstr(h$value, "attachment") == 1) {
            # disposition name
            local dname_idx = strstr(h$value, ";");
            if (dname_idx != 0) {
                att$content_disposition = h$value[:dname_idx-1];
            } else {
                att$content_disposition = h$value;
            }

            # file name
            local fname_idx = strstr(h$value, "filename=");
            if (fname_idx != 0) {
                att$file_name = h$value[fname_idx+|"filename="|:-1];
            } else {
                att$file_name = "";
            }
        } else {
            att$content_disposition = "";
            att$file_name = "";
        }
    }

    # Save
    smtp_attachments[c$uid] = att;
}

# Track files
event file_sniff(f: fa_file, meta: fa_metadata) {
    # Require application mime
    if ( ! meta?$mime_type || strstr(meta$mime_type, "application") != 1 ) return;

    # Calculate MD5
    Files::add_analyzer(f, Files::ANALYZER_MD5);
}

event osquery::download_execution::smtp_attachment_recv(smtp_attachment: SMTP_attachment) {
    # New or existing hash
    local h: string = smtp_attachment$file_hash;
    if (h !in smtp_hashes) {
        smtp_hashes[h] = vector();
    }

    # Append session
    smtp_hashes[h][|smtp_hashes[h]|] = smtp_attachment;
}

event file_hash(f: fa_file, kind: string, hash: string) {
    # MD5 only
    if (kind != "md5") { return; }

    # SMTP and known attachment only
    if (!f?$conns) { return; }
    local att_sessions: set[string] = set();
    local c_id: conn_id;
    for (c_id in f$conns) {
        # SMTP only
        if ("SMTP" !in f$conns[c_id]$service) { next; }
        # Known attachment only
        if (f$conns[c_id]$uid !in smtp_attachments) { next; }
        # Candidate session
        add att_sessions[f$conns[c_id]$uid];
    }
    if (|att_sessions| == 0) { return; }

    # Known attachment only
    local sess: string;
    local att: SMTP_attachment;
    for (sess in att_sessions) {
        att = smtp_attachments[sess];
        att$file_hash = hash;
        #print "smtp attachment", att;

        # Valid file attachment
        event osquery::download_execution::smtp_attachment_recv(att);
    }
}

event process_binary_hash(resultInfo: osquery::ResultInfo, md5: string) {
    # Known smtp attachment hash
    if (md5 !in smtp_hashes) { return; }

    # Execution
    local att: SMTP_attachment;
    local tos: set[string] = set();
    for (att_idx in smtp_hashes[md5]) {
        # Collect recp
        att = smtp_hashes[md5][att_idx];
        add tos[att$to];
    }
    print fmt("Execution of email attachment for '%s' on host '%s'", tos, resultInfo$host);
}

event process_state_added(host_id: string, process_info: osquery::processes::ProcessInfo) {
    # Binaries only
    if (!process_info?$path || process_info$path == "") { return; }

    # Select query
    local query_string = fmt("SELECT md5 FROM hash WHERE path=\"%s\"", process_info$path);

    # Send query
    local query = [$ev=process_binary_hash, $query=query_string];
    osquery::execute(query, host_id);

}

