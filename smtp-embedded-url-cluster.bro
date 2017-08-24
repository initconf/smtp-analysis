module SMTPurl;

export {

	    redef enum Log::ID += { Links_LOG };

	    type Info: record {
                # When the email was seen.
                ts:   time    &log;
                # Unique ID for the connection.
                uid:  string  &log;
                # Connection details.
                id:   conn_id &log;
                # url that was discovered.
		host: string &log &optional ; 
                url:  string  &log &optional;

        };


        redef enum Notice::Type += {
                # Indicates that an MD5 sum was calculated for a MIME message.
		## decommissioned 
		#SMTP_Link_in_EMAIL_Clicked, 
		#SMTP_Embedded_Malicious_URL,

                SMTP_sensitiveURI,
		SMTP_URI_Click, 
		SMTP_Link_REFERRER_Clicked, 
		SMTP_Linked_BINARY_Download, 
		SMTP_Dotted_URL, 	
		SMTP_Suspicious_File_URL, 
		SMTP_Suspicious_Embedded_Text, 
		SMTP_WatchedFileType, 
		SMTP_Click_Here_Seen, 
		Maillinks_Stats,
		HTTPSensitivePOST, 
	}; 
        

#		global url_dotted_pattern: pattern = /href.*http:\/\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*\"/ ; 
		global url_dotted_pattern: pattern = /([^"#]+)/; 

		####const url_regex = /^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/ &redef;
		const url_regex = /^https?:\/\/([a-z0-9A-Z]+(:[a-zA-Z0-9]+)?@)?[-a-z0-9A-Z\-]+(\.[-a-z0-9A-Z\-]+)*((:[0-9]+)?)(\/[a-zA-Z0-9;:\/\.\-_+%~?&amp;@=#\(\)]*)?/ ;
		

		global mail_links: table [string] of string &synchronized &create_expire=1 days &redef ; 
		global link_already_seen: set[string] &redef ; 
		global referrer_link_already_seen: set[string] ; 
		
		const suspicious_file_types: pattern = /\.xls$|\.rar$|\.exe$|\.zip$/ &redef; 
		#const ignore_file_types: pattern = /Z.GALAKA.COM/  &redef ;
		const ignore_file_types: pattern = /\.gif$|\.png$|\.jpg$|\.xml$|\.PNG$|\.jpeg$|\.css$/ &redef; 

		const ignore_fp_links : pattern = /GALAKA\.com|support\.proofpoint\.com/ &redef ;

		redef link_already_seen += { "lbl.gov","es.net", "jbei.org"}; 
		
		const ignore_mail_originators: set[subnet] += { 128.3.64.0/24, 128.3.65.0/24} &redef; 
		
		const ignore_mailfroms : pattern += /bro@|cp-mon-trace|ir-dev|security|ir-alerts|ir-reports/ &redef ; 
		const ignore_notification_emails: set[string] = {"ir-dev@lbl.gov", "ir-alerts@lbl.gov", "ir-reports@lbl.gov", "security@lbl.gov", "emailteam@lbl.gov",} &redef ; 
		const ignore_site_links: pattern = /lbl\.gov|es\.net|jbei\.org/ &redef ; 

		
		const suspicious_text_in_url = /password\.lbl\.gov\.[a-zA-Z0-9]+(\/)?|login\.lbl\.gov\.[a-zA-Z0-9]+(\/)?|googledoc|googledocs|wrait\.ru|login\.lbl\.gov\.htm|login\.lbnl\.gov\.htm/ &redef ; 
		const suspicious_text_in_body = /[Pp][Ee][Rr][Ss][Oo][Nn][Aa][Ll] [Ee][Mm][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Uu][Ss][Ee][Rr] [Nn][Aa][Mm][Ee]|[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]/ &redef ; 

		global m_w_smtpurls_add: event (link: string, mail_info: string); 
		global w_m_smtpurls_new: event (link: string, mail_info: string); 
		global populate_mail_links: function(link: string, mail_info: string); 

		global mail_links_stats: event () ;

		global track_post_requests: table[addr] of string &synchronized &create_expire= 2 days &redef ;
} 

@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /SMTPurl::m_w_smtpurls_add/;
redef Cluster::worker2manager_events += /SMTPurl::w_m_smtpurls_new/;
@endif



hook Notice::policy(n: Notice::Info)
{
  if ( n$note == SMTPurl::HTTPSensitivePOST)
        {
              add n$actions[Notice::ACTION_EMAIL];
        }
}


redef record connection += {
        smtp_url: Info &optional;
};


event bro_init() &priority=5
{
        Log::create_stream(SMTPurl::Links_LOG, [$columns=Info]);

} 


function extract_host(name: string): string
{
        local split_on_slash = split(name, /\//);
        local num_slash = |split_on_slash|;

# ash
        return split_on_slash[3];
}



# Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
    {
    return find_all(s, url_regex);
    }


# Extracts URLs discovered in arbitrary text without
# the URL scheme included.
function find_all_urls_without_scheme(s: string): string_set
{
	local urls = find_all_urls(s);
	local return_urls: set[string] = set();
	for ( url in urls )
		{
		local no_scheme = sub(url, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");
		add return_urls[no_scheme];
		}

	return return_urls;
}



function log_smtp_urls(c:connection, url:string)
{
		local info: Info; 

		info$ts = c$smtp$ts;
               	info$uid = c$smtp$uid ;
                info$id = c$id ;
               	info$url = url;
		info$host = extract_host(url) ;  

              	c$smtp_url = info;
               
		Log::write(SMTPurl::Links_LOG, c$smtp_url);

} 


event mime_all_data(c: connection, length: count, data: string) &priority=-5
{

#	if(/bro@|cp-mon-trace|ir-dev|security|ir-alerts|ir-reports/ in c$smtp$mailfrom)
	
	if (! c?$smtp) 
		return ;

	if(c$smtp?$mailfrom && ignore_mailfroms  in c$smtp$mailfrom)
	{	#print fmt ("To is %s", c) ; 
		#print fmt ("from is %s", c$smtp$mailfrom) ; 
		return ; 
	} 

	if (c$smtp?$to) 
	{  
		for (to in c$smtp$to) 
		{ 
			if(/ir-dev@lbl\.gov|ir-reports@lbl\.gov|ir-alerts@lbl\.gov|security@lbl\.gov|cppm@lbl\.gov/ in to )
                        { 	#print fmt ("2 To: %s", to); 
				return ; 
			} 
		} 
	} 

	if ( ! c?$smtp ) return;

	#if (c$smtp?$to in ignore_notification_emails) return ; 
	if (c$id$orig_h in ignore_mail_originators) return; 

	#print fmt("mime_all_data - Data: %s", data); 
	#print fmt ("mime_all_data: %s %s %s %s", c$smtp$mailfrom, c$smtp$rcptto, c$smtp$subject, c$smtp$reply_to); 

	local mail_info:string; 
	
	local to_list="" ; 

        for (to in c$smtp$to)
        {
                to_list = fmt ("%s, ", to);
        }

        if (c$smtp?$to && c$smtp?$subject) 
	{
                mail_info =  fmt ("uid=%s from=%s to=%s subject=%s", c$smtp$uid, c$smtp$from, to_list, c$smtp$subject);
        }
        else 
	{
                mail_info =  fmt ("uid=%s from=%s", c$smtp$uid, c$smtp$from);
        }
        #else 
	#{
#                mail_info =  fmt ("uid=%s ", c$smtp$uid);
#        }

	local urls = find_all_urls(data) ; 

	for (link in urls)
	{
		#local link =  sub(a,/(http|https):\/\//,"");
		#print fmt ("Inside URLS: %s",link); 

		log_smtp_urls(c, link);

		if (link !in mail_links && ignore_file_types !in link && ignore_fp_links !in link )
		  { 
			populate_mail_links(link, mail_info); 

			if ( suspicious_file_types in link)
			{ 
				NOTICE([$note=SMTP_WatchedFileType, $msg=fmt("Suspicious filetype embeded in URL %s from  %s", link, c$id$orig_h), $conn=c]); 
			} 
			
			if ( suspicious_text_in_url in link)
			{ 
				NOTICE([$note=SMTP_sensitiveURI, $msg=fmt("Suspicious text embeded in URL %s from  %s", link, c$smtp$uid), $conn=c]); 
			} 
			
			if ( suspicious_text_in_body in data && /[Cc][Ll][Ii][Cc][Kk] [Hh][Ee][Rr][Ee]/ in data)
			{ 
				NOTICE([$note=SMTP_Click_Here_Seen, $msg=fmt("Click Here seen in the email %s from  %s", link, c$smtp$uid), $conn=c]); 
			} 

			if (/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*/ in link )
			{ 
				#local url = split_all(data, /href.*\"http:\/\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*\"/); 
				#url[2]= sub(url[2], /^href=3D\"|href=\"/, "");
				#url[2]= sub(url[2], /\"$/, "");
				#print fmt("mime_all_data: URL is  %s", url[2]) ; 
				NOTICE([$note=SMTP_Dotted_URL, $msg=fmt("Embeded IP in URL %s from  %s", link, c$id$orig_h), $conn=c]);
			} 
		 } # check link in mail_links 
	} 	# for  
}


@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event m_w_smtpurls_add (link: string, mail_info: string)
{
	populate_mail_links(link, mail_info); 
}
@endif 


@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event w_m_smtpurls_new(link: string, mail_info: string)
{
 	event m_w_smtpurls_add (link, mail_info); 
}
@endif 

function populate_mail_links(link: string, mail_info: string)
{

	if (link !in mail_links && ignore_file_types !in link )
	{
               	mail_links[link] = mail_info ;

	} 

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
        event w_m_smtpurls_new(link, mail_info); 
@endif

} 
 

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-3
{ 

	local dst = c$id$resp_h ; 
	local str = HTTP::build_url_http(c$http); 

	### if (str in SMTPurl::mail_links && str !in SMTPurl::link_already_seen && ignore_file_types !in str && ignore_site_links !in str)

	if (str in SMTPurl::mail_links && ignore_file_types !in str && ignore_site_links !in str )
	{ 		
		NOTICE([$note=SMTPurl::SMTP_URI_Click, $msg=fmt("URL %s [%s]", str, SMTPurl::mail_links[str]), $conn=c]);
		add SMTPurl::link_already_seen[str] ; 
	
		if (dst !in track_post_requests)
                {
                        track_post_requests[dst] = fmt ("%s clicked %s to %s", c$id$orig_h, str, dst);
                        #print fmt ("POST request track: %s", track_post_requests[dst]);
                }
	} 	
	
#	if (c$http?$referrer) 
#	{ 
#		#local ref = c$http$referrer; 
#	#	#print fmt ("referrer is %s", ref) ; 
#		
#		if (ref !in SMTPurl::mail_links &&  ignore_file_types !in ref && ignore_site_links !in ref)
#		{  
#			mail_links[ref] = fmt("%s", str); 
#		} 
#	} 

# aashish
#                if (c$http?$md5 && str in SMTPurl::mail_links )
#                {
#                	NOTICE([$note=SMTP_Linked_BINARY_Download, $msg=fmt("%s %s %s", c$id$orig_h, c$http$md5, str),
#				$sub=c$http$md5, $conn=c, $URL=str]);
#                }

} 

#event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
#{
#
#	if ( method == "POST" && c$id$resp_h in track_post_requests)
#	{
#		local msg= fmt ("%s (smtp-url) resulting in POST request %s:", track_post_requests[c$id$resp_h], unescaped_URI);
#		NOTICE([$note=SMTPurl::HTTPSensitivePOST, $msg=msg, $conn=c]);
#	}
#
#}




event bro_init()
{
	schedule 1 min { mail_links_stats() }; 
} 

event mail_links_stats()
{
	local msg=fmt ("Mail_links stats: %s", |mail_links|);
	NOTICE([$note=SMTPurl::Maillinks_Stats, $msg=msg]);
	
	schedule 1 min { mail_links_stats() } ; 

} 
