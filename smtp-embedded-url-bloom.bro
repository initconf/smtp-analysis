module SMTPurl;

export {

	    redef enum Log::ID += { Links_LOG };

	    type Info: record {
                ### When the email was seen.
                ts:   time    &log;
                ### Unique ID for the connection.
                uid:  string  &log;
                ### Connection details.
                id:   conn_id &log;
                ### url that was discovered.
		host: string &log &optional ; 
                url:  string  &log &optional;

        };


        redef enum Notice::Type += {
                ### Indicates that an MD5 sum was calculated for a MIME message.
                SMTP_Embeded_Malicious_URL,
		SMTP_Link_in_EMAIL_Clicked, 
		SMTP_Link_REFERRER_Clicked, 
		SMTP_Linked_BINARY_Download, 
		SMTP_Dotted_URL, 	
		SMTP_Suspicious_File_URL, 
		SMTP_Suspicious_Embedded_Text, 
		SMTP_WatchedFileType, 
		SMTP_Click_Here_Seen
	}; 
        

#		global url_dotted_pattern: pattern = /href.*http:\/\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*\"/ ; 
		global url_dotted_pattern: pattern = /([^"#]+)/; 

		const url_regex = /^([a-zA-Z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/ &redef;

		
		global ignore_dotted: pattern = /GLAKA\.COM/ &redef ; 

		#global mail_links: table [string] of string &synchronized &create_expire=4 hrs &redef ; 

		global mail_links :opaque of bloomfilter ; 

	
		global link_already_seen: set[string] &redef ; 
		global referrer_link_already_seen: set[string] ; 
		
		const suspicious_file_types: pattern = /\.rar$|\.exe$|\.zip$/ &redef; 
		const ignore_file_types: pattern = /\.gif$|\.png$|\.jpg$|\.xml$|\.PNG$|\.jpeg$|\.css$/ &redef; 

		redef link_already_seen += { "lbl.gov","es.net"}; 
		
		const ignore_mail_originators: set[subnet] += { 128.3.64.0/24, 128.3.65.0/24} &redef; 
		
		const ignore_mailfroms : pattern += /bro@|cp-mon-trace|ir-dev|security|ir-alerts|ir-reports/ &redef ; 
		const ignore_notification_emails: set[string] = {"ir-dev@lbl.gov", "ir-alerts@lbl.gov", "ir-reports@lbl.gov", "security@lbl.gov", "emailteam@lbl.gov",} &redef ; 
		const ignore_site_links: pattern = /http:\/\/.*\.lbl\.gov\/|http:\/\/.*\.es\.net/ &redef ; 

		
		const suspicious_text_in_url = /googledoc|googledocs|wrait\.ru|login\.lbl\.gov\.htm|login\.lbnl\.gov\.htm/ &redef ; 
		const suspicious_text_in_body = /[Pp][Ee][Rr][Ss][Oo][Nn][Aa][Ll] [Ee][Mm][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Uu][Ss][Ee][Rr] [Nn][Aa][Mm][Ee]|[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]/ &redef ; 

	#redef Notice::policy += {
		  #[$pred(n: Notice::Info) = { return n$note == SMTPurl::SMTP_Embeded_Malicious_URL; }, $action = Notice::ACTION_EMAIL],  
		  #####[$pred(n: Notice::Info) = { return n$note == SMTPurl::SMTP_Click_Here_Seen; }, $action = Notice::ACTION_EMAIL],   
	#} ; 
} 

redef record connection += {
        smtp_url: Info &optional;
};


event bro_init() &priority=5
{
        Log::create_stream(SMTPurl::Links_LOG, [$columns=Info]);

		mail_links = bloomfilter_basic_init(0.00000001, 10000000) ; 
} 


function extract_host(name: string): string
{
        local split_on_slash = split(name, /\//);
        local num_slash = |split_on_slash|;

        return split_on_slash[3];
}



### Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
    {
    return find_all(s, url_regex);
    }


### Extracts URLs discovered in arbitrary text without
### the URL scheme included.
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

if (! c?$smtp)
	return ; 

if(c$smtp?$mailfrom ) 
{
	if(c$smtp?$mailfrom && ignore_mailfroms  in c$smtp$mailfrom)
		return ; 
	} 

	if (c$smtp?$to) 
	{  
		for (to in c$smtp$to) 
		{ 
			if(/ir-dev@lbl\.gov|ir-reports@lbl\.gov|ir-alerts@lbl\.gov|security@lbl\.gov|cppm@lbl\.gov/ in to )
                        { 
				return ; 
			} 
		} 
	} 

	if ( ! c?$smtp ) return;

	if (c$id$orig_h in ignore_mail_originators) return; 

	local mail_info:string; 

	if (c$smtp?$to && c$smtp?$subject) { 
                mail_info =  fmt ("uid=%s from=%s to=%s subject=%s", c$smtp$uid, c$smtp$from, c$smtp$to, c$smtp$subject);
        }   
        else { 
		mail_info = c$smtp?$from ? fmt ("uid=%s from=%s", c$smtp$uid, c$smtp$from): fmt ("uid=%s", c$smtp$uid) ; 
        } 

	local urls = find_all_urls(data) ; 

	for (link in urls){
		if ( ignore_file_types !in link )
		  { 
			
			bloomfilter_add(mail_links, link); 
			log_smtp_urls(c, link); 
			
			if ( suspicious_file_types in link)
			{ 
				NOTICE([$note=SMTP_WatchedFileType, $msg=fmt("Suspicious filetype embeded in URL %s from  %s", link, c$id$orig_h), $conn=c]); 
			} 
			
			if ( suspicious_text_in_url in link)
			{ 
				NOTICE([$note=SMTP_Embeded_Malicious_URL, $msg=fmt("Suspicious text embeded in URL %s from  %s", link, c$smtp$uid), $conn=c]); 
			} 
			
			if ( suspicious_text_in_body in data && /[Cc][Ll][Ii][Cc][Kk] [Hh][Ee][Rr][Ee]/ in data)
			{ 
				NOTICE([$note=SMTP_Click_Here_Seen, $msg=fmt("Click Here seen in the email %s from  %s", link, c$smtp$uid), $conn=c]); 
			} 

			if (/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*/ in link && ignore_dotted !in link  )
			{ 
				NOTICE([$note=SMTP_Dotted_URL, $msg=fmt("Embeded IP in URL %s from  %s", link, c$id$orig_h), $conn=c]);
			} 

		 } ### check link in mail_links 
	} 	
}
 

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-3
{ 
	local str = HTTP::build_url_http(c$http); 

	local _bf_lookup_http= bloomfilter_lookup(SMTPurl::mail_links, str); 



	if ((_bf_lookup_http >0) && str !in SMTPurl::link_already_seen && ignore_file_types !in str && ignore_site_links !in str)
	{ 		
		NOTICE([$note=SMTPurl::SMTP_Link_in_EMAIL_Clicked, $msg=fmt("URL %s ", str), $conn=c]);
		add SMTPurl::link_already_seen[str] ; 
	} 	
	
	if (c$http?$referrer) 
	{ 

	local ref = c$http$referrer; 
	
		local _bf_lookup_ref = bloomfilter_lookup(SMTPurl::mail_links, ref);		
		if ((_bf_lookup_ref > 0) && ref !in SMTPurl::referrer_link_already_seen && ignore_file_types !in ref && ignore_site_links !in ref)
		{  
			print fmt("Added from %s", ref); 
		} 
	} 

} 
