module Phish; 


export {	
	global STATS_TIME: interval  =  10 mins ; 

	 redef enum Notice::Type += {
		WRITER_POSTGRESQL_CRASH, 
	} ; 
		
} 

event bro_done()
{
#	for (l in http_fqdn)
#		print fmt("%s", http_fqdn[l]); 


	for (a in AddressBook)
		print fmt ("Addressbook: %s", a); 

	return ; 

	for (l in smtp_from)
		print fmt("%s", smtp_from[l]); 
	
	for (l in smtp_from_name)
		print fmt("FROM_NAMEEEEEE: %s", smtp_from_name[l]); 
	
	for (l in smtp_from_email)
		print fmt("FROM_EMAIL: %s", smtp_from_email[l]); 
}	

event bro_done()
{

	return ; 

	print fmt("########### from_name #################"); 
        for (from_name in smtp_from_name)
               print fmt ("%s -> %s", from_name, smtp_from_name[from_name]);

	print fmt("########### from_email #################"); 
        for (from_email in smtp_from_email)
               print fmt ("%s -> %s", from_email, smtp_from_email[from_email]);

	print fmt("########### smtp_from #################"); 
        for (from in smtp_from)
               print fmt ("%s -> %s", from, smtp_from[from]);

	for (to_name in email_recv_to_name)
		print fmt("TO_NAME: %s, %s", to_name, email_recv_to_name[to_name]); 
	
	for (to_email in email_recv_to_address)
		print fmt("TO_EMAIL: %s, %s", to_email, email_recv_to_address[to_email]); 

}

event log_stats()
{
        #print fmt("STATS: mail_links: %s", |mail_links|); 
        log_reporter(fmt("STATS: mail_links: %s, smtp_from: %s, smtp_from_name: %s, smtp_from_email: %s, http_fqdn: %s, email_recv_to_name: %s, email_recv_to_address: %s", |Phish::mail_links|, |Phish::smtp_from|, |Phish::smtp_from_name|, |Phish::smtp_from_email|, |Phish::http_fqdn|, |Phish::email_recv_to_name|, |Phish::email_recv_to_address|),0);
        schedule STATS_TIME { Phish::log_stats() };
}

event bro_init()
{
        schedule STATS_TIME { Phish::log_stats() };

	#for(l in mail_links)
	#	print fmt("%s - %s", l, mail_links[l]); 
}


event reporter_error(t: time , msg: string , location: string )
{
	print fmt ("EVENT: bro-done Reporter ERROR: %s, %s, %s", t, msg, location); 

	if (/WRITER_POSTGRESQL/ in msg)
	{
		NOTICE([$note=Phish::WRITER_POSTGRESQL_CRASH, $msg=msg]); 
	} 

	if (/mail_links\/Log::WRITER_POSTGRESQL/ in msg)
	{
		#Log::disable_stream(Phish::MAIL_LINKS);
		#Log::remove_filter(Phish::MAIL_LINKS, "default");
		#Log::create_stream(Phish::MAIL_LINKS, [$columns=mail_links_table]);

		#local filter: Log::Filter = [$name="postgres_b", $path="mail_links", $writer=Log::WRITER_POSTGRESQL, $config=table(["dbname"]="bro", ["hostname"]="localhost")];
		#Log::add_filter(Phish::MAIL_LINKS, filter);

		#log_reporter(fmt("REINITIALIZING THE LOG STREAM: %s", filter),0); 
	} 

} 
