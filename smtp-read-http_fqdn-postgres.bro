module Phish; 

export {

	global tmpset: set[string] &create_expire=30 mins; 

	global Phish::sqlite_http_repute_db_line: event(description: Input::EventDescription, tpe: Input::Event, r: Phish::fqdn_rec); 
	global sql_read_http_reputation_db: event(domain: string); 
	
}

# since we have the smtp URL could be a good check to see if its reputation
# if host is not already in http_fqdn 

event Phish::process_smtp_urls(c: connection, url: string)
{

	log_reporter(fmt("EVENT: Phish::process_smtp_urls: url: %s", url),10);

        local host = extract_host(url);

	if (host in http_fqdn) 
		return ; 

	event Phish::sql_read_http_reputation_db(host); 
}

event Phish::sql_read_http_reputation_db(host: string)
	{

	log_reporter(fmt("EVENT: Phish::sql_read_http_reputation_db: host: %s", host),10);

	if (host !in tmpset)
        	{
		log_reporter(fmt("SQL READ: sql_read_http_reputation_db: %s", host),10); 
                add tmpset[host];

                Input::add_event( [
                        $source=fmt("select * from http_fqdn where domain = '%s' order by last_visited desc limit 1;", host), 
                        $name=host,
                        $fields=Phish::fqdn_rec,
                        $ev=Phish::sqlite_http_repute_db_line,
                        $want_record=T,
                        $reader=Input::READER_POSTGRESQL, 
			$config=table(["conninfo"]="host=localhost dbname=bro_test password=")
                ]);
        	}
	} 

#@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event Phish::sqlite_http_repute_db_line(description: Input::EventDescription, tpe: Input::Event, r: Phish::fqdn_rec)
	{
    		log_reporter(fmt("EVENT: Phish::sqlite_http_repute_db_line: returned: %s", r),10); 

		# populate bloomfilter with wellknown domain
		bloomfilter_add(Phish::uninteresting_fqdns, r$domain); 
	
		# now clear up the rare domain table since its in bloomfilter now 
		if (r$domain in http_fqdn)
			delete http_fqdn[r$domain]; 
	}

event Input::end_of_data(name: string, source:string)
	{
		log_reporter(fmt("END_OF_DATA: name:%s, source: %s", name, source),10); 
		#local query = fmt ("select * from http_fqdn where domain='%s' order by last_visited desc limit 1 ;", name); 
		#if (/http_fqdn/ in source && query == source)

		if (/http_fqdn/ in source) 
		{ 
			Input::remove(name);
			FINISHED_READING_HTTP_FQDN = T ; 
			### log_reporter(fmt("FINISHED_READING_HTTP_FQDN: %s", FINISHED_READING_HTTP_FQDN),10);
			event check_db_read_status(); 
		} 

		# since trust DB is only read on the manager 
		# we either (1) sync populated bloom with all workers
		# or (2) read trust DB on all workers too 
		# or (3) let workers query DB 'on-demand' ie when they see 
		# a new (! in http_fqdn) domain, they query the DB 
		# (3) is implemented and has no such performance issue 

		#if (source == "select * from http_fqdn;") 
		#	event m_w_bloomfilter_merge(uninteresting_fqdns); 
	}

#@endif 

### At the bro startup - we want to read the reputation_db 
### and populate uninteresting_fqdns 


event bro_init()
	{
               Input::add_table(
                   [
                   $source=fmt("select t1.* from http_fqdn t1 JOIN (select domain, MAX(last_visited) max_last_visited from http_fqdn group by domain) t2 ON t1.domain = t2.domain AND t1.last_visited = t2.max_last_visited ;"),
                   $name="http_fqdn_table",
                   $idx=fqdn_rec_idx, 
                   $val=fqdn_rec, 
                   $want_record=T,
		   $destination=http_fqdn, 
                   $reader=Input::READER_POSTGRESQL,
                   $config=table(["conninfo"]="host=localhost dbname=bro_test password=")
                   ]);	
	}


