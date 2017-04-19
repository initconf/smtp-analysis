@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
        redef enum Log::ID += { SMTP_FROM_NAME };
	redef Input::accept_unsupported_types = T;

	global sql_write_smtp_from_name_db: function(fr: from_name_rec):bool ;
	global smtp_from_name_db: string = "" ; 
	

	}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_smtp_from_name_db(fr: from_name_rec): bool 
{

	 Phish::log_reporter(fmt("EVENT: sql_write_smtp_from_name_db: VARS: from_email_rec: %s", fr),10);

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("FROM_REC: SQL WRITING  sql_write_smtp_from_name_db: %s", fr),10) ;
		Log::write(Phish::SMTP_FROM_NAME, fr); 
		}
	return T ; 
}

event bro_init()
{
        Log::create_stream(Phish::SMTP_FROM_NAME, [$columns=from_name_rec]);
        #Log::remove_filter(Phish::SMTP_FROM_NAME, "default");

	local filter: Log::Filter = [$name="postgres_from_name_rec", $path="smtp_from_name", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test password=")];
	Log::add_filter(Phish::SMTP_FROM_NAME, filter);

}


event bro_init()
{
			
#$source="select from_name, array_to_string(days_sent,',') as days_sent, array_to_string(email, ',') as email, emails_sent, emails_recv, num_clicks, trustworthy from smtp_from_name order by id asc", 
#			$source="select t1.from_name, array_to_string(t1.days_sent,',') as days_sent, array_to_string(t1.email,',') as email, t1.emails_sent, t1.emails_recv, t1.num_clicks, t1.trustworthy from smtp_from_name t1 JOIN (select from_name, MAX(emails_sent) as max_emails_sent from smtp_from_name  group by from_name) t2 ON t1.from_name = t2.from_name AND t1.emails_sent = max_emails_sent ;",

	   Input::add_table( [
			$source="select t1.* from smtp_from_name t1 JOIN (select from_name, MAX(emails_sent) as max_emails_sent from smtp_from_name  group by from_name) t2 ON t1.from_name = t2.from_name AND t1.emails_sent = max_emails_sent ;",
			$name="smtp_from_name_table",
			$idx=from_name_rec_idx,
			$val=from_name_rec, 
			$destination=smtp_from_name, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["conninfo"]="host=localhost dbname=bro_test password=")
		]);





} 
@endif 


event read_smtp_from_name(description: Input::EventDescription, t: Input::Event, data: Val) {
        # do something here...
        print "DDDDDDDDDDDDDDDDDDDDDDD data:", data;
}


event Phish::sql_read_smtp_from_name_db(from_name: string)
        {

	          Input::add_event( [
                        $source="select t1.* from smtp_from_name t1 JOIN (select from_name, MAX(emails_sent) as max_emails_sent from smtp_from_name  where from_name = '$from_name' group by from_name) t2 ON t1.from_name = t2.from_name AND t1.emails_sent = max_emails_sent ;",
                        $name="read_smtp_from_name",
			$fields=from_name_rec, 
			$ev=read_smtp_from_name, 
                        $reader=Input::READER_POSTGRESQL,
                        $config=table(["conninfo"]="host=localhost dbname=bro_test password=")
                ]);
	
        }

event Input::end_of_data(name: string, source:string) 
        {

		if ( name == "smtp_from_name_table") 
		{ 
		Input::remove("smtp_from_name_table"); 
		FINISHED_READING_SMTP_FROM_NAME = T ; 
		log_reporter(fmt("FINISHED_READING_SMTP_FROM_NAME: %s", FINISHED_READING_SMTP_FROM_NAME),10);
		 event check_db_read_status();
		} 
        }


