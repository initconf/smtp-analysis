@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
        redef enum Log::ID += { SMTP_FROM_EMAIL };
	redef Input::accept_unsupported_types = T;

	global sql_write_smtp_from_email_db: function(fr: from_email_rec):bool ;
	global smtp_from_email_db: string = "" ; 

	}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_smtp_from_email_db(fr: from_email_rec): bool 
{
	Phish::log_reporter(fmt("EVENT: sql_write_smtp_from_email_db: VARS: from_email_rec: %s", fr),10); 

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("FROM_REC: SQL WRITING  sql_write_smtp_from_email_db: %s", fr),10) ;
		Log::write(Phish::SMTP_FROM_EMAIL, fr); 
		}
	return T ; 
}

event bro_init()
{

        #Log::remove_filter(Phish::SMTP_FROM_EMAIL, "default");

        Log::create_stream(Phish::SMTP_FROM_EMAIL, [$columns=from_email_rec]);

	local filter: Log::Filter = [$name="postgres_from_email_rec", $path="smtp_from_email", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test password=")];
        Log::add_filter(Phish::SMTP_FROM_EMAIL, filter);

}


event bro_init()
{

#$source="select from_email, array_to_string(days_sent,',') as days_sent, array_to_string(email, ',') as name, emails_sent, emails_recv, num_clicks, trustworthy from smtp_from_name order by id asc",
#$source="select t1.from_email, array_to_string(t1.days_sent,',') as days_sent, array_to_string(t1.name, ',') as name, t1.emails_sent, t1.emails_recv, t1.num_clicks, t1.trustworthy from smtp_from_email t1 JOIN (select from_email, MAX(emails_sent) as max_emails_sent from smtp_from_email group by from_email) t2 ON t1.from_email = t2.from_email AND t1.emails_sent = max_emails_sent",

	   Input::add_table( [
			$source="select t1.* from smtp_from_email t1 JOIN (select from_email, MAX(emails_sent) as max_emails_sent from smtp_from_email group by from_email) t2 ON t1.from_email = t2.from_email AND t1.emails_sent = max_emails_sent",
			 $name="smtp_from_email_table",
			$idx=from_email_rec_idx,
			$val=from_email_rec, 
			$destination=smtp_from_email, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["conninfo"]="host=localhost dbname=bro_test password=")
		]);





} 
@endif 





event Phish::sql_read_smtp_from_email_db(link: string)
        {
        }

event Input::end_of_data(name: string, source:string) 
        {

		if ( name == "smtp_from_email_table") 
		{ 
		Input::remove("smtp_from_email_table"); 
		FINISHED_READING_SMTP_FROM_EMAIL = T ; 
		log_reporter(fmt("FINISHED_READING_SMTP_FROM_EMAIL: %s", FINISHED_READING_SMTP_FROM_EMAIL),10); 
		 event check_db_read_status();
		} 
        }


