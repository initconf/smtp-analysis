@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
        redef enum Log::ID += { SMTP_FROM };
	redef Input::accept_unsupported_types = T;

	global sql_write_smtp_from_db: function(fr: from_rec):bool ;
	global smtp_from_db: string = "" ; 


	}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_smtp_from_db(fr: from_rec): bool 
{
	log_reporter(fmt("EVENT: function sql_write_smtp_from_db: VARS fr: %s", fr),10);

	local t_fr: from_rec = [$m_from=escape_string(fr$m_from), $days_sent=fr$days_sent, $email=fr$email, $emails_sent=fr$emails_sent, $emails_recv=fr$emails_recv, $num_clicks=fr$num_clicks, $trustworthy=fr$trustworthy]; 

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("FROM_REC: SQL WRITING  sql_write_smtp_from_db: %s", fr),10) ;
		Log::write(Phish::SMTP_FROM, fr); 
		}
	return T ; 
}

event bro_init()
{

        Log::create_stream(Phish::SMTP_FROM, [$columns=from_rec]);
        #Log::remove_filter(Phish::SMTP_FROM, "default");

	local filter: Log::Filter = [$name="postgres_from_rec", $path="smtp_from", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test password=")];
        Log::add_filter(Phish::SMTP_FROM, filter);

}


event bro_init()
{

	   Input::add_table( [
			$source="select t1.* from smtp_from t1 JOIN (select m_from, MAX(emails_sent) as max_emails_sent from smtp_from group by m_from ) t2 ON t1.m_from = t2.m_from AND t1.emails_sent = max_emails_sent ;",
			 $name="smtp_from_table",
			$idx=from_rec_idx,
			$val=from_rec, 
			$destination=smtp_from, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["conninfo"]="host=localhost dbname=bro_test password=")
		]);
} 
@endif 

event Phish::sql_read_smtp_from_db(link: string)
        {
        }

event Input::end_of_data(name: string, source:string) 
        {
	
	log_reporter(fmt("EVENT: Input::end_of_data: VARS name: %s", name),10);
		if ( name == "smtp_from_table") 
		{ 
		Input::remove("smtp_from_table"); 
		FINISHED_READING_SMTP_FROM = T ; 
		log_reporter(fmt("FINISHED_READING_SMTP_FROM: %s", FINISHED_READING_SMTP_FROM),10);
		 event check_db_read_status();
		} 
        }


