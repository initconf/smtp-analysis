@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
        redef enum Log::ID += { MAIL_FROM };
	redef Input::accept_unsupported_types = T;

	global sql_write_mail_from_db: function(fr: from_rec):bool ;
	global mail_from_db: string = "" ; 

	}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_mail_from_db(fr: from_rec): bool 
{
	Phish::log_reporter(fmt("from_rec: %s", fr),0); 

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("FROM_REC: SQL WRITING  sql_write_mail_from_db: %s", fr),0) ;
		Log::write(Phish::MAIL_FROM, fr); 
		}
	return T ; 
}

event bro_init()
{

        Log::remove_filter(Phish::MAIL_FROM, "default");

        Log::create_stream(Phish::MAIL_FROM, [$columns=from_rec]);

	local filter: Log::Filter = [$name="postgres_from_rec", $path="mail_from", $writer=Log::WRITER_POSTGRESQL, $config=table(["dbname"]="bro", ["hostname"]="localhost")];
        Log::add_filter(Phish::MAIL_FROM, filter);

}


event bro_init()
{
	print fmt ("RUNNNNNNNNNNNNNNNNG ..."); 

	   Input::add_table( [
			$source="select * from mail_from order by id asc", 
			$name="mail_from_table",
			$idx=from_rec_idx,
			$val=from_rec, 
			$destination=smtp_from, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["dbname"]="bro", ["hostname"]="localhost")
		]);





} 
@endif 





event Phish::sql_read_mail_from_db(link: string)
        {
        }

event Input::end_of_data(name: string, source:string) 
        {

		if ( name == "mail_from_table") 
		{ 
		Input::remove("mail_from_table"); 
		print fmt ("name : %s, source: %s", name, source) ; 


	for (r in smtp_from)
		print fmt ("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRR %s", smtp_from[r]); 
		} 
        }


