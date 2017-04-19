@load base/protocols/smtp 

redef LogSQLite::unset_field = "(unset)";

module Phish;

export {
        redef enum Log::ID += { AddressBookDB  };
	redef Input::accept_unsupported_types = T;

	global sql_write_addressbook_db: function(fr: addressbook_rec):bool ;
	global addressbook_db: string = "" ; 


	}

@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

function sql_write_addressbook_db(fr: addressbook_rec): bool 
{
	log_reporter(fmt("EVENT: function sql_write_addressbook_db: VARS fr: %s", fr),2);

	if ( Cluster::local_node_type() == Cluster::MANAGER  || ! Cluster::is_enabled()) {
		Phish::log_reporter(fmt ("AddressBookDB: REC: SQL WRITING  sql_write_addressbook_db: %s", fr),10) ;
		Log::write(Phish::AddressBookDB, fr); 
		}
	return T ; 
}

event bro_init()
{

        Log::create_stream(Phish::AddressBookDB, [$columns=addressbook_rec]);
        #Log::remove_filter(Phish::SMTP_FROM, "default");
	local filter: Log::Filter = [$name="postgres_addressbook_rec", $path="addressbook", $writer=Log::WRITER_POSTGRESQL, $config=table(["conninfo"]="host=localhost dbname=bro_test password=")];
        Log::add_filter(Phish::AddressBookDB, filter);

}


event bro_init()
{
	   Input::add_table( [
			$source="select t1.* from addressbook t1 JOIN (select owner_email, MAX(id) as last_entry from addressbook group by owner_email ) t2 ON t1.owner_email = t2.owner_email AND t1.id = last_entry ;", 
			$name="addressbook_table",
			$idx=addressbook_rec_idx,
			$val=addressbook_rec, 
			$destination=AddressBook, 
			$reader=Input::READER_POSTGRESQL,
			$config=table(["conninfo"]="host=localhost dbname=bro_test password=")
		]);

} 


event Phish::sql_read_addressbook_db(link: string)
        {
        }

event Input::end_of_data(name: string, source:string) 
        {
	
	log_reporter(fmt("EVENT: Input::end_of_data: VARS name: %s", name),10);
		if ( name == "addressbook_table") 
		{ 
		Input::remove("addressbook_table"); 

		#	print fmt("%s", AddressBook ); 
		 event check_db_read_status();
		} 
        }


@endif 
