module Phish; 

export {

	redef enum Notice::Type += {
		AllGood, 
		Spoofer, 
		SpoofedName, 
		Weird, 
		NewContact, 
	}; 

	type name_rec: record { 
		name: string &optional &log ; 
		email: string &log ;
	} ; 

	global mail_handshake : table[string, string] of count &default=0 ; 
	#global AddressBook: table[string] of addressbook_rec ; 	
	global check_addressbook: function(rec: SMTP::Info); 
	global check_addressbook_anomalies: function (rec: SMTP::Info); 
	global handshake_bloom: opaque of bloomfilter ;

} 

function add_to_addressbook(owner_name: string, owner_email: string, entry_name: string, entry_email: string)
{
	if (owner_email !in AddressBook)
	{
		local a_rec: addressbook_rec ;
               	local a_entry: set[string] ;
               	a_rec = [$owner_email = owner_email, $owner_name = owner_name, $entry = a_entry ] ;
               	AddressBook[owner_email] = a_rec ;
	}

       	local e = fmt("%s,%s", entry_name, entry_email);
       	if (e !in AddressBook[owner_email]$entry)
       	{
       		add AddressBook[owner_email]$entry [e] ;
               	sql_write_addressbook_db(AddressBook[owner_email]);
	}
} 

function addressbook_candidate(from_email: string, from_name: string, to_email: string, to_name: string)
{
	#print fmt ("Handshake: %s, %s", to_email, from_email);

	if (from_name == "" && to_email == from_email)
		return ; 

	if ([from_email, to_email] !in mail_handshake)
		mail_handshake[from_email, to_email] = 0 ;

	mail_handshake[from_email, to_email] += 1 ;

	if ([to_email, from_email] in mail_handshake )
	{ 
		add_to_addressbook(from_name, from_email, to_name, to_email);
	
		### TODO: now since to_email has responded to from_email
		### lets also add from_email to to_email's addressbook as well
		add_to_addressbook(to_name, to_email, from_name, from_email);
	} 
} 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled())

event SMTP::log_smtp(rec : SMTP::Info) &priority=-10 
{

        log_reporter(fmt("EVENT: SMTP::log_smtp: VARS: rec: %s", rec),10);

        #if (/250 ok/ !in rec$last_reply )
        #      return ;

        if (! rec?$from)
                return ;

	#check_addressbook_anomalies(rec); 
        #event Phish::w_m_smtp_rec_new(rec);
	#check_addressbook(rec); 


}

@endif 

function check_addressbook_anomalies(rec: SMTP::Info)
{
	local from_email  = rec?$from ? get_email_address(rec$from) : ""  ;
	local from_name = rec?$from ? get_email_name(rec$from) : "" ;
	local name_trustworthy = (from_name in smtp_from_name) ? smtp_from_name[from_name]$trustworthy : F ;
	local email_trustworthy: bool = (from_email in smtp_from_email) ? smtp_from_email[from_email]$trustworthy : F ;

	if (rec?$to) 
	{
		for (to in rec$to) 
		{
			local to_name = get_email_name(to); 
			local to_email = get_email_address(to); 

			if (to_email in AddressBook) 
			{ 
				for (e in AddressBook[to_email]$entry )
				{
				local parts = split_string(e,/,/); 
                        	local address_name = to_lower(parts[0]); 
	                        local address_email = to_lower(parts[1]); 

				local _msg = fmt("from_name: %s, from_address: %s, address_name: %s, address_email: %s", from_name, from_email, address_name, address_email);

				if (address_name == from_name && address_email != from_email && name_trustworthy && !email_trustworthy )
				{
					_msg += fmt(" BAD - spoof");
					_msg += fmt ("Other Entries: %s", smtp_from_name[from_name]);
					NOTICE([$note=Spoofer, $msg=_msg, $uid=rec$uid, $id=rec$id ]);
				}

				#if (address_name != from_name && address_email == from_email)
				#{
				#	_msg += fmt(" Weird");
				#	NOTICE([$note=Weird, $msg=_msg, $id=rec$id]);
				#	break; 
				#}
				#if (address_name == from_name && address_email == from_email)
				#{
				#	_msg += fmt(" ALL GOOD");
				#	NOTICE([$note=AllGood, $msg=_msg, $id =rec$id]);
				#}
				#if (address_name != from_name && address_email != from_email )
				#{
				#	_msg += fmt(" Potential NEW Contact");
				#	_msg += fmt ("NAME : %s", smtp_from_name[from_name]); 
				#	_msg += fmt ("Email: %s", smtp_from_email[from_email]); 
				#	local _from = fmt("%s %s", from_name, from_email); 
				#	_msg += _from == " " ? fmt ("History: %s", smtp_from[_from]) : "NONE" ; 
				#	NOTICE([$note=NewContact, $msg=_msg, $id=rec$id]);
			 	#	addressbook_candidate(from_email, from_name, to_email, to_name) ; 
				#	break ; 
				#}
				} 
			} 
			else 
			{ 
				if (from_name in smtp_from_name && from_email in smtp_from_email) 
				{ #print fmt ("NNNNNNNNNNNNNOT in addressbook: From: from_name: %s, from_email: %s", smtp_from_name[from_name], smtp_from_email[from_email]); 

				if (name_trustworthy && !email_trustworthy)
				{ 
					_msg = fmt ("from_name: %s, from_email: %s,rec : %s", from_name, from_email, rec); 
					NOTICE([$note=SpoofedName, $msg=_msg, $uid=rec$uid, $id=rec$id]);
				} 
				} 
			} 
		}
	} 
} 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled())

event Phish::w_m_smtp_rec_new(rec: SMTP::Info) &priority=-10 
{
	#log_reporter(fmt("EVENT: Phish::w_m_smtp_rec_new : VARS: rec: %s", rec),0); 

	local from_email  = rec?$from ? get_email_address(rec$from) : ""  ;
	local from_name = rec?$from ? get_email_name(rec$from) : "" ;

	local name_trustworthy = (from_name in smtp_from_name) ? smtp_from_name[from_name]$trustworthy : F ;
        local email_trustworthy: bool = (from_email in smtp_from_email) ? smtp_from_email[from_email]$trustworthy : F ;
	
	# if sender is trustworthy we check for compromised account 
	
	if (name_trustworthy && email_trustworthy)
	{ 
		return ; 

		## eventually we check for compromised account phish 
		#check_for_compromised_login_anomaly(rec); 
	} 

	if (from_name == "" && email_trustworthy)
		return ; 


	if (name_trustworthy && !email_trustworthy)
	{
		local _msg = fmt ("from_name: %s, from_email: %s,rec : %s", from_name, from_email, rec);
		NOTICE([$note=SpoofedName, $msg=_msg, $uid=rec$uid, $id=rec$id]);
	}

	
	
	#addressbook_candidate(from_email, from_name, to_email, to_name) ; 
	
	if (rec?$to) {
       		for (to in rec$to) 
		{
                        local to_name = get_email_name(to);
                        local to_email = get_email_address(to);

			if ([from_email, to_email] !in mail_handshake)
				mail_handshake[from_email, to_email] = 0 ;

			mail_handshake[from_email, to_email] += 1 ;

			if ([to_email, from_email] in mail_handshake )
			{
				add_to_addressbook(from_name, from_email, to_name, to_email);

				### TODO: now since to_email has responded to from_email
				### lets also add from_email to to_email's addressbook as well
				add_to_addressbook(to_name, to_email, from_name, from_email);
			}

			#print fmt ("TOOOOOOOOO0000000000000000000000000000  email is %s, %s, %s", rec$uid, to_name, to_email); 

			if (to_email in AddressBook)
				check_addressbook_anomalies(rec); 
		} 
	} 
} 


@endif 

event bro_init()
{
	handshake_bloom = bloomfilter_basic_init(0.001, 1000000);
} 


