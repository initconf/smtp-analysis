smtp-analysis
=============
Also, please put the contents of site.bro in your site conf file (eg. local.bro etc).

Please make sure you configure the varaibles in site.bro portion of the script appropraitely. The biggest issue I have encountered was that if notice sender/reciepeints are not configured properly, and if a URL in question is sent out as alert, then the alert itself will generate an alert (since URL is content of the alert email). So to stop that "alert flood" we want to ignore emails going to/from your alert addresses.


Also, for bro-2.3 onwards use smtp-embedded-url-bloom.bro version of script which works with bloomfilter so you shouldn't even have any big memory footprints any more.

Look for SMTP* in notice logs. tweak as desired.
