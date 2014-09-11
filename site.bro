@load ./smtp-embedded-url-bloom.bro 

### smtp-embedded-url analysis

## Ignore HTTP tracking if the links from these domains are seen/clicked

redef SMTPurl::link_already_seen += { "example.come","example.org", };
redef SMTPurl::ignore_site_links: pattern = /.*\.example\.com\/|.*\.example\.net/ ;

## Careful: Since Bro watches all the emails (including the alerts it sends, this
## can create an Email storm because an alert including a malicious URL can cause another alert email
## ignore email going to these addresses.

redef SMTPurl::ignore_mails_to: set[string] = {"bro-alerts@example.com", "alerts@example.com", "reports@example.com"}; 

# Ignore emails from the following sender
redef SMTPurl::ignore_mailfroms += /bro@|alerts@|security@|reports/;

### Ignore emails originating from these subnets
## For IP address please use x.y.w.z/32

redef SMTPurl::ignore_mail_originators: set[subnet] += { 1.2.3.4/24, 1.2.3.5/24, } &redef;

### ignore further processing on the following file types embedded in the url - too much volume not useful dataset
redef SMTPurl::ignore_file_types: pattern = /\.gif$|\.png$|\.jpg$|\.xml$|\.PNG$|\.jpeg$|\.css$/ ;

## alert on these file types: generates SMTP_WatchedFileType
redef SMTPurl::suspicious_file_types: pattern = /\.doc$|\.docx|\.xlsx|\.xls|\.rar$|\.exe$|\.zip$/ ;


### Alert on text in URI : generates SMTP_Embeded_Malicious_URL
redef SMTPurl::suspicious_text_in_url = /googledoc|googledocs|ph\.ly\/|webs\.com\/|jimdo\.com/ &redef ;
#redef SMTPurl::suspicious_text_in_url = /googledoc|googledocs|ph\.ly\/|webs\.com\/|jimdo\.com|http(s)?:\/\/.*\/.*(\.edu|\.gov|\.com).*/ &redef ;

## Alert on the text in the body of the message: generates
redef SMTPurl::suspicious_text_in_body = /[Pp][Ee][Rr][Ss][Oo][Nn][Aa][Ll] [Ee][Mm][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Uu][Ss][Ee][Rr] [Nn][Aa][Mm][Ee]|[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]/ &redef ;
