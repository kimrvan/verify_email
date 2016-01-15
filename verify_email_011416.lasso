<?Lassoscript

/*
	Type determines if a email address exists on a mail server

	REQUIRES $email
	RETURNS boolean true or false


	RESEARCH
	How to check if an email address exists without sending an email? - https://www.webdigi.co.uk/blog/2009/how-to-check-if-an-email-address-exists-without-sending-an-email/
	Lookup using MX record to validate mail server - http://www.rgagnon.com/javadetails/java-0452.html
	Email validation MX Lookup (...edge cases where a valid email address could fail an MX lookup check?) - http://stackoverflow.com/questions/1666807/email-validation-mx-lookup
	Log to console - sudo tcpdump -w /private/var/log/mail.log  -s 0 host mail.sutp.com and port 25
	Checking to see if an Email address is real.. - http://www.lassotalk.com/Checking-to-see-if-an-Email-address-is-real.lasso?225884

	Lasso
	There's something funky with the SMTP tags - http://www.lassotalk.com/There-s-something-funky-with-the-SMTP-tags.lasso?273604
	pop type for Lasso 9 - https://gist.github.com/Ke-/54b5ba95b9490070e7a6
	smtp-validate-email - https://github.com/zytzagoo/smtp-validate-email/blob/master/smtp-validate-email.php
	SSL and SMTP - http://www.lassotalk.com/SSL-and-SMTP.lasso?235664

	php
	php-smtp-email-validation - https://code.google.com/p/php-smtp-email-validation/source/browse/trunk/smtp_validateEmail.class.php

	Java
	Lookup using MX record to validate mail server - http://www.rgagnon.com/javadetails/java-0452.html
	

	REFERENCE
	SMTP Commands Reference - http://www.samlogic.net/articles/smtp-commands-reference.htm
	SMTP Commands and Definitions - https://technet.microsoft.com/en-us/library/aa996114(v=exchg.65).aspx
	
	SMTP errors and reply codes - http://www.serversmtp.com/en/smtp-error
	SMTP Connector Inbound Response Codes - http://www.mailenable.com/kb/Content/Article.asp?ID=me020032&SS=
	Internet Commands Error Codes - http://www.4d.com/docs/CMU/CMU88906.HTM

*/

// Load Ke Carlton's debug // Can activate 'console' mode, or use debug->activate for HTML mode
( (client_ip == '127.0.0.1' && server_name >> 'sutp.dev') || (client_ip == '68.148.103.77' && server_name >> 'dev.sutp') ) ? debug->activate('console')

// Initiate var to store results of SMTP responses
local(mailserver_msg = string)

local(time_start = date)

debug(`**** ` + #time_start + ` ********************`)

/* Gmail validation works */
// var(email = 'kimrvan@gmail.com')

// var(email = 'disco@sutp.com') // test for bad email
var(email = 'taplin@accesstelluride.com')
// var(email = 'fordprefect@sutp.com') // use on dev.sutp.com mail server
// var(email = 'kimv@sutp.com')
// var(email = 'kiwibirdie83@me.com')
// var(email = 'johnb@me.com')

debug('email to validate: ' + $email)

local(email_parts = $email->split('@'))
// Extract domain from email address
local(email_domain = #email_parts->second)

// Determine mailserver host name
local(mailserver_lookup = email_mxlookup(#email_domain))

if(#mailserver_lookup !== void) => {
	// Define vars for server response
	local(mailserver_domain = #mailserver_lookup->find('domain'))
	local(mailserver_host = #mailserver_lookup->find('host'))
	local(mailserver_priority = integer(#mailserver_lookup->find('priority'))) // lower is better
	
debug('mailserver_domain: ' + #mailserver_domain) // ie. sutp.com OR gmail.com
debug('mailserver_host: ' + #mailserver_host) // ie. mail.sutp.com OR gmail-smtp-in.l.google.com
debug('mailserver_priority: ' + #mailserver_priority)

else
	#mailserver_msg = 'Mail server lookup failed'
	debug('mailserver_msg: ' + #mailserver_msg)
}

// Initiate var to store SMTP commands to send
local(command_send = string)

// Create an instance of 'email_smtp' object
local(smtp = email_smtp)

// Open mail server connection
local(smtp_open = #smtp->open(
// 	-host = 'localhost',  // use on dev.sutp.com mail server
	-host = #mailserver_host,
// 	-port = 465, // SSL port for SMTPS /* gives Error Code: 54, Error Msg: Connection reset by peer // Remove server has sent a RST packet */
// 	-port = 587, // TLS port for MSA
// 	-ssl))
	-port = 25)) // unsecure, does not use TLS/SSL

debug('smtp_open: ' + #smtp_open)

if(#smtp_open) => {^
	
	local(smtp_mailfrom = #smtp->command(
		-send = 'MAIL FROM:<automatedemail@sutp.com>\r\n', // Identify sender of message
// 		-expect = 250)) // expected result code
		-expect = 250, // expected result code
		-read = true))
// 		-read,
// 		-timeout = 10))

debug('smtp_mailfrom: ' + #smtp_mailfrom)

	if(#smtp_mailfrom) => {
			
		// Identify message recipient
		#command_send = 'RCPT TO:<' + $email + '>\r\n'

		local(smtp_rcptto = #smtp->command(
			-send = #command_send,
// 			-expect = 250)) // expected result code
			-expect = 250, // expected result code
			-read = true))
// 			-read,
// 			-timeout = 10))

debug('smtp_rcptto: ' + #smtp_rcptto)
/*
	POSSIBLE RESPONSES
	- Server Error: 250 Requested mail action okay, completed
	- Server Error: 450 Requested mail action not taken: mailbox unavailable
		"Greylisting will send back a temporary error (450) and therefore the address will be 
		denied" - http://www.serversmtp.com/en/smtp-error
	- Server Error: 550 Requested action not taken: mailbox unavailable
		Blacklisting by spam checker (ie. Spamhaus Project - http://www.spamhaus.org/) or 
		rejection by mail server to prevent spam
 */

		if(#smtp_rcptto) => {
			#mailserver_msg = 'Recipient accepted - Email address is verified'
		else // #smtp_rcptto is false - close connection and try again to accomodate greylisting
			#mailserver_msg = 'Recipient NOT accepted - Email address can not be verified'
		}

	else // #smtp_mailfrom is false
		#mailserver_msg = 'Sender rejected'
	}
	
else
	// #smtp_open is false
	#mailserver_msg = 'Connection rejected - Invalid header'
^}

// Close mail server connection
local(smtp_close = #smtp->close)

debug('smtp_close: ' + #smtp_close)

?>

<html>
<head>
</head>
<body>
	<p>Email Address Validation Process<br />
		---------------------------------<br />
		Message: [#mailserver_msg]<br />
		Duration: [duration(#time_start,date)]</p>
</body>
