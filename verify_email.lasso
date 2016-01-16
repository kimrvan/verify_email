<?lasso

/*
	Type to determine if a email address exists on a mail server

	REQUIRES
		email

	RETURNS following in an array
		proc_success
		proc_msg
		proc_duration

	USAGE
		local(email = 'somebody@domain.com')
	
		local(result = verify_email(#email))
		local(proc_success = #result->first)
		local(proc_msg = #result->second)
		local(proc_duration = #result->get(3))


	RESEARCH
	How to check if an email address exists without sending an email? - https://www.webdigi.co.uk/blog/2009/how-to-check-if-an-email-address-exists-without-sending-an-email/
	Lookup using MX record to validate mail server - http://www.rgagnon.com/javadetails/java-0452.html
	Email validation MX Lookup (...edge cases where a valid email address could fail an MX lookup check?) - http://stackoverflow.com/questions/1666807/email-validation-mx-lookup
	Log to console - sudo tcpdump -w /private/var/log/mail.log  -s 0 host mail.sutp.com and port 25
	Checking to see if an Email address is real.. - http://www.lassotalk.com/Checking-to-see-if-an-Email-address-is-real.lasso?225884

	- Lasso
	There's something funky with the SMTP tags - http://www.lassotalk.com/There-s-something-funky-with-the-SMTP-tags.lasso?273604
	pop type for Lasso 9 - https://gist.github.com/Ke-/54b5ba95b9490070e7a6
	smtp-validate-email - https://github.com/zytzagoo/smtp-validate-email/blob/master/smtp-validate-email.php
	SSL and SMTP - http://www.lassotalk.com/SSL-and-SMTP.lasso?235664

	- php
	php-smtp-email-validation - https://code.google.com/p/php-smtp-email-validation/source/browse/trunk/smtp_validateEmail.class.php

	- Java
	Lookup using MX record to validate mail server - http://www.rgagnon.com/javadetails/java-0452.html
	

	REFERENCE
	SMTP Commands Reference - http://www.samlogic.net/articles/smtp-commands-reference.htm
	SMTP Commands and Definitions - https://technet.microsoft.com/en-us/library/aa996114(v=exchg.65).aspx
	
	SMTP errors and reply codes - http://www.serversmtp.com/en/smtp-error
	SMTP Connector Inbound Response Codes - http://www.mailenable.com/kb/Content/Article.asp?ID=me020032&SS=
	Internet Commands Error Codes - http://www.4d.com/docs/CMU/CMU88906.HTM

*/

define verify_email => type {
	data
		public email::string, // email address to verify
		public proc_success, // used to return true or false
		public proc_msg, // stores results of SMTP responses
		public proc_duration, // stores time to complete script
		public result // used to return .proc_success, .proc_msg and .proc_duration

	public onCreate(
		email::string // required
	) => {

		.proc_success = false

		// Assign parameter value to data member
		.'email' = #email

		// Var used to time duration of process
		local(time_start = date)
		
		log_critical(`**** ` + #time_start + ` ********************`)		
		log_critical('email to validate: ' + .'email')
		
		// Extract domain from email address
		local(email_parts = .'email'->split('@'))
		local(email_domain = #email_parts->second)
		
		// Determine mailserver host name
		local(mailserver_lookup = email_mxlookup(#email_domain))
		
		if(#mailserver_lookup !== void) => {
			// Define vars for server response
			local(mailserver_domain = #mailserver_lookup->find('domain'))
			local(mailserver_host = #mailserver_lookup->find('host'))
			local(mailserver_priority = integer(#mailserver_lookup->find('priority'))) // lower is better
			
// 			log_critical('mailserver_domain: ' + #mailserver_domain) // ie. gmail.com
			log_critical('mailserver_host: ' + #mailserver_host) // ie. gmail-smtp-in.l.google.com
			log_critical('mailserver_priority: ' + #mailserver_priority)
		else
			.proc_msg = 'Mail server lookup failed'
			log_critical('MX Lookup: ' + .proc_msg)
		}
		
		// Initiate var to store SMTP commands to send
		local(command_send = string)
		
		// Create an instance of 'email_smtp' object
		local(smtp = email_smtp)
		
		// Open mail server connection
		local(smtp_open = #smtp->open(
			-host = #mailserver_host,
			-port = 25)) // unsecure, does not use TLS/SSL
		
		log_critical('smtp_open: ' + #smtp_open)
		
		if(#smtp_open) => {^
			
			local(smtp_mailfrom = #smtp->command(
				-send = 'MAIL FROM:<automatedemail@sutp.com>\r\n', // Identify sender of message
				-expect = 250, // expected result code
				-read = true))
		
		log_critical('smtp_mailfrom: ' + #smtp_mailfrom)
		
			if(#smtp_mailfrom) => {
					
				// Identify message recipient
				#command_send = 'RCPT TO:<' + .'email' + '>\r\n'
		
				local(smtp_rcptto = #smtp->command(
					-send = #command_send,
					-expect = 250, // expected result code
					-read = true))
		
				log_critical('smtp_rcptto: ' + #smtp_rcptto)
				/*
					POSSIBLE RESPONSES
					True:
					- Server Error: 250 Requested mail action okay, completed
					False:
					- Server Error: 450 Requested mail action not taken: mailbox unavailable
						"Greylisting will send back a temporary error (450) and therefore the address will be 
						denied" - http://www.serversmtp.com/en/smtp-error
					- Server Error: 550 Requested action not taken: mailbox unavailable
						Blacklisting by spam checker (ie. Spamhaus Project - http://www.spamhaus.org/) or 
						rejection by mail server to prevent spam
				 */
		
				if(#smtp_rcptto) => {
					.proc_success = true
					.proc_msg = 'Recipient accepted - Email address is verified'
				else
					.proc_msg = 'Recipient NOT accepted - Email address can NOT be verified'
				}
		
			else // #smtp_mailfrom is false
				.proc_msg = 'Sender rejected'
			}
			
		else
			// #smtp_open is false
			.proc_msg = 'Connection rejected - Invalid header'
		^}
		
		// Close mail server connection
		local(smtp_close = #smtp->close)
		
		log_critical('smtp_close: ' + #smtp_close)

		.proc_duration = duration(#time_start,date)
		.result = array(.proc_success,.proc_msg,.proc_duration)
		
		return(.result)
	}
}

?>