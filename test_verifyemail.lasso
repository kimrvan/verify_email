<?lasso

// Load Ke Carlton's debug // Can activate 'console' mode, or use debug->activate for HTML mode
( (client_ip == '127.0.0.1' && server_name >> 'sutp.dev') || (client_ip == '68.148.103.77' && server_name >> 'dev.sutp') ) ? debug->activate('console')

// var(email = 'kimrvan@gmail.com')
// var(email = 'disco@sutp.com') // test for bad email
var(email = 'taplin@accesstelluride.com')
// var(email = 'fordprefect@sutp.com') // use on dev.sutp.com mail server
// var(email = 'kimv@sutp.com')
// var(email = 'kiwibirdie83@me.com')
// var(email = 'johnb@me.com')

local(result = verify_email($email))
local(mailserver_msg = #result->first)
local(duration = #result->second)

?>

<html>
<head>
</head>
<body>
	<p>Email Address Validation Process<br />
		---------------------------------<br />
		Message: [#mailserver_msg]<br />
		Duration: [#duration]</p>
</body>
