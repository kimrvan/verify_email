<?lasso

// Use type to verify email with mail server
local(result = verify_email($email))

// Retrieve results and set to vars
local(proc_success = #result->first)
local(proc_msg = #result->second)
local(proc_duration = #result->get(3))

// Set $sys_msg depending on when the validation process failed
if(!#proc_success) => {
	(#proc_msg >> '001') ? $sys_msg = 'Please check your email address after the \'@\'. The domain you used does not appear to be correct.'
	(#proc_msg >> '004') ? $sys_msg = 'Please re-enter your email address. The address you entered does not appear to be correct.'
}

?>