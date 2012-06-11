<?php
  require_once 'lib_trustauth.php';
	echo '
<table class="form-table">
<tr>
	<th><label for="trustauth-register-button">'.__('TrustAuth', 'trustauth').'</label></th>
	<td>
		<p style="margin-top:0;">'.__('Adding your TrustAuth key allows you to login to WordPress using TrustAuth.', 'trustauth').'</p>
		<p>',
      TrustAuth::register_form(array('use_html5' => false)),
		'</p>
	</td>
</tr>
</table>
';
?>
