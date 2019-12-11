<!doctype html>
<html>
  <head>
    <title>SSP-API CPS Authentication</title>
  </head>
</html>

<?php

echo "/opt/lampp/htdocs/auth/index.php";
echo "<br/>";

echo "<br/>QUERY_STRING: ";
echo	isset($_SERVER['QUERY_STRING'])? $_SERVER['QUERY_STRING']: "(none)";	// Query String
echo "<br/>CONTENT_LENGTH: ";
echo	isset($_SERVER['CONTENT_LENGTH'])? intval($_SERVER['CONTENT_LENGTH']): 0; // Data Length
echo "<br/>HTTP_HOST: ";
echo	isset($_SERVER['HTTP_HOST'])? $_SERVER['HTTP_HOST']: "(none)";	// Http Host
echo "<br/>HTTP_REFERER: ";
echo	isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']: "(none)";	// Http Referrer
echo "<br/>REMOTE_ADDR: ";
echo	isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR']: "(none)";	// Remote Address
echo "<br/>HTTP_ORIGIN: ";
echo	isset($_SERVER['HTTP_ORIGIN'])? $_SERVER['HTTP_ORIGIN']: "(none)";	// Http Origin

echo "<br/>";
echo "<br/>";

echo "_SERVER:<br/>";
$n=0;
while ($key = key($_SERVER)) {
$n++;
    echo $n.' '.$key.':'.$_SERVER[$key];
	echo "<br/>";
    next($_SERVER);
}

echo "_GET:<br/>";
$n=0;
while ($key = key($_GET)) {
$n++;
    echo $n.' '.$key.':'.$_GET[$key];
	echo "<br/>";
    next($_GET);
}

echo "_POST:<br/>";
$n=0;
while ($key = key($_POST)) {
$n++;
    echo $n.' '.$key.':'.$_POST[$key];
	echo "<br/>";
    next($_POST);
}

echo "_REQUEST:<br/>";
$n=0;
while ($key = key($_REQUEST)) {
$n++;
    echo $n.' '.$key.':'.$_REQUEST[$key];
	echo "<br/>";
    next($_REQUEST);
}


// "streamContext" gets around the problem of self-signed certificates not being accepted
$streamContext = stream_context_create(
[
'ssl' => [
	'verify_peer'      => false,
	'verify_peer_name' => false
	]
]);

// web.server -> ssp.server
// ------------------------

$B64 = array("+", "/");
$B64url = array("-", "/");
$CRLF = array("\r\n");
$BR = array("<br/>");

echo "<br/>/cps.sqrl";
$cps_token=$_SERVER['QUERY_STRING'];
$cps_url='https://ssp.server:8443/cps.sqrl?'.$cps_token;
echo "<br/>".$cps_url;
$cps_result=file_get_contents($cps_url, false, $streamContext);
echo "<br/>cps_result:<br/>";
if($cps_result!==false) { echo $cps_result;} else {echo "(none)";}
$user="(none)";
$stat="(none)";
$name="(none)";
$acct="(none)";
parse_str($cps_result);
echo "<br/>Parsed:";
echo "<br/> user=".$user;
echo "<br/> stat=".$stat;
echo "<br/> auth'&name'=".base64_decode(str_replace($B64url, $B64, $name));
echo "<br/> acct=".$acct;

echo "<br/>";
echo "<br/>/add.sqrl";
$add_query='acct=TestAccount&user='.$user.'&stat='.$stat.'&name=user-name';
$add_url='https://ssp.server:8443/add.sqrl?'.$add_query;
echo "<br/>".$add_url;
$add_result=file_get_contents($add_url, false, $streamContext);
$add_result=str_replace($CRLF, $BR, $add_result);
echo "<br/>add_result:<br/>";
if($add_result!==false) {
	echo $add_result;
	$add_result_explode =explode("<br/>", $add_result);
	echo "<br/>Parsed:";
	$i=0;
	while ($i<count($add_result_explode)) {
		if(strlen($add_result_explode[$i])==0) break;
		$user="(none)";
		$acct="(none)";
		$name="(none)";
		$stat="(none)";
		$invt="(none)";
		parse_str($add_result_explode[$i]);
		echo "<br/>[".$i."]";
		echo "<br/> user=".$user;
		echo "<br/> acct=".$acct;
		echo "<br/> name=".$name;
		echo "<br/> stat=".$stat;
		echo "<br/> invt=".$invt;
		$i++;
	}
} else {echo "(none)";}

?>

