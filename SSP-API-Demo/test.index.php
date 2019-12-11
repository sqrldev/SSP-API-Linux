
<?php

echo "PHP Extension sspphp loaded = ";
var_dump(extension_loaded('sspphp'));

echo "<br>";
sspapiOpenLibrary();

echo "<br>";
sspapiPing();

echo "<br>";
//sspapiResetCounter();

echo "<br>";
sspapiInitSqrlCfgData();

echo "<br>";
sspapiInitSqrlSystem();

echo "<br><br>";

$NutLen=16;
$MyArray = array(
	"GET",								// Method
	"/nut.sqrl",							// Path Info
	isset($_SERVER['QUERY_STRING'])? $_SERVER['QUERY_STRING']: "",	// Query String
	isset($_SERVER['CONTENT_LENGTH'])? intval($_SERVER['CONTENT_LENGTH']): 0, // Data Length
	"",								// Data String
	isset($_SERVER['HTTP_HOST'])? $_SERVER['HTTP_HOST']: "",	// Http Host
	isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']: "",	// Http Referrer
	isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR']: "",	// Remote Address
	isset($_SERVER['HTTP_ORIGIN'])? $_SERVER['HTTP_ORIGIN']: "",	// Http Origin
	isset($_SERVER['SERVER_PORT'])? $_SERVER['SERVER_PORT']: ""	// Server Port
);
$Return=sspapiSendRequest($MyArray);
echo "<br><br>";

$NutEq=substr($Return[1], 0, $NutLen);
printf("Returned Headers (len=%d):<br>%s", strlen($Return[0]), $Return[0]);
echo "<br><br>";

$Len=$Return[2];
$Data=substr($Return[1], 0, $Len);
printf("Returned Data (len=%d):<br>", $Len);
print_r($Data);
echo "<br><br>";

$MyArray = array(
	"GET",								// Method
	"/png.sqrl",							// Path Info
	$NutEq,								// Query String
	isset($_SERVER['CONTENT_LENGTH'])? intval($_SERVER['CONTENT_LENGTH']): 0, // Data Length
	"",								// Data String
	isset($_SERVER['HTTP_HOST'])? $_SERVER['HTTP_HOST']: "",	// Http Host
	isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']: "",	// Http Referrer
	isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR']: "",	// Remote Address
	isset($_SERVER['HTTP_ORIGIN'])? $_SERVER['HTTP_ORIGIN']: "",	// Http Origin
	isset($_SERVER['SERVER_PORT'])? $_SERVER['SERVER_PORT']: ""	// Server Port
);
$Return=sspapiSendRequest($MyArray);
echo "<br><br>";

$NutEq=substr($Return[1], 0, $NutLen);
printf("Returned Headers (len=%d):<br>%s", strlen($Return[0]), $Return[0]);
echo "<br><br>";

$Len=$Return[2];
$Data=substr($Return[1], 0, $Len);
printf("Returned Data (len=%d):<br>", $Len);
print_r($Data);
echo "<br><br>";

sspapiCloseLibrary();
echo "<br><br>";

?>

