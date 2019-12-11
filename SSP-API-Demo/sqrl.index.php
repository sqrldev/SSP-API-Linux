<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>
   GRC SQRL Service Provider API for Linux Test/Demo
  </title>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
 </head>

 <body>
  <div align="center">
   <form method="post" autocomplete="off">
    <div>
     http:// <img src="_" id="probe" alt="probe"> image
    </div>

    <br>
    <div>
     <a id="sqrl" tabindex="-1" onclick="gifProbe.onerror();return true;">
      <button type="button" tabindex="-1"> <big><big><big>Sign In with SQRL</big></big></big>
      </button>
     </a>
    </div>

    <br>
    <div>
     Or Scan the QR Code
    </div>

    <br>
    <div>
     <img src="_" id="qrimg" alt="QR Code">
    <br>
     <a id="qrtxt"></a>
    </div>

    <br>
    <div>
     <a href="https://ssp.server:8443/add.sqrl?acct=TestAccount&user=&stat=&name=">
      <button type="button"><big><big>Show TestAccount</big></big></button>
     </a>
    </div>

    <br>
    <div>
     <a href="https://ssp.server:8443/pnd.sqrl">
      <button type="button"><big><big>List Pending Auths</big></big></button>
     </a>
    </div>

    <br>
    <div>
     <a href="https://ssp.server:8443/sup.sqrl">
      <button type="button"><big><big>List Superseded IDs</big></big></button>
     </a>
    </div>

    <br>
    <div>
     <a href="https://ssp.server:8443/bdb.sqrl">
      <button type="button"><big><big>List Database</big></big></button>
     </a>
    </div>

    <br>
    <div>
     <a href="https://ssp.server:8443/end.sqrl">
      <button type="button"><big><big>Shut Down</big></big></button>
     </a>
    </div>

   </form>	 

   <script>

var syncQuery1 = window.XMLHttpRequest ? new window.XMLHttpRequest() : new ActiveXObject('MSXML2.XMLHTTP.3.0');
var syncQuery2 = window.XMLHttpRequest ? new window.XMLHttpRequest() : new ActiveXObject('MSXML2.XMLHTTP.3.0');
var mixedProbe = new Image();
var gifProbe = new Image(); 					// create an instance of a memory-based probe image
var localhostRoot = 'http://localhost:25519/';	// the SQRL client listening URL root

var sqrlApiDomain = 'https://ssp.server:8443';	// the location of the SQRL server

var imageProbeUrl = 'http://www.rebindtest.com/open.gif';
Date.now = Date.now || function() { return (+new Date()) };	// add old browser Date.now() support
var sqrlNut, sqrlUrl, sqrlPng;

function getSqrlNut() {
	syncQuery2.open( 'GET', sqrlApiDomain + '/nut.sqrl' );		// the page's DOM is loaded
	syncQuery2.onreadystatechange = function() {
		if ( syncQuery2.readyState === 4 ) {
			if ( syncQuery2.status === 200 ) {
				sqrlNut = syncQuery2.responseText;
				sqrlUrl = sqrlApiDomain.replace('https:','sqrl:') + '/cli.sqrl?' + sqrlNut;
				sqrlNut = sqrlNut.substr(sqrlNut.indexOf("nut="), 16);	// trim for just the 'nut={...}'
				sqrlQrc = sqrlApiDomain.replace('https:','sqrl:') + '/cli.sqrl?' + sqrlNut;
				sqrlPng = sqrlApiDomain + '/png.sqrl?' + sqrlNut;

				if (x = document.getElementById("sqrl")) x.href = sqrlUrl;
				if (x = document.getElementById("qrimg")) x.src = sqrlPng;
				if (x = document.getElementById("qrtxt")) x.text = sqrlQrc;
//				pollForNextPage();	// start our next page checking
				} else {
				setTimeout(getSqrlNut, 10000); // if our request for a /nut.sqrl fails, wait 10msec and retry
			}
		}	
	};
	syncQuery2.send(); // initiate the query to obtain the page's SQRL nut
};

function pollForNextPage() {
	if (document.hidden) {					// before probing for any page change, we check to 
		setTimeout(pollForNextPage, 3000);	// see whether the page is visible. If the user is 
		return;								// not viewing the page, check again in 5 seconds.
	}
	syncQuery1.open( 'GET', sqrlApiDomain + '/pag.sqrl?' + sqrlNut );	// the page is visible, so let's check for any update
	syncQuery1.onreadystatechange = function() {
		if ( syncQuery1.readyState === 4 ) {
			if ( syncQuery1.status === 250 ) {
				var cpsUrl = syncQuery1.responseText
				document.location.href = cpsUrl;
			} else {
				setTimeout(pollForNextPage, 3000); // if we do not obtain a /pag.sqrl, wait 1/2 second and retry
			}
		}	
	};
	syncQuery1.send(); // initiate the query to the 'sync.txt' object.
};

getSqrlNut(); // get a fresh nut for the page, setup URLs and begin probing for any page change.

function showMessage() { document.getElementById("mixed").style.display = "block" };
probeImage = document.getElementById("probe");
setTimeout( function(){ if ( probeImage.height == 0 ) showMessage() }, 2000 );
probeImage.onerror = function() { showMessage() };
probeImage.src = imageProbeUrl;

gifProbe.onload = function() {  // define our load-success function
	// base64url-encode our CPS-jump URL. This replaces '/' with '_' and '+' with '-' and removes all trailing '='s
	var encodedSqrlUrl = window.btoa(sqrlUrl).replace(/\//,"_").replace(/\+/,"-").replace(/=+$/,"");
	document.location.href = localhostRoot + encodedSqrlUrl;
};

gifProbe.onerror = function() { // define our load-failure function
	setTimeout( function(){ gifProbe.src = localhostRoot + Date.now() + '.gif';	}, 100 );
};
 
   </script>
  </div> 
 </body>
</html>
