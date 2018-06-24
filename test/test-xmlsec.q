#!/usr/bin/env qore

# requires the xmlsec module
%requires xmlsec

# requires the xml module
%requires xml

# execute the xmlsec_test class as the application class
%exec-class xmlsec_test

# require all variables to be declared before use
%require-our

# enable all warnings
%enable-all-warnings

namespace xmlsec_test {
    # option defaults
    const defaults = (
	"password"      : "password",       # password to private key
	"certificate"   : "test-cert.pem",  # test certificate name
	"cert_key_file" : "test-key.pem",   # test private key name
	"format"        : True,             # if XML strings should be formatted
	"iters"         : 1,                # test loop iterations per thread
	"threads"       : 1                 # number of concurrent threads
	);

    const opts = 
	( "verbose" : "verbose,v:i+",
	  "help"    : "help,h",
	  "iters"   : "iters,i=i",
	  "format"  : "format,f",
	  "threads" : "threads,t=i" );

    # to create XML encryption template
    const enc_hash = ( "e:TestEncryptedMessage" : 
		       ( "^attributes^" : ( "xmlns:e" : "http://test.local/just_testing" ),
			 "EncryptedData" :
			 ( "^attributes^" : ( "xmlns" : "http://www.w3.org/2001/04/xmlenc#",
					      "Type" : "http://www.w3.org/2001/04/xmlenc#Element" ),
			   "EncryptionMethod" :
			   ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/2001/04/xmlenc#aes256-cbc") ),
			   "KeyInfo" : 
			   ( "^attributes^" : ( "xmlns" : "http://www.w3.org/2000/09/xmldsig#" ),
			     "EncryptedKey" :
			     ( "^attributes^" : ( "xmlns" : "http://www.w3.org/2001/04/xmlenc#" ),
			       "EncryptionMethod" :
			       ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/2001/04/xmlenc#rsa-1_5") ),
			       "KeyInfo" : 
			       ( "^attributes^" : ( "xmlns" : "http://www.w3.org/2000/09/xmldsig#" ),
				 "X509Data" : NOTHING ),
			       "CipherData" : ( "CipherValue" : NOTHING ) ) ),
			   "CipherData" : ( "CipherValue" : NOTHING ) ) ) );
}

class xmlsec_test::xmlsec_test {
    constructor() {
	$.command_line();
	
 	printf("QORE xmlsec module v%s Test Script (%d thread%s, %d iteration%s per thread)\n", XmlSec::ModuleVersion, 
	       $.threads, $.threads == 1 ? "" : "s", 
	       $.iters, $.iters == 1 ? "" : "s");

	$.counter = new Counter();
	my $t = $.threads;
	while ($t--) {
	    $.counter.inc();
	    background $.run_tests();
	}
	
	$.counter.waitForZero();

	my $ntests = elements $.thash;
	printf("%d error%s encountered in %d unique test%s in %d iteration%s (%d thread%s).\n",
	       $.errors, $.errors == 1 ? "" : "s", 
	       $ntests, $ntests == 1 ? "" : "s",
	       $.ip, $.ip == 1 ? "" : "s",
	       $.threads, $.threads == 1 ? "" : "s");
    }

    run_tests() {
	on_error ++$.errors;
	on_exit $.counter.dec();

	my $str;

	for (my $i = 0; $i < $.iters; $i++) {
	    my $template = $.get_signature_template("1.0", "hello there, testing");

	    # sign the string with the certificate's private key
	    $str = XmlSec::sign($template, $.cert_key);
	    if ($.verbose)
		printf("signed message:\n%s\n", $str);
	    
	    $.test_value(True, True, "XmlSec::sign()");

	    # verify the signature
	    XmlSec::verify($str, $.cert_key);
	    $.test_value(True, True, "XmlSec::verify()");
	    
	    my $estr;

	    # encrypt the signed message with a session key using the private key and certificate
	    $estr = XmlSec::encrypt($str, $.enc_tmpl, $.session_key, $.mgr);
	    if ($.verbose)
		printf("encrypted message:\n%s\n", $estr);

	    $.test_value(True, True, "XmlSec::encrypt()");

	    # decrypt the message and compare to the original
	    my $dstr = XmlSec::decrypt($estr, $.mgr);
	    $.test_value($dstr, $str, "XmlSec::decrypt()");
	
	    $.ip += 1;
	}
    }

    static usage() {
	# get script name
	my $pn = split("/", $ENV."_");
	$pn = pop $pn; #$l[elements $l - 1];

	printf(
	    "usage: %s [options] <iterations>
  -h,--help         shows this help text
  -f,--format       format XML output seen with --verbose
  -i,--iters=ARG    runs ARG iterations of the tests in each thread
  -t,--threads=ARG  runs tests in ARG threads
  -v,--verbose=ARG  sets verbosity level to ARG
", 
	    $pn);
	exit(1);
    }

    private command_line() {
	my $g = new GetOpt(opts);
	my $o = $g.parse(\$ARGV);
	if (exists $o."_ERRORS_") {
	    printf("%s\n", $o."_ERRORS_"[0]);
	    exit(1);
	}
	if ($o.help)
	    xmlsec_test::usage();

	# the file name of the certificate to use
	if (!exists $o.certificate)
	    $o.certificate = defaults.certificate;

	# the file name of the private key for the certificate
	if (!exists $o.cert_key_file)
	    $o.cert_key_file = defaults.cert_key_file;

	# the password to the private key
	if (!exists $o.password)
	    $o.password = defaults.password;

	$.verbose = $o.verbose;

	# number of iterations
	$.iters = exists $o.iters ? $o.iters : defaults.iters;

	# number of threads
	$.threads = exists $o.threads ? $o.threads : defaults.threads;

	# set to False to make compact XML without formatting
	$.format = exists $o.format ? $o.format : defaults.format;

	# set up encoding template XML string (enc_hash defined below)
	$.enc_tmpl = $.format ? makeFormattedXMLString(enc_hash) : makeXMLString(enc_hash);

	# create session key
	$.session_key = new XmlSecKey(xmlSecKeyDataAesId, 256, xmlSecKeyDataTypeSession);

	# set up encryption key for certificate
	$.cert_key = new XmlSecKey(xmlsec_test::get_file($o.cert_key_file), xmlSecKeyDataFormatPem, $o.password);
	$.cert_key.setCertificate(xmlsec_test::get_file($o.certificate), xmlSecKeyDataFormatCertPem);

	# set up key manager
	$.mgr = new XmlSecKeyManager();
	$.mgr.addKey($.cert_key);
    }

    # returns the signature template XML string created from some example parameters
    get_signature_template($ver, $body) {
	# this template uses several transformations including an XPath specification
	# to sign the e:Body and e:SenderDetails parts of the tree 
	my $h = ( "e:TestSignedMessage" :
		  ( "^attributes^" : ( "xmlns:e" : "http://test.local/just_testing" ),
		    "e:SenderDetails" :
		    ( "e:TestEnvelopeVersion" : $ver,
		      "e:Sender" :
		      ( "e:URI" : "http://test.local/test",
			"e:Authentication" :
			( "Signature" :
			  ( "^attributes^" : ( "xmlns" : "http://www.w3.org/2000/09/xmldsig#" ),
			    "SignedInfo" :
			    ( "CanonicalizationMethod" :
			      ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ) ),
			      "SignatureMethod" :
			      ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/2000/09/xmldsig#rsa-sha1" ) ),
			      "Reference" :
			      ( "^attributes^" : ( "URI" : NOTHING ),
				"Transforms" :
				( "Transform" :
				  ( ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/2000/09/xmldsig#enveloped-signature" ) ),
				    ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/TR/1999/REC-xpath-19991116" ),
				      "XPath" :
				      ( "^attributes^" : ( "xmlns:e" : "http://test.local/just_testing" ),
					"^value^" : "ancestor-or-self::e:Body|ancestor-or-self::e:SenderDetails" ) ),
				    ( "^attributes^" : ( "Algorithm" : "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" ) ) ) ),
				"DigestMethod" :
				( "^attributes^" : ( "Algorithm" : "http://www.w3.org/2000/09/xmldsig#sha1" ) ),
				"DigestValue" : NOTHING ) ),
			    "SignatureValue" : NOTHING,
			    "KeyInfo" :
			    ( "X509Data" : NOTHING ) ) ) ) ),
		    "e:Body" : $body ) );
	
	return $.format ? makeFormattedXMLString($h) : makeXMLString($h);
    }

    static get_file($fn) {
	my $f = new File();
	$f.open2($fn);
	return $f.read(-1);
    }

    static get_file_bin($fn) {
	my $f = new File();
	$f.open2($fn);
	return $f.readBinary(-1);
    }

    test_value($v1, $v2, $msg) {
	if ($v1 === $v2) {
	    if ($.verbose)
		printf("OK: %s test\n", $msg);
	}
	else {
	    printf("ERROR: %s test failed! (%N != %N)\n", $msg, $v1, $v2);
	    $.errors++;
	}
	$.thash.$msg = True;
    }
}
