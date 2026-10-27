<?php
#20261027184235
use Symfony\Polyfill\Php80 as p;
if(\PHP_VERSION_ID>=80000){
return;
}
if(!defined('FILTER_VALIDATE_BOOL')&&defined('FILTER_VALIDATE_BOOLEAN')){
define('FILTER_VALIDATE_BOOL',\FILTER_VALIDATE_BOOLEAN);
}
if(!function_exists('fdiv')){
function fdiv(float$num1,float$num2):float{return p\Php80::fdiv($num1,$num2);}
}
if(!function_exists('preg_last_error_msg')){
function preg_last_error_msg():string{return p\Php80::preg_last_error_msg();}
}
if(!function_exists('str_contains')){
function str_contains(?string$haystack,?string$needle):bool{return p\Php80::str_contains($haystack??'',$needle??'');}
}
if(!function_exists('str_starts_with')){
function str_starts_with(?string$haystack,?string$needle):bool{return p\Php80::str_starts_with($haystack??'',$needle??'');}
}
if(!function_exists('str_ends_with')){
function str_ends_with(?string$haystack,?string$needle):bool{return p\Php80::str_ends_with($haystack??'',$needle??'');}
}
if(!function_exists('get_debug_type')){
function get_debug_type($value):string{return p\Php80::get_debug_type($value);}
}
if(!function_exists('get_resource_id')){
function get_resource_id($resource):int{return p\Php80::get_resource_id($resource);}
}
use Symfony\Polyfill\Php82 as p;
if(\PHP_VERSION_ID>=80200){
return;
}
if(\extension_loaded('curl')&&!defined('CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256')&&curl_version()['version_number']>=479232){
define('CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256',10311);
}
if(extension_loaded('odbc')){
if(!function_exists('odbc_connection_string_is_quoted')){
function odbc_connection_string_is_quoted(string$str):bool{return p\Php82::odbc_connection_string_is_quoted($str);}
}
if(!function_exists('odbc_connection_string_should_quote')){
function odbc_connection_string_should_quote(string$str):bool{return p\Php82::odbc_connection_string_should_quote($str);}
}
if(!function_exists('odbc_connection_string_quote')){
function odbc_connection_string_quote(string$str):string{return p\Php82::odbc_connection_string_quote($str);}
}
}
if(!function_exists('ini_parse_quantity')){
function ini_parse_quantity(string$shorthand):int{return p\Php82::ini_parse_quantity($shorthand);}
}
if(!function_exists('trigger_deprecation')){
function trigger_deprecation(string$package,string$version,string$message,...$args):void
{
@trigger_error(($package||$version?"Since $package $version: ":'').($args?vsprintf($message,$args):$message),\E_USER_DEPRECATED);
}
}
namespace Akrez\HttpProxy;
class Config
{
protected?string$method=null;
protected?string$scheme=null;
protected bool$debug=false;
protected bool$base64=false;
protected int$timeout=60;
function method():?string
{
return$this->method;
}
function scheme():?string
{
return$this->scheme;
}
function debug():bool
{
return$this->debug;
}
function base64():bool
{
return$this->base64;
}
function timeout():int
{
return$this->timeout;
}
function setMethod(?string$method):self
{
$this->method=$method;
return$this;
}
function setScheme(?string$scheme):self
{
$this->scheme=$scheme;
return$this;
}
function setDebug(bool$debug):self
{
$this->debug=$debug;
return$this;
}
function setBase64(bool$base64):self
{
$this->base64=$base64;
return$this;
}
function setTimeout(int$timeout):self
{
$this->timeout=$timeout;
return$this;
}
function setByConfigString(string$configString){
$configs=$this->sanitizeConfig($configString);
return$this
->setMethod($configs['method'])->setScheme($configs['scheme'])->setDebug($configs['debug'])->setBase64($configs['base64'])->setTimeout($configs['timeout']);
}
protected function sanitizeConfig(string$configString):array
{
$configs=explode('_',strtolower($configString));
return['method'=>$this->findInArray($configs,['get','post','head','put','delete','options','trace','connect','patch']),'scheme'=>$this->findInArray($configs,['https','http']),'debug'=>$this->findInArray($configs,['debug'])==='debug','base64'=>$this->findInArray($configs,['base64'])==='base64','timeout'=>60,];
}
protected function findInArray(array$needles,array$haystack,?string$default=null):?string
{
foreach($needles as$needle){
if(in_array($needle,$haystack)){
return$needle;
}
}
return$default;
}
}
namespace Akrez\HttpProxy;
use GuzzleHttp\Psr7\Message;
use Psr\Http\Message\RequestInterface;
class CurlStreamer
{
function send(RequestInterface$request,Config$config){
if($request->getMethod()==='CONNECT'){
return;
}
if($config->debug()){
echo nl2br(Message::toString($request));
return;
}
$url=(string)$request->getUri();
$headers=[];
foreach($request->getHeaders()as$name=>$values){
$headers[]=$name.': '.join('; ',$values);
}
$options=[CURLOPT_CONNECTTIMEOUT=>$config->timeout(),CURLOPT_TIMEOUT=>$config->timeout(),CURLOPT_RETURNTRANSFER=>false,CURLOPT_HEADER=>false,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>false,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_AUTOREFERER=>false,CURLOPT_HEADERFUNCTION=>[$this,'headerCallback'],CURLOPT_WRITEFUNCTION=>[$this,'writeCallback'],CURLOPT_FORBID_REUSE=>true,CURLOPT_FRESH_CONNECT=>true,CURLOPT_URL=>$url,CURLOPT_CUSTOMREQUEST=>$request->getMethod(),CURLOPT_POSTFIELDS=>(string)$request->getBody(),CURLOPT_HTTPHEADER=>$headers,CURLOPT_HTTP_CONTENT_DECODING=>false,CURLOPT_HTTP_VERSION=>CURL_HTTP_VERSION_1_1,];
$ch=curl_init();
curl_setopt_array($ch,$options);
curl_exec($ch);
}
protected function headerCallback($ch,$headers){
$parts=explode(':',$headers,2);
if(count($parts)==2){
if(in_array(strtolower($parts[0]),[])){
}else{
header($headers,false);
}
}elseif(preg_match('/HTTP\/[\d.]+\s*(\d+)/',$headers,$matches)){
http_response_code($matches[1]);
}else{
}
return strlen($headers);
}
protected function writeCallback($ch,$str){
$len=strlen($str);
echo$str;
flush();
return$len;
}
}
namespace Akrez\HttpProxy;
use Exception;
use GuzzleHttp\Psr7\MultipartStream;
use GuzzleHttp\Psr7\Uri;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
class InlineInitiator
{
protected?Config$config=null;
function config():?Config
{
return$this->config;
}
protected?RequestInterface$request=null;
function request():?RequestInterface
{
return$this->request;
}
function __construct(protected ServerRequestInterface$serverRequest,){}
function initiate():bool
{
try{
$this->request=null;
$this->config=null;
$serverRequest=$this->serverRequest;
$configStringHostPath=$this->extractConfigStringHostPath($serverRequest);
if($configStringHostPath===null){
return false;
}
[0=>$configString,1=>$hostPath,]=explode('/',$configStringHostPath,2)+[0=>'',1=>''];
if(empty($hostPath)){
return false;
}
$config=(new Config)->setByConfigString($configString);
$scheme=$config->scheme()?:$serverRequest->getUri()->getScheme();
if($config->base64()){
$decodedHostPath=base64_decode(rawurldecode($hostPath),true);
$newUri=new Uri($scheme.'://'.$decodedHostPath);
}else{
$newUri=new Uri($scheme.'://'.$hostPath);
$newUri=$newUri->withQuery($serverRequest->getUri()->getQuery());
}
$newRequest=clone$serverRequest;
$newRequest=$newRequest->withUri($newUri);
if($config->method()){
$newRequest=$newRequest->withMethod($config->method());
}
$multipartBoundary=$this->getMultipartBoundary($serverRequest);
if($multipartBoundary){
$newRequest=$newRequest->withBody($this->getMultipartStream($multipartBoundary,$serverRequest));
}
$newRequest=$this->filterAcceptEncoding($newRequest);
$this->request=$newRequest;
$this->config=$config;
return true;
}catch(Exception$e){
}
return false;
}
protected function extractConfigStringHostPath(ServerRequestInterface$globalServerRequest):?string
{
['REQUEST_URI'=>$requestUri,'SCRIPT_NAME'=>$scriptName,]=$globalServerRequest->getServerParams()+['SCRIPT_NAME'=>null,'REQUEST_URI'=>null];
if(is_string($requestUri)&&is_string($scriptName)&&
($requestUri!=='')&&($scriptName!=='')&&
(strpos($requestUri,$scriptName)===0)){
$url=substr($requestUri,strlen($scriptName));
return ltrim($url," \n\r\t\v\0/");
}
return;
}
protected function getMultipartBoundary(ServerRequestInterface$globalServerRequest):?string
{
$contentType=$globalServerRequest->getHeaderLine('Content-Type');
if(strpos($contentType,'multipart/form-data')===0 and
preg_match('/boundary=(.*)$/',$contentType,$matches)){
return trim($matches[1],'"');
}
return;
}
protected function getMultipartStream(string$multipartBoundary,ServerRequestInterface$globalServerRequest){
$elements=[];
foreach($globalServerRequest->getParsedBody()as$key=>$value){
$elements[]=['name'=>$key,'contents'=>$value,];
}
foreach($globalServerRequest->getUploadedFiles()as$key=>$value){
if(empty($value->getError())){
$elements[]=['name'=>$key,'filename'=>$value->getClientFilename(),'contents'=>$value->getStream(),];
}
}
return new MultipartStream($elements,$multipartBoundary);
}
protected function filterAcceptEncoding(RequestInterface$request){
if(!$request->hasHeader('Accept-Encoding')){
return$request;
}
$supportedEncodings=['identity'];
if(function_exists('gzdecode')){
$supportedEncodings[]='gzip';
}
if(function_exists('gzinflate')){
$supportedEncodings[]='deflate';
}
if(function_exists('brotli_uncompress')){
$supportedEncodings[]='br';
}
if(function_exists('zstd_uncompress')){
$supportedEncodings[]='zstd';
}
$clientEncodings=array_map('trim',explode(',',$request->getHeaderLine('Accept-Encoding')));
$filtered=[];
foreach($clientEncodings as$encoding){
$name=strtolower(trim(explode(';',$encoding)[0]));
if(in_array($name,$supportedEncodings,true)){
$filtered[]=$encoding;
}
}
if(empty($filtered)){
$filtered[]='identity';
}
return$request
->withoutHeader('Accept-Encoding')->withHeader('Accept-Encoding',join(', ',$filtered));
}
}
namespace Akrez\HttpProxy;
use Psr\Http\Message\ServerRequestInterface;
class Proxy
{
static function inlineCurl(ServerRequestInterface$serverRequest){
$inlineinitiator=new InlineInitiator($serverRequest);
$curlStreamer=new CurlStreamer;
$canInitiate=$inlineinitiator->initiate();
if(!$canInitiate){
return false;
}
$request=$inlineinitiator->request();
$curlStreamer->send($request,$inlineinitiator->config());
return true;
}
}
namespace Composer;
use Composer\Autoload\ClassLoader;
use Composer\Semver\VersionParser;
class InstalledVersions
{
private static$selfDir=null;
private static$installed;
private static$installedIsLocalDir;
private static$canGetVendors;
private static$installedByVendor=array();
static function getInstalledPackages(){
$packages=array();
foreach(self::getInstalled()as$installed){
$packages[]=array_keys($installed['versions']);
}
if(1===\count($packages)){
return$packages[0];
}
return array_keys(array_flip(\call_user_func_array('array_merge',$packages)));
}
static function getInstalledPackagesByType($type){
$packagesByType=array();
foreach(self::getInstalled()as$installed){
foreach($installed['versions']as$name=>$package){
if(isset($package['type'])&&$package['type']===$type){
$packagesByType[]=$name;
}
}
}
return$packagesByType;
}
static function isInstalled($packageName,$includeDevRequirements=true){
foreach(self::getInstalled()as$installed){
if(isset($installed['versions'][$packageName])){
return$includeDevRequirements||!isset($installed['versions'][$packageName]['dev_requirement'])||$installed['versions'][$packageName]['dev_requirement']===false;
}
}
return false;
}
static function satisfies(VersionParser$parser,$packageName,$constraint){
$constraint=$parser->parseConstraints((string)$constraint);
$provided=$parser->parseConstraints(self::getVersionRanges($packageName));
return$provided->matches($constraint);
}
static function getVersionRanges($packageName){
foreach(self::getInstalled()as$installed){
if(!isset($installed['versions'][$packageName])){
continue;
}
$ranges=array();
if(isset($installed['versions'][$packageName]['pretty_version'])){
$ranges[]=$installed['versions'][$packageName]['pretty_version'];
}
if(key_exists('aliases',$installed['versions'][$packageName])){
$ranges=array_merge($ranges,$installed['versions'][$packageName]['aliases']);
}
if(key_exists('replaced',$installed['versions'][$packageName])){
$ranges=array_merge($ranges,$installed['versions'][$packageName]['replaced']);
}
if(key_exists('provided',$installed['versions'][$packageName])){
$ranges=array_merge($ranges,$installed['versions'][$packageName]['provided']);
}
return join(' || ',$ranges);
}
throw new\OutOfBoundsException('Package "'.$packageName.'" is not installed');
}
static function getVersion($packageName){
foreach(self::getInstalled()as$installed){
if(!isset($installed['versions'][$packageName])){
continue;
}
if(!isset($installed['versions'][$packageName]['version'])){
return;
}
return$installed['versions'][$packageName]['version'];
}
throw new\OutOfBoundsException('Package "'.$packageName.'" is not installed');
}
static function getPrettyVersion($packageName){
foreach(self::getInstalled()as$installed){
if(!isset($installed['versions'][$packageName])){
continue;
}
if(!isset($installed['versions'][$packageName]['pretty_version'])){
return;
}
return$installed['versions'][$packageName]['pretty_version'];
}
throw new\OutOfBoundsException('Package "'.$packageName.'" is not installed');
}
static function getReference($packageName){
foreach(self::getInstalled()as$installed){
if(!isset($installed['versions'][$packageName])){
continue;
}
if(!isset($installed['versions'][$packageName]['reference'])){
return;
}
return$installed['versions'][$packageName]['reference'];
}
throw new\OutOfBoundsException('Package "'.$packageName.'" is not installed');
}
static function getInstallPath($packageName){
foreach(self::getInstalled()as$installed){
if(!isset($installed['versions'][$packageName])){
continue;
}
return isset($installed['versions'][$packageName]['install_path'])?$installed['versions'][$packageName]['install_path']:null;
}
throw new\OutOfBoundsException('Package "'.$packageName.'" is not installed');
}
static function getRootPackage(){
$installed=self::getInstalled();
return$installed[0]['root'];
}
static function getRawData(){
@trigger_error('getRawData only returns the first dataset loaded, which may not be what you expect. Use getAllRawData() instead which returns all datasets for all autoloaders present in the process.',E_USER_DEPRECATED);
if(null===self::$installed){
if(substr(__DIR__,-8,1)!=='C'){
self::$installed=include __DIR__.'/installed.php';
}else{
self::$installed=array();
}
}
return self::$installed;
}
static function getAllRawData(){
return self::getInstalled();
}
static function reload($data){
self::$installed=$data;
self::$installedByVendor=array();
self::$installedIsLocalDir=false;
}
private static function getSelfDir(){
if(self::$selfDir===null){
self::$selfDir=strtr(__DIR__,'\\','/');
}
return self::$selfDir;
}
private static function getInstalled(){
if(null===self::$canGetVendors){
self::$canGetVendors=method_exists('Composer\Autoload\ClassLoader','getRegisteredLoaders');
}
$installed=array();
$copiedLocalDir=false;
if(self::$canGetVendors){
$selfDir=self::getSelfDir();
foreach(ClassLoader::getRegisteredLoaders()as$vendorDir=>$loader){
$vendorDir=strtr($vendorDir,'\\','/');
if(isset(self::$installedByVendor[$vendorDir])){
$installed[]=self::$installedByVendor[$vendorDir];
}elseif(is_file($vendorDir.'/composer/installed.php')){
$required=require$vendorDir.'/composer/installed.php';
self::$installedByVendor[$vendorDir]=$required;
$installed[]=$required;
if(self::$installed===null&&$vendorDir.'/composer'===$selfDir){
self::$installed=$required;
self::$installedIsLocalDir=true;
}
}
if(self::$installedIsLocalDir&&$vendorDir.'/composer'===$selfDir){
$copiedLocalDir=true;
}
}
}
if(null===self::$installed){
if(substr(__DIR__,-8,1)!=='C'){
$required=require __DIR__.'/installed.php';
self::$installed=$required;
}else{
self::$installed=array();
}
}
if(self::$installed!==array()&&!$copiedLocalDir){
$installed[]=self::$installed;
}
return$installed;
}
}
declare(strict_types=1);
namespace GuzzleHttp;
trait NonSerializableTrait
{
function __serialize():array
{
throw new\LogicException(static::class.' should never be serialized');
}
function __unserialize(array$data):void
{
throw new\LogicException(static::class.' should never be unserialized');
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Auth\DigestAuth;
use GuzzleHttp\Auth\DigestChallenge;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\LazyOpenStream;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
final class AuthMiddleware
{
use NonSerializableTrait;
private const DIGEST_MAX_RETRIES=2;
private const CHALLENGE_CACHE_LIMIT=32;
private const DIGEST_NONCE_COUNTS_OPTION='__guzzle_digest_nonce_counts';
private const DIGEST_PROBE_PAYLOAD_HEADERS=['Transfer-Encoding','Expect','Trailer','Content-Range','Content-Encoding','Content-MD5','Digest','Content-Digest','Repr-Digest',];
private$nextHandler;
private$cnonceGenerator;
private bool$reuseChallenges;
private?string$credentialHashSecret=null;
private array$digestChallenges=[];
function __construct(callable$nextHandler,?callable$cnonceGenerator=null,bool$reuseChallenges=true){
$this->nextHandler=$nextHandler;
$this->cnonceGenerator=$cnonceGenerator??static function():string{
return\bin2hex(\random_bytes(16));
};
$this->reuseChallenges=$reuseChallenges;
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$auth=$options['auth']??null;
if($auth===null||$auth===false||$auth===[]||\is_string($auth)){
return($this->nextHandler)($request,$options);
}
$normalizedAuth=self::normalizeAuth($auth);
if($normalizedAuth===null){
return($this->nextHandler)($request,$options);
}
[$username,$password,$type]=$normalizedAuth;
if($type==='basic'){
return$this->sendBasic($request,$options,$username,$password);
}
return$this->sendDigest($request,$options,$username,$password);
}
private static function normalizeAuth(#[\SensitiveParameter]array$auth
):?array{
$type='basic';
if(\array_key_exists(2,$auth)&&$auth[2]!==null){
if(!\is_string($auth[2])){
throw new InvalidArgumentException('auth type must be a string');
}
$type=Psr7\Utils::asciiToLower($auth[2]);
}
if(!\in_array($type,['basic','digest'],true)){
return;
}
if(!\array_key_exists(0,$auth)||!\array_key_exists(1,$auth)){
throw new InvalidArgumentException('auth must contain username and password strings');
}
if(!\is_string($auth[0])||!\is_string($auth[1])){
throw new InvalidArgumentException('auth must contain username and password strings');
}
return[$auth[0],$auth[1],$type];
}
private function sendBasic(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,string$username,#[\SensitiveParameter]string$password
):PromiseInterface{
if(\strpos($username,':')!==false){
throw new InvalidArgumentException('Basic authentication username must not contain a colon');
}
if(\preg_match('/[\x00-\x1F\x7F]/',$username.$password)!==0){
throw new InvalidArgumentException('Basic authentication credentials must not contain ASCII control characters');
}
unset($options['auth']);
return($this->nextHandler)($request->withHeader('Authorization','Basic '.\base64_encode($username.':'.$password)),$options
);
}
private function sendDigest(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,string$username,#[\SensitiveParameter]string$password
):PromiseInterface{
$preemptive=$this->reuseChallenges
?$this->preemptiveDigestRequest($request,$username,$password):null;
if($preemptive!==null){
$preemptiveOptions=self::withTemporarySink($options);
unset($preemptiveOptions['auth']);
return($this->nextHandler)($preemptive,$preemptiveOptions)->then(function(#[\SensitiveParameter]ResponseInterface$response
)use($request,$options,$preemptiveOptions,$username,$password){
$status=$response->getStatusCode();
if($status>=400&&$status!==401){
$this->clearDigestChallenge($request);
}
return$this->handleDigestResponse($request,$options,$preemptiveOptions,$response,$username,$password,false);
},function(#[\SensitiveParameter]$reason
)use($request,$preemptiveOptions){
return$this->handleDigestRejection($request,$preemptiveOptions,$reason,true);
}
);
}
$probeOptions=self::withTemporarySink($options);
unset($probeOptions['auth']);
[$probeRequest,$bodyWithheld]=self::probeRequest($request,$options);
if($bodyWithheld){
$probeOptions[RequestOptions::EXPECT]=false;
}
return($this->nextHandler)($probeRequest,$probeOptions)->then(function(#[\SensitiveParameter]ResponseInterface$response
)use($request,$options,$probeOptions,$username,$password,$bodyWithheld){
return$this->handleDigestResponse($request,$options,$probeOptions,$response,$username,$password,$bodyWithheld);
},function(#[\SensitiveParameter]$reason
)use($request,$probeOptions){
return$this->handleDigestRejection($request,$probeOptions,$reason,false);
}
);
}
private function preemptiveDigestRequest(#[\SensitiveParameter]RequestInterface$request,string$username,#[\SensitiveParameter]string$password
):?RequestInterface{
try{
if($request->getBody()->getSize()!==0){
return;
}
}catch(\Exception$e){
return;
}
$key=self::digestCacheKey($request);
if($key===null){
return;
}
$entry=$this->digestChallenges[$key]??null;
if($entry===null
||$entry['credentials']!==$this->digestCredentialKey($username,$password)||!self::challengeCoversRequest($entry['challenge'],$request)){
return;
}
$authorization=DigestAuth::authorizationHeader($request,$entry['challenge'],$username,$password,($this->cnonceGenerator)(),\sprintf('%08x',$entry['nextNc']));
if($authorization===null){
return;
}
++$this->digestChallenges[$key]['nextNc'];
return$request->withHeader('Authorization',$authorization);
}
private static function probeRequest(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):array{
$probe=$request->withoutHeader('Authorization');
try{
$size=$probe->getBody()->getSize();
}catch(\Exception$e){
$size=null;
}
if($size===0){
return[$probe,false];
}
$streamFactory=self::requireStreamFactory($options[RequestOptions::STREAM_FACTORY]??new HttpFactory
);
$probe=$probe->withBody($streamFactory->createStream(''))->withHeader('Content-Length','0');
foreach(self::DIGEST_PROBE_PAYLOAD_HEADERS as$header){
$probe=$probe->withoutHeader($header);
}
return[$probe,true];
}
private function handleDigestResponse(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]array$probeOptions,#[\SensitiveParameter]ResponseInterface$response,string$username,#[\SensitiveParameter]string$password,bool$bodyWithheld
){
$status=$response->getStatusCode();
$previousEntry=null;
if($this->reuseChallenges&&$status===401){
$key=self::digestCacheKey($request);
$previousEntry=$key!==null?($this->digestChallenges[$key]??null):null;
$this->clearDigestChallenge($request);
}
if($status!==401){
if($this->reuseChallenges&&$response->hasHeader('Authentication-Info')){
$this->clearDigestChallenge($request);
}
$response=self::restoreOriginalSink($request,$response,$probeOptions);
if($bodyWithheld&&$status!==407&&!self::isRedirectLikeResponse($response)){
throw new ResponseException('Digest authentication failed because the server did not issue a challenge; the request was probed without its body',$request,$response
);
}
return$response;
}
$challenge=DigestAuth::selectChallenge($response);
if($challenge===null){
return self::restoreOriginalSink($request,$response,$probeOptions);
}
$retries=$options['__guzzle_digest_retries']??0;
if(!\is_int($retries)){
$retries=0;
}
if(($retries>0&&!$challenge->stale)||$retries>=self::DIGEST_MAX_RETRIES){
return self::restoreOriginalSink($request,$response,$probeOptions);
}
try{
self::rewindBodyForRetry($request,$bodyWithheld);
}catch(\Exception$e){
$response=self::restoreOriginalSink($request,$response,$probeOptions);
throw new ResponseException('Digest authentication failed because the request body could not be rewound',$request,$response,$e
);
}
$nonceCounts=self::digestNonceCountsFromOptions($options);
if($previousEntry!==null
&&$previousEntry['credentials']===$this->digestCredentialKey($username,$password)){
self::rememberDigestNonceCount($nonceCounts,$previousEntry['challenge'],$previousEntry['nextNc']);
}
$nc=$challenge->qop===null?1:($nonceCounts[self::digestNonceCountKey($challenge)]??1);
$authorization=DigestAuth::authorizationHeader($request,$challenge,$username,$password,($this->cnonceGenerator)(),\sprintf('%08x',$nc));
if($authorization===null){
return self::restoreOriginalSink($request,$response,$probeOptions);
}
$response->getBody()->close();
self::rememberDigestNonceCount($nonceCounts,$challenge,$nc+1);
$retryOptions=$options;
$retryOptions['__guzzle_digest_retries']=$retries+1;
$retryOptions[self::DIGEST_NONCE_COUNTS_OPTION]=$nonceCounts;
$downstreamOptions=$retryOptions;
unset($downstreamOptions[self::DIGEST_NONCE_COUNTS_OPTION]);
unset($downstreamOptions[RequestOptions::DELAY]);
$downstreamOptions=self::withTemporarySink($downstreamOptions);
unset($downstreamOptions['auth']);
$retryRequest=$request->withHeader('Authorization',$authorization);
return($this->nextHandler)($retryRequest,$downstreamOptions)->then(function(#[\SensitiveParameter]ResponseInterface$retryResponse
)use($retryRequest,$retryOptions,$downstreamOptions,$username,$password,$challenge,$nc){
if($this->reuseChallenges&&self::isCacheableDigestSuccess($retryResponse)){
$this->storeDigestChallenge($retryRequest,$challenge,$username,$password,$nc+1);
}
return$this->handleDigestResponse($retryRequest,$retryOptions,$downstreamOptions,$retryResponse,$username,$password,false);
},function(#[\SensitiveParameter]$reason
)use($retryRequest,$downstreamOptions){
return$this->handleDigestRejection($retryRequest,$downstreamOptions,$reason,false);
}
);
}
private static function isCacheableDigestSuccess(ResponseInterface$response):bool
{
$status=$response->getStatusCode();
return$status>=200&&$status<400&&!$response->hasHeader('Authentication-Info');
}
private function storeDigestChallenge(#[\SensitiveParameter]RequestInterface$request,DigestChallenge$challenge,string$username,#[\SensitiveParameter]string$password,int$nextNc
):void{
$key=self::digestCacheKey($request);
if($key===null||$challenge->qop===null){
return;
}
unset($this->digestChallenges[$key]);
if(\count($this->digestChallenges)>=self::CHALLENGE_CACHE_LIMIT){
\array_shift($this->digestChallenges);
}
$this->digestChallenges[$key]=['challenge'=>$challenge,'credentials'=>$this->digestCredentialKey($username,$password),'nextNc'=>$nextNc,];
}
private function clearDigestChallenge(RequestInterface$request):void
{
$key=self::digestCacheKey($request);
if($key!==null){
unset($this->digestChallenges[$key]);
}
}
private static function digestNonceCountsFromOptions(array$options):array
{
$counts=$options[self::DIGEST_NONCE_COUNTS_OPTION]??[];
if(!\is_array($counts)){
return[];
}
$normalized=[];
foreach($counts as$key=>$nextNc){
if(\is_string($key)&&\is_int($nextNc)&&$nextNc>0&&$nextNc<\PHP_INT_MAX){
$normalized[$key]=$nextNc;
}
}
return$normalized;
}
private static function digestNonceCountKey(DigestChallenge$challenge):string
{
return\implode("\0",[$challenge->realm,$challenge->nonce,$challenge->qop??'',$challenge->algorithm['header'],]);
}
private static function rememberDigestNonceCount(array&$counts,DigestChallenge$challenge,int$nextNc):void
{
if($challenge->qop===null){
return;
}
$key=self::digestNonceCountKey($challenge);
$counts[$key]=\max($counts[$key]??1,$nextNc);
}
private function handleDigestRejection(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]$reason,bool$preemptive
):PromiseInterface{
if($this->reuseChallenges&&$reason instanceof ResponseException){
$response=$reason->getResponse();
if($response->getStatusCode()===401
||$response->hasHeader('Authentication-Info')||($preemptive&&$response->getStatusCode()>=400)){
$this->clearDigestChallenge($request);
}
}
return self::restoreOriginalSinkOnRejection($options,$reason);
}
private static function digestCacheKey(RequestInterface$request):?string
{
$uri=$request->getUri();
$scheme=Psr7\Utils::asciiToLower($uri->getScheme());
$host=HostIdentity::canonicalHost($uri->getHost());
if(($scheme!=='http'&&$scheme!=='https')||$host===''){
return;
}
$port=$uri->getPort()??($scheme==='https'?443:80);
return$scheme.'://'.$host.':'.$port.'|'.HostIdentity::canonicalHostHeader($request->getHeaderLine('Host'));
}
private function digestCredentialKey(string$username,#[\SensitiveParameter]string$password
):string{
if($this->credentialHashSecret===null){
$this->credentialHashSecret=\random_bytes(32);
}
return\hash_hmac('sha256',$username."\0".$password,$this->credentialHashSecret);
}
private static function challengeCoversRequest(DigestChallenge$challenge,RequestInterface$request):bool
{
if($challenge->domain===[]){
return true;
}
$target=$request->getRequestTarget();
foreach($challenge->domain as$space){
$prefix=self::protectionSpacePath($space,$request);
if($prefix!==null&&\str_starts_with($target,$prefix)){
return true;
}
}
return false;
}
private static function protectionSpacePath(string$space,RequestInterface$request):?string
{
if($space===''){
return;
}
if($space[0]==='/'){
return$space;
}
try{
$uri=new Psr7\Uri($space);
}catch(\InvalidArgumentException$e){
return;
}
if(Psr7\UriComparator::isCrossOrigin($uri,self::effectiveRequestUri($request))){
return;
}
$path=$uri->getPath();
$prefix=$path===''?'/':$path;
if($uri->getQuery()!==''){
$prefix.='?'.$uri->getQuery();
}
return$prefix;
}
private static function effectiveRequestUri(RequestInterface$request):UriInterface
{
$uri=$request->getUri();
$host=$request->getHeaderLine('Host');
if($host===''||Psr7\Utils::caselessEquals($host,$uri->getHost())){
return$uri;
}
try{
$authority=new Psr7\Uri('//'.$host);
if($authority->getHost()===''){
return$uri;
}
return$uri->withHost($authority->getHost())->withPort($authority->getPort());
}catch(\InvalidArgumentException$e){
return$uri;
}
}
private static function isRedirectLikeResponse(ResponseInterface$response):bool
{
return$response->hasHeader('Location')&&\in_array($response->getStatusCode(),[301,302,303,307,308],true);
}
private static function rewindBodyForRetry(#[\SensitiveParameter]RequestInterface$request,bool$bodyWithheld
):void{
$body=$request->getBody();
if(!$bodyWithheld){
try{
if($body->getSize()===0){
return;
}
}catch(\Exception$e){
}
Psr7\Message::rewindBody($request);
return;
}
if($body->isSeekable()){
$body->rewind();
}
}
private static function withTemporarySink(#[\SensitiveParameter]array$options
):array{
if(!isset($options[RequestOptions::SINK])){
return$options;
}
$streamFactory=self::requireStreamFactory($options[RequestOptions::STREAM_FACTORY]??new HttpFactory
);
$options['__guzzle_auth_original_sink']=$options[RequestOptions::SINK];
$options[RequestOptions::SINK]=$streamFactory->createStreamFromResource(Psr7\Utils::tryFopen('php://temp','w+'));
return$options;
}
private static function restoreOriginalSink(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]array$options
):ResponseInterface{
if(!\array_key_exists('__guzzle_auth_original_sink',$options)){
return$response;
}
try{
$source=$response->getBody();
if($source->isSeekable()){
$source->rewind();
}
$target=self::streamForOriginalSink($options['__guzzle_auth_original_sink']);
Psr7\Utils::copyToStream($source,$target);
if($target->isSeekable()){
$target->rewind();
}
return$response->withBody($target);
}catch(\Exception$e){
throw new ResponseException($e->getMessage()!==''?$e->getMessage():'Failed to write the response body',$request,$response,$e
);
}
}
private static function restoreOriginalSinkOnRejection(#[\SensitiveParameter]array$options,#[\SensitiveParameter]$reason
):PromiseInterface{
if(!$reason instanceof ResponseException||!\array_key_exists('__guzzle_auth_original_sink',$options)){
return P\Create::rejectionFor($reason);
}
try{
$response=self::restoreOriginalSink($reason->getRequest(),$reason->getResponse(),$options);
return P\Create::rejectionFor($reason->withResponse($response));
}catch(\Throwable$e){
return P\Create::rejectionFor($e);
}
}
private static function streamForOriginalSink($sink):StreamInterface
{
if(\is_string($sink)){
return new LazyOpenStream($sink,'w+');
}
if(\is_resource($sink)){
return self::streamForResourceSink(Psr7\Utils::streamFor($sink));
}
if(!$sink instanceof StreamInterface){
throw new InvalidArgumentException(\sprintf('sink must be a resource, string, or %s',StreamInterface::class
));
}
return Psr7\Utils::streamFor($sink);
}
private static function streamForResourceSink(StreamInterface$stream):StreamInterface
{
return Psr7\FnStream::decorate($stream,['close'=>static function()use($stream):void{
$stream->detach();
},]);
}
private static function requireStreamFactory($factory):StreamFactoryInterface
{
if(!$factory instanceof StreamFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::STREAM_FACTORY,StreamFactoryInterface::class
));
}
return$factory;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Auth;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class DigestAuth
{
private const ALGORITHMS=['MD5'=>['hash'=>'md5','sess'=>false,'rank'=>10,'header'=>'MD5'],'MD5-SESS'=>['hash'=>'md5','sess'=>true,'rank'=>11,'header'=>'MD5-sess'],'SHA-256'=>['hash'=>'sha256','sess'=>false,'rank'=>20,'header'=>'SHA-256'],'SHA-256-SESS'=>['hash'=>'sha256','sess'=>true,'rank'=>21,'header'=>'SHA-256-sess'],'SHA-512-256'=>['hash'=>'sha512/256','sess'=>false,'rank'=>30,'header'=>'SHA-512-256'],'SHA-512-256-SESS'=>['hash'=>'sha512/256','sess'=>true,'rank'=>31,'header'=>'SHA-512-256-sess'],];
private const DIGEST_CHALLENGE_PARAMETER_NAMES=['realm'=>true,'domain'=>true,'nonce'=>true,'opaque'=>true,'stale'=>true,'algorithm'=>true,'qop'=>true,'charset'=>true,'userhash'=>true,];
private function __construct(){
}
static function selectChallenge(#[\SensitiveParameter]ResponseInterface$response
):?DigestChallenge{
$selected=null;
foreach($response->getHeader('WWW-Authenticate')as$header){
foreach(self::parseAuthenticateHeader($header)as$challenge){
if($challenge['scheme']!=='digest'||$challenge['invalid']){
continue;
}
$digest=self::createChallenge($challenge['params']);
if($digest===null){
continue;
}
if($selected===null||$digest->algorithm['rank']>$selected->algorithm['rank']){
$selected=$digest;
}
}
}
return$selected;
}
static function authorizationHeader(#[\SensitiveParameter]RequestInterface$request,DigestChallenge$challenge,string$username,#[\SensitiveParameter]string$password,string$cnonce,string$nc='00000001'):?string{
if($challenge->algorithm['sess']&&$challenge->qop===null){
return;
}
$uri=$request->getRequestTarget();
if($uri===''){
$uri='/';
}
foreach([$username,$challenge->realm,$challenge->nonce,$uri,$cnonce]as$value){
if(!self::isHeaderSafe($value)){
return;
}
}
if($challenge->opaque!==null&&!self::isHeaderSafe($challenge->opaque)){
return;
}
if($challenge->qop!==null&&!self::isNonceCount($nc)){
return;
}
$hash=$challenge->algorithm['hash'];
$ha1=\hash($hash,$username.':'.$challenge->realm.':'.$password);
if($challenge->algorithm['sess']){
$ha1=\hash($hash,$ha1.':'.$challenge->nonce.':'.$cnonce);
}
$ha2=\hash($hash,$request->getMethod().':'.$uri);
$response=$challenge->qop===null
?\hash($hash,$ha1.':'.$challenge->nonce.':'.$ha2):\hash($hash,$ha1.':'.$challenge->nonce.':'.$nc.':'.$cnonce.':'.$challenge->qop.':'.$ha2);
if($challenge->userhash){
$headerUsername=\hash($hash,$username.':'.$challenge->realm);
if($headerUsername===false){
return;
}
}else{
$headerUsername=$username;
}
$parts=['username='.self::quote($headerUsername),'realm='.self::quote($challenge->realm),'nonce='.self::quote($challenge->nonce),'uri='.self::quote($uri),'response='.self::quote($response),'algorithm='.$challenge->algorithm['header'],];
if($challenge->opaque!==null){
$parts[]='opaque='.self::quote($challenge->opaque);
}
if($challenge->qop!==null){
$parts[]='qop='.$challenge->qop;
$parts[]='nc='.$nc;
$parts[]='cnonce='.self::quote($cnonce);
}
if($challenge->userhash){
$parts[]='userhash=true';
}
return'Digest '.\implode(', ',$parts);
}
static function parseAuthenticateHeader(string$header):array
{
$length=\strlen($header);
$offset=0;
$challenges=[];
while(true){
self::skipSeparators($header,$offset,$length);
if($offset>=$length){
break;
}
$scheme=self::readToken($header,$offset,$length);
if($scheme===null){
break;
}
self::skipWhitespace($header,$offset,$length);
if(self::skipToken68Challenge($header,$offset,$length)){
$challenges[]=['scheme'=>Psr7\Utils::asciiToLower($scheme),'params'=>[],'invalid'=>false,];
continue;
}
$params=[];
$invalid=false;
while($offset<$length){
self::skipWhitespace($header,$offset,$length);
if($offset<$length&&$header[$offset]===','){
if(self::commaStartsNextChallenge($header,$offset+1,$length)){
if(Psr7\Utils::caselessEquals($scheme,'Digest')&&self::commaStartsKnownDigestParameterWithoutValue($header,$offset+1,$length)){
$invalid=true;
break;
}
++$offset;
break;
}
++$offset;
continue;
}
$name=self::readToken($header,$offset,$length);
if($name===null){
if($offset<$length){
$invalid=true;
}
break;
}
self::skipWhitespace($header,$offset,$length);
if($offset>=$length||$header[$offset]!=='='){
$invalid=true;
break;
}
++$offset;
self::skipWhitespace($header,$offset,$length);
$value=self::readValue($header,$offset,$length);
if($value===null){
$invalid=true;
break;
}
$lowerName=Psr7\Utils::asciiToLower($name);
if(\array_key_exists($lowerName,$params)){
$invalid=true;
}
$params[$lowerName]=$value;
self::skipWhitespace($header,$offset,$length);
if($offset>=$length){
break;
}
if($header[$offset]!==','){
$invalid=true;
break;
}
}
$challenges[]=['scheme'=>Psr7\Utils::asciiToLower($scheme),'params'=>$params,'invalid'=>$invalid,];
}
return$challenges;
}
private static function createChallenge(array$params):?DigestChallenge
{
if(!isset($params['nonce'])||$params['nonce']===''){
return;
}
if(isset($params['charset'])&&!Psr7\Utils::caselessEquals($params['charset'],'UTF-8')){
return;
}
$algorithm=self::algorithm($params['algorithm']??null);
if($algorithm===null){
return;
}
$qop=self::selectQop($params['qop']??null);
if($qop===false){
return;
}
if($algorithm['sess']&&$qop===null){
return;
}
$challenge=new DigestChallenge;
$challenge->algorithm=$algorithm;
$challenge->realm=$params['realm']??'';
$challenge->nonce=$params['nonce'];
$challenge->opaque=$params['opaque']??null;
if(isset($params['domain'])){
$domainAreas=\preg_split('/[ \t]+/',$params['domain']);
if($domainAreas===false){
throw new\RuntimeException('Unable to split the Digest domain list: '.\preg_last_error_msg());
}
$challenge->domain=\array_values(\array_filter($domainAreas));
}else{
$challenge->domain=[];
}
$challenge->qop=$qop;
$challenge->stale=isset($params['stale'])&&Psr7\Utils::caselessEquals($params['stale'],'true');
$challenge->userhash=isset($params['userhash'])&&Psr7\Utils::caselessEquals($params['userhash'],'true');
return$challenge;
}
private static function algorithm(?string$algorithm):?array
{
$name=Psr7\Utils::asciiToUpper($algorithm??'MD5');
if(!isset(self::ALGORITHMS[$name])){
return;
}
$mapped=self::ALGORITHMS[$name];
if(!\in_array($mapped['hash'],\hash_algos(),true)){
return;
}
return['name'=>$name]+$mapped;
}
private static function selectQop(?string$qop){
if($qop===null){
return;
}
$tokens=\array_map(static function(string$token):string{
return Psr7\Utils::asciiToLower(\trim($token," \t"));
},\explode(',',$qop));
return\in_array('auth',$tokens,true)?'auth':false;
}
private static function quote(string$value):string
{
return'"'.\strtr($value,['\\'=>'\\\\','"'=>'\\"',]).'"';
}
private static function isHeaderSafe(string$value):bool
{
return\preg_match('/^[\x20\x09\x21-\x7E\x80-\xFF]*$/D',$value)===1;
}
private static function isNonceCount(string$nc):bool
{
return$nc!=='00000000'&&\preg_match('/^[0-9a-f]{8}$/D',$nc)===1;
}
private static function commaStartsNextChallenge(string$header,int$offset,int$length):bool
{
self::skipWhitespace($header,$offset,$length);
$nextOffset=$offset;
$token=self::readToken($header,$nextOffset,$length);
if($token===null){
return false;
}
self::skipWhitespace($header,$nextOffset,$length);
return$nextOffset>=$length||$header[$nextOffset]!=='=';
}
private static function commaStartsKnownDigestParameterWithoutValue(string$header,int$offset,int$length):bool
{
self::skipWhitespace($header,$offset,$length);
$name=self::readToken($header,$offset,$length);
if($name===null||!isset(self::DIGEST_CHALLENGE_PARAMETER_NAMES[Psr7\Utils::asciiToLower($name)])){
return false;
}
self::skipWhitespace($header,$offset,$length);
return$offset>=$length||$header[$offset]!=='=';
}
private static function skipToken68Challenge(string$header,int&$offset,int$length):bool
{
$cursor=$offset;
$hasValue=false;
while($cursor<$length&&self::isToken68Char($header[$cursor])){
$hasValue=true;
++$cursor;
}
while($cursor<$length&&$header[$cursor]==='='){
++$cursor;
}
if(!$hasValue){
return false;
}
$after=$cursor;
self::skipWhitespace($header,$after,$length);
if($after<$length&&$header[$after]!==','){
return false;
}
$offset=$after;
return true;
}
private static function skipSeparators(string$header,int&$offset,int$length):void
{
while($offset<$length){
$char=$header[$offset];
if($char!==','&&!self::isWhitespace($char)){
return;
}
++$offset;
}
}
private static function skipWhitespace(string$header,int&$offset,int$length):void
{
while($offset<$length&&self::isWhitespace($header[$offset])){
++$offset;
}
}
private static function isWhitespace(string$char):bool
{
return$char===' '||$char==="\t";
}
private static function readToken(string$header,int&$offset,int$length):?string
{
$start=$offset;
while($offset<$length&&self::isTokenChar($header[$offset])){
++$offset;
}
if($offset===$start){
return;
}
$token=\substr($header,$start,$offset-$start);
return$token===false?null:$token;
}
private static function isTokenChar(string$char):bool
{
return\strspn($char,"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")===1;
}
private static function isToken68Char(string$char):bool
{
return\strspn($char,'-._~+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')===1;
}
private static function readValue(string$header,int&$offset,int$length):?string
{
if($offset>=$length){
return;
}
if($header[$offset]==='"'){
return self::readQuotedString($header,$offset,$length);
}
return self::readToken($header,$offset,$length);
}
private static function readQuotedString(string$header,int&$offset,int$length):?string
{
++$offset;
$value='';
$escaped=false;
while($offset<$length){
$char=$header[$offset++];
if($escaped){
$value.=$char;
$escaped=false;
continue;
}
if($char==='\\'){
$escaped=true;
continue;
}
if($char==='"'){
return$value;
}
$value.=$char;
}
return;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Auth;
final class DigestChallenge
{
array$algorithm;
string$realm='';
string$nonce;
?string$opaque=null;
array$domain=[];
?string$qop=null;
bool$stale=false;
bool$userhash=false;
}
declare(strict_types=1);
namespace GuzzleHttp;
use Psr\Http\Message\MessageInterface;
interface BodySummarizerInterface
{
function summarize(MessageInterface$message):?string;
}
declare(strict_types=1);
namespace GuzzleHttp;
use Psr\Http\Message\MessageInterface;
final class BodySummarizer implements BodySummarizerInterface
{
private?int$truncateAt;
function __construct(?int$truncateAt=null){
$this->truncateAt=$truncateAt;
}
function summarize(MessageInterface$message):?string
{
try{
return Psr7\Message::bodySummary($message,$this->truncateAt);
}catch(\Exception$e){
return;
}
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Cookie\CookieJarInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
trait ClientTrait
{
abstract  function request(string$method,$uri,array$options=[]):ResponseInterface;
function get($uri,#[\SensitiveParameter]array$options=[]):ResponseInterface{
return$this->request('GET',$uri,$options);
}
function head($uri,#[\SensitiveParameter]array$options=[]):ResponseInterface{
return$this->request('HEAD',$uri,$options);
}
function put($uri,#[\SensitiveParameter]array$options=[]):ResponseInterface{
return$this->request('PUT',$uri,$options);
}
function post($uri,#[\SensitiveParameter]array$options=[]):ResponseInterface{
return$this->request('POST',$uri,$options);
}
function patch($uri,#[\SensitiveParameter]array$options=[]):ResponseInterface{
return$this->request('PATCH',$uri,$options);
}
function delete($uri,#[\SensitiveParameter]array$options=[]):ResponseInterface{
return$this->request('DELETE',$uri,$options);
}
abstract  function requestAsync(string$method,$uri,array$options=[]):PromiseInterface;
function getAsync($uri,#[\SensitiveParameter]array$options=[]):PromiseInterface{
return$this->requestAsync('GET',$uri,$options);
}
function headAsync($uri,#[\SensitiveParameter]array$options=[]):PromiseInterface{
return$this->requestAsync('HEAD',$uri,$options);
}
function putAsync($uri,#[\SensitiveParameter]array$options=[]):PromiseInterface{
return$this->requestAsync('PUT',$uri,$options);
}
function postAsync($uri,#[\SensitiveParameter]array$options=[]):PromiseInterface{
return$this->requestAsync('POST',$uri,$options);
}
function patchAsync($uri,#[\SensitiveParameter]array$options=[]):PromiseInterface{
return$this->requestAsync('PATCH',$uri,$options);
}
function deleteAsync($uri,#[\SensitiveParameter]array$options=[]):PromiseInterface{
return$this->requestAsync('DELETE',$uri,$options);
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Cookie\CookieJarInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
interface ClientInterface
{
const MAJOR_VERSION=8;
function send(RequestInterface$request,array$options=[]):ResponseInterface;
function sendAsync(RequestInterface$request,array$options=[]):PromiseInterface;
function request(string$method,$uri,array$options=[]):ResponseInterface;
function requestAsync(string$method,$uri,array$options=[]):PromiseInterface;
}
namespace Psr\Http\Client;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
interface ClientInterface
{
function sendRequest(RequestInterface$request):ResponseInterface;
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\CookieJarInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\CurlShareHandleState;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\DiagnosticValue;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
class Client implements ClientInterface,\Psr\Http\Client\ClientInterface
{
use ClientTrait;
use NonSerializableTrait;
private array$config;
function __construct(#[\SensitiveParameter]array$config=[]){
$handlerOptions=[];
foreach(['max_host_connections','max_total_connections']as$capOption){
if(\array_key_exists($capOption,$config)){
if($config[$capOption]!==null){
$handlerOptions[$capOption]=$config[$capOption];
}
unset($config[$capOption]);
}
}
$handlerMultiplex=($config['multiplex']??null)===Multiplexing::NONE;
$transportSharing=\array_key_exists('transport_sharing',$config)?$config['transport_sharing']:null;
$transportSharingMode=CurlShareHandleState::normalizeMode($transportSharing,'transport_sharing');
unset($config['transport_sharing']);
if(!isset($config['handler'])){
if($transportSharingMode!==TransportSharing::NONE){
$handlerOptions['transport_sharing']=$transportSharingMode;
}
if($handlerMultiplex){
$handlerOptions['multiplex']=Multiplexing::NONE;
}
$config['handler']=$handlerOptions===[]?HandlerStack::create():HandlerStack::create(Utils::chooseHandler($handlerOptions));
}elseif(!\is_callable($config['handler'])){
throw new InvalidArgumentException('handler must be a callable');
}elseif($handlerOptions!==[]){
throw new InvalidArgumentException('The "max_host_connections" and "max_total_connections" client options require Guzzle to create the default handler. Configure the options on the CurlMultiHandler constructor for numeric enforcement, or on the StreamHandler constructor to reject enabled response streaming, when providing a custom handler.');
}elseif($transportSharingMode===TransportSharing::HANDLER_REQUIRE){
throw new InvalidArgumentException('The "transport_sharing" client option can only require sharing when Guzzle creates the default handler. Configure the "transport_sharing" option on CurlHandler, CurlMultiHandler, or StreamHandler when providing a custom handler.');
}elseif($transportSharingMode===TransportSharing::PERSISTENT_REQUIRE){
throw new InvalidArgumentException('The "transport_sharing" client option can only require sharing when Guzzle creates the default handler. Configure the "transport_sharing" option on CurlHandler or CurlMultiHandler when providing a custom handler.');
}
$factory=new HttpFactory;
if(!isset($config[RequestOptions::REQUEST_FACTORY])){
$config[RequestOptions::REQUEST_FACTORY]=$factory;
}
if(!isset($config[RequestOptions::URI_FACTORY])){
$config[RequestOptions::URI_FACTORY]=$factory;
}
if(!isset($config[RequestOptions::STREAM_FACTORY])){
$config[RequestOptions::STREAM_FACTORY]=$factory;
}
if(!isset($config[RequestOptions::RESPONSE_FACTORY])){
$config[RequestOptions::RESPONSE_FACTORY]=$factory;
}
self::requireRequestFactory($config[RequestOptions::REQUEST_FACTORY]);
self::requireResponseFactory($config[RequestOptions::RESPONSE_FACTORY]);
self::requireStreamFactory($config[RequestOptions::STREAM_FACTORY]);
$uriFactory=self::requireUriFactory($config[RequestOptions::URI_FACTORY]);
if(isset($config['base_uri'])){
$config['base_uri']=self::createUri($config['base_uri'],$uriFactory);
}
$this->configureDefaults($config);
}
function sendAsync(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options=[]):PromiseInterface{
$options=$this->prepareDefaults($options);
return$this->transfer($request->withUri($this->buildUri($request->getUri(),$options),self::shouldPreserveHost($request)),$options
);
}
function send(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options=[]):ResponseInterface{
$options[RequestOptions::SYNCHRONOUS]=true;
return$this->sendAsync($request,$options)->wait();
}
function sendRequest(#[\SensitiveParameter]RequestInterface$request
):ResponseInterface{
$options[RequestOptions::SYNCHRONOUS]=true;
$options[RequestOptions::ALLOW_REDIRECTS]=false;
$options[RequestOptions::HTTP_ERRORS]=false;
return$this->sendAsync($request,$options)->wait();
}
function requestAsync(string$method,$uri='',#[\SensitiveParameter]array$options=[]):PromiseInterface{
$options=$this->prepareDefaults($options);
$version=self::normalizeProtocolVersion($options['version']??'1.1');
unset($options['version']);
if(isset($options['body'])&&\is_array($options['body'])){
throw$this->invalidBody();
}
$uriFactory=isset($options[RequestOptions::URI_FACTORY])?self::requireUriFactory($options[RequestOptions::URI_FACTORY]):new HttpFactory;
$requestFactory=isset($options[RequestOptions::REQUEST_FACTORY])?self::requireRequestFactory($options[RequestOptions::REQUEST_FACTORY]):new HttpFactory;
$uriIsString=\is_string($uri);
$uri=self::createUri($uri,$uriFactory);
$builtUri=$this->buildUri($uri,$options);
if($uriIsString&&$builtUri!==$uri){
$builtUri=self::createUri((string)$builtUri,$uriFactory);
}
$uri=$builtUri;
$request=$requestFactory->createRequest($method,$uri);
$request=Psr7\Utils::modifyRequest($request,['version'=>$version]);
return$this->transfer($request,$options);
}
function request(string$method,$uri='',#[\SensitiveParameter]array$options=[]):ResponseInterface{
$options[RequestOptions::SYNCHRONOUS]=true;
return$this->requestAsync($method,$uri,$options)->wait();
}
function getConfig(?string$option=null){
return$option===null
?$this->config
:($this->config[$option]??null);
}
private function buildUri(UriInterface$uri,#[\SensitiveParameter]array$config
):UriInterface{
if(isset($config['base_uri'])){
$uriFactory=self::requireUriFactory($config[RequestOptions::URI_FACTORY]??new HttpFactory);
$uri=Psr7\UriResolver::resolve(self::createUri($config['base_uri'],$uriFactory),$uri);
}
$idnOptions=Idn::normalizeConversionOption($config['idn_conversion']??null);
if($idnOptions!==null){
$uri=Idn::convertUri($uri,$idnOptions);
}
if($uri->getScheme()===''&&$uri->getHost()!==''){
$uri=$uri->withScheme('http');
}
return$uri;
}
private static function shouldPreserveHost(RequestInterface$request):bool
{
if(!$request->hasHeader('Host')){
return false;
}
$uri=$request->getUri();
$host=$uri->getHost();
$port=$uri->getPort();
if($port!==null){
$host.=':'.$port;
}
return$host!==$request->getHeaderLine('Host');
}
private static function requireRequestFactory($factory):RequestFactoryInterface
{
if(!$factory instanceof RequestFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::REQUEST_FACTORY,RequestFactoryInterface::class
));
}
return$factory;
}
private static function requireResponseFactory($factory):ResponseFactoryInterface
{
if(!$factory instanceof ResponseFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::RESPONSE_FACTORY,ResponseFactoryInterface::class
));
}
return$factory;
}
private static function requireUriFactory($factory):UriFactoryInterface
{
if(!$factory instanceof UriFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::URI_FACTORY,UriFactoryInterface::class
));
}
return$factory;
}
private static function requireStreamFactory($factory):StreamFactoryInterface
{
if(!$factory instanceof StreamFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::STREAM_FACTORY,StreamFactoryInterface::class
));
}
return$factory;
}
private static function createUri($uri,UriFactoryInterface$uriFactory):UriInterface
{
if($uri instanceof UriInterface){
return$uri;
}
if(\is_string($uri)){
return$uriFactory->createUri($uri);
}
throw new InvalidArgumentException(\sprintf('URI must be a string or %s',UriInterface::class));
}
private static function createBodyStream($body,StreamFactoryInterface$streamFactory):StreamInterface
{
if($body instanceof StreamInterface){
return$body;
}
if(\is_resource($body)){
return$streamFactory->createStreamFromResource($body);
}
if($body===null){
return$streamFactory->createStream();
}
if(\is_string($body)){
return$streamFactory->createStream($body);
}
if($body instanceof\Iterator){
return Psr7\Utils::streamFor($body);
}
if(\is_object($body)&&\method_exists($body,'__toString')){
return$streamFactory->createStream((string)$body);
}
if(\is_callable($body)){
return Psr7\Utils::streamFor($body);
}
throw new InvalidArgumentException(\sprintf('Passing %s to request option "body" is invalid; expected resource|string|null|StreamInterface|callable&object|Iterator|Stringable.',\get_debug_type($body)));
}
private function configureDefaults(#[\SensitiveParameter]array$config
):void{
$defaults=['allow_redirects'=>RedirectMiddleware::DEFAULT_SETTINGS,'http_errors'=>true,'decode_content'=>true,'verify'=>true,'cookies'=>false,'idn_conversion'=>false,'protocols'=>['http','https'],];
if(\PHP_SAPI==='cli'&&($proxy=Env::get('HTTP_PROXY'))){
$defaults['proxy']['http']=$proxy;
}
if($proxy=Env::get('HTTPS_PROXY')){
$defaults['proxy']['https']=$proxy;
}
$noProxy=Env::get('NO_PROXY');
if($noProxy!==null){
$noProxy=ProxyOptions::normalizeNoProxy($noProxy);
if($noProxy!==[]){
$defaults['proxy']['no']=$noProxy;
}
}
$this->config=$config+$defaults;
if(!empty($config['cookies'])&&$config['cookies']===true){
$this->config['cookies']=new CookieJar;
}
if(!isset($this->config['headers'])){
$this->config['headers']=['User-Agent'=>Utils::defaultUserAgent()];
}else{
self::assertHeaderOptionTypes($this->config['headers']);
$hasUserAgent=false;
foreach(\array_keys($this->config['headers'])as$name){
if(Psr7\Utils::asciiToLower((string)$name)==='user-agent'){
$hasUserAgent=true;
break;
}
}
if(!$hasUserAgent){
$this->config['headers']['User-Agent']=Utils::defaultUserAgent();
}
}
}
private function prepareDefaults(#[\SensitiveParameter]array$options
):array{
if(isset($options['handler'])){
throw new InvalidArgumentException('The "handler" request option is not supported; configure the handler when creating the client, or use a separate client instance for requests that need a different handler.');
}
$defaults=$this->config;
if(!empty($defaults['headers'])){
$defaults['_conditional']=$defaults['headers'];
unset($defaults['headers']);
}
if(\array_key_exists('headers',$options)){
if($options['headers']===null){
$defaults['_conditional']=[];
unset($options['headers']);
}elseif(!\is_array($options['headers'])){
throw new InvalidArgumentException('headers must be an array');
}
}
$result=$options+$defaults;
foreach($result as$k=>$v){
if($v===null){
unset($result[$k]);
}
}
self::assertRequestOptionTypes($result);
return$result;
}
private static function assertRequestOptionTypes(#[\SensitiveParameter]array$options
):void{
if(isset($options['allow_redirects'])){
if(!\is_bool($options['allow_redirects'])&&!\is_array($options['allow_redirects'])){
self::invalidRequestOptionType('allow_redirects','bool|array',$options['allow_redirects']);
}
if(\is_array($options['allow_redirects'])){
self::assertAllowRedirectsOptionTypes($options['allow_redirects']);
}
}
if(isset($options['auth'])&&$options['auth']!==false
&&!\is_string($options['auth'])&&!\is_array($options['auth'])){
self::invalidRequestOptionType('auth','array{0: string, 1: string, 2?: string|null}|string|false|null',$options['auth']);
}
if(isset($options['auth'])&&\is_array($options['auth'])&&$options['auth']!==[]){
self::assertAuthOptionTypes($options['auth']);
}
self::assertTlsFileOptionTypes($options,'cert');
self::assertIfPresentAndNotString($options,'cert_type');
self::assertIfPresentAndNotNumber($options,'connect_timeout');
self::assertIfPresentAndNotInt($options,'crypto_method');
self::assertIfPresentAndNotInt($options,'crypto_method_max');
self::assertIfPresentAndNotBoolOrResource($options,'debug');
self::assertIfPresentAndNotBoolOrString($options,'decode_content');
self::assertIfPresentAndNotFiniteNonNegativeNumber($options,'delay');
self::assertIfPresentAndNotBoolOrInt($options,'expect');
if(isset($options['form_params'])){
self::assertFormParamTypes($options['form_params']);
}
self::assertIfPresentAndNotForceIpResolve($options);
if(isset($options['headers'])){
self::assertHeaderOptionTypes($options['headers']);
}
self::assertIfPresentAndNotBool($options,'http_errors');
if(isset($options['multipart'])){
self::assertMultipartOptionTypes($options['multipart']);
}
self::assertValidMultiplex($options);
self::assertIfPresentAndNotCallable($options,'on_headers');
self::assertIfPresentAndNotCallable($options,'on_stats');
self::assertIfPresentAndNotCallable($options,'on_trailers');
self::assertIfPresentAndNotCallable($options,'progress');
self::assertIfPresentAndNotProtocolArray($options,'protocols');
self::assertProxyOptionTypes($options);
self::assertIfPresentAndNotNumber($options,'read_timeout');
self::assertIfPresentAndNotInt($options,'retries');
if(isset($options['sink'])&&!\is_resource($options['sink'])&&!\is_string($options['sink'])&&!$options['sink']instanceof StreamInterface){
self::invalidRequestOptionType('sink','resource|string|StreamInterface',$options['sink']);
}
self::assertTlsFileOptionTypes($options,'ssl_key');
self::assertIfPresentAndNotString($options,'ssl_key_type');
self::assertIfPresentAndNotBool($options,'stream');
self::assertIfPresentAndNotArray($options,'stream_context','array<array-key, mixed>');
self::assertIfPresentAndNotBool($options,'synchronous');
self::assertIfPresentAndNotNumber($options,'timeout');
self::assertIfPresentAndNotBoolOrString($options,'verify');
self::assertIfPresentAndNotStringOrNumber($options,'version');
self::assertIfPresentAndNotArray($options,'curl','array<int|string, mixed>');
if(isset($options['cookies'])&&$options['cookies']!==false&&!$options['cookies']instanceof CookieJarInterface){
self::invalidRequestOptionType('cookies','false|CookieJarInterface',$options['cookies']);
}
}
private static function assertAllowRedirectsOptionTypes(array$allowRedirects):void
{
self::assertIfPresentAndNotInt($allowRedirects,'max','allow_redirects.max');
self::assertIfPresentAndNotBool($allowRedirects,'strict','allow_redirects.strict');
self::assertIfPresentAndNotBool($allowRedirects,'referer','allow_redirects.referer');
self::assertIfPresentAndNotProtocolArray($allowRedirects,'protocols','allow_redirects.protocols');
self::assertIfPresentAndNotCallable($allowRedirects,'on_redirect','allow_redirects.on_redirect');
self::assertIfPresentAndNotBool($allowRedirects,'track_redirects','allow_redirects.track_redirects');
}
private static function assertAuthOptionTypes(#[\SensitiveParameter]array$auth
):void{
if(!\array_key_exists(0,$auth)||!\is_string($auth[0])){
self::invalidRequestOptionType('auth.0','string',$auth[0]??null);
}
if(!\array_key_exists(1,$auth)||!\is_string($auth[1])){
self::invalidRequestOptionType('auth.1','string',$auth[1]??null);
}
if(\array_key_exists(2,$auth)&&$auth[2]!==null&&!\is_string($auth[2])){
self::invalidRequestOptionType('auth.2','string|null',$auth[2]);
}
}
private static function assertFormParamTypes($value):void
{
if(!\is_array($value)){
self::invalidRequestOptionType('form_params','array<array-key, string|int|float|bool|null|array>',$value);
return;
}
self::assertFormParamArray($value,'form_params');
self::assertFiniteFloats($value,'form_params');
}
private static function assertFormParamArray(array$values,string$path):bool
{
foreach($values as$key=>$item){
$itemPath=$path.'.'.(string)$key;
if(\is_array($item)){
if(!self::assertFormParamArray($item,$itemPath)){
return false;
}
continue;
}
if($item!==null&&!\is_scalar($item)){
self::invalidRequestOptionType($itemPath,'string|int|float|bool|null|array',$item);
return false;
}
}
return true;
}
private static function assertFiniteFloats(array$values,string$option):void
{
foreach($values as$key=>$value){
if(\is_array($value)){
self::assertFiniteFloats($value,$option.'.'.(string)$key);
}elseif(\is_float($value)&&!\is_finite($value)){
throw new InvalidArgumentException(\sprintf('Passing a non-finite float to request option "%s" is invalid; non-finite floats are not supported.',DiagnosticValue::escape($option.'.'.(string)$key)));
}
}
}
private static function assertHeaderOptionTypes(#[\SensitiveParameter]$headers
):void{
if(!\is_array($headers)){
self::invalidRequestOptionType('headers','array<array-key, string|non-empty-array<array-key, string>>|null',$headers);
return;
}
foreach($headers as$name=>$value){
$path='headers.'.(string)$name;
if(\is_array($value)){
if($value===[]){
self::invalidRequestOptionType($path,'string|non-empty-array<array-key, string>',$value);
}
foreach($value as$index=>$item){
if(!\is_string($item)){
self::invalidRequestOptionType($path.'.'.(string)$index,'string',$item);
}
}
}elseif(!\is_string($value)){
self::invalidRequestOptionType($path,'string|non-empty-array<array-key, string>',$value);
}
}
}
private static function assertMultipartOptionTypes($multipart):void
{
if(!\is_array($multipart)){
self::invalidRequestOptionType('multipart','array<array-key, array{name: string|int, contents: mixed, headers?: array<array-key, string>, filename?: string}>',$multipart);
return;
}
foreach($multipart as$index=>$part){
$path='multipart.'.(string)$index;
if(!\is_array($part)){
self::invalidRequestOptionType($path,'array{name: string|int, contents: mixed, headers?: array<array-key, string>, filename?: string}',$part);
return;
}
if(!\array_key_exists('name',$part)||(!\is_string($part['name'])&&!\is_int($part['name']))){
self::invalidRequestOptionType($path.'.name','string|int',$part['name']??null);
}
if(!\array_key_exists('contents',$part)){
self::invalidRequestOptionType($path,'array{name: string|int, contents: mixed, headers?: array<array-key, string>, filename?: string}',$part);
}
if(\array_key_exists('headers',$part)){
if(!\is_array($part['headers'])){
self::invalidRequestOptionType($path.'.headers','array<array-key, string>',$part['headers']);
return;
}
foreach($part['headers']as$name=>$value){
if(!\is_string($value)){
self::invalidRequestOptionType($path.'.headers.'.(string)$name,'string',$value);
}
}
}
if(\array_key_exists('filename',$part)&&!\is_string($part['filename'])){
self::invalidRequestOptionType($path.'.filename','string',$part['filename']);
}
}
}
private static function assertProxyOptionTypes(#[\SensitiveParameter]array$options
):void{
if(!isset($options['proxy'])){
return;
}
if(!\is_string($options['proxy'])&&!\is_array($options['proxy'])){
self::invalidRequestOptionType('proxy','string|array{http?: string|null, https?: string|null, no?: string|array<array-key, string>|null}',$options['proxy']);
return;
}
if(!\is_array($options['proxy'])){
return;
}
foreach(['http','https']as$scheme){
if(\array_key_exists($scheme,$options['proxy'])&&$options['proxy'][$scheme]!==null&&!\is_string($options['proxy'][$scheme])){
self::invalidRequestOptionType('proxy.'.$scheme,'string|null',$options['proxy'][$scheme]);
}
}
if(!\array_key_exists('no',$options['proxy'])||$options['proxy']['no']===null){
return;
}
if(\is_string($options['proxy']['no'])){
return;
}
if(!\is_array($options['proxy']['no'])){
self::invalidRequestOptionType('proxy.no','string|array<array-key, string>|null',$options['proxy']['no']);
return;
}
foreach($options['proxy']['no']as$index=>$noProxy){
if(!\is_string($noProxy)){
self::invalidRequestOptionType('proxy.no.'.(string)$index,'string',$noProxy);
}
}
}
private static function assertTlsFileOptionTypes(#[\SensitiveParameter]array$options,string$option
):void{
if(!isset($options[$option])){
return;
}
if(\is_string($options[$option])){
return;
}
if(!\is_array($options[$option])){
self::invalidRequestOptionType($option,'string|array{0: string, 1?: string}',$options[$option]);
return;
}
if(!\array_key_exists(0,$options[$option])||!\is_string($options[$option][0])){
self::invalidRequestOptionType($option.'.0','string',$options[$option][0]??null);
}
if(\array_key_exists(1,$options[$option])&&$options[$option][1]!==null&&!\is_string($options[$option][1])){
self::invalidRequestOptionType($option.'.1','string|null',$options[$option][1]);
}
}
private static function assertIfPresentAndNotArray(#[\SensitiveParameter]array$options,string$option,string$expected
):void{
if(\array_key_exists($option,$options)&&!\is_array($options[$option])){
self::invalidRequestOptionType($option,$expected,$options[$option]);
}
}
private static function assertIfPresentAndNotBool(#[\SensitiveParameter]array$options,string$option,?string$path=null
):void{
if(\array_key_exists($option,$options)&&!\is_bool($options[$option])){
self::invalidRequestOptionType($path??$option,'bool',$options[$option]);
}
}
private static function assertValidMultiplex(#[\SensitiveParameter]array$options
):void{
if(!\array_key_exists('multiplex',$options)||$options['multiplex']===null){
return;
}
if(!\in_array($options['multiplex'],[Multiplexing::NONE,Multiplexing::EAGER,Multiplexing::WAIT,Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new InvalidArgumentException(\sprintf('The "multiplex" option must be null or a GuzzleHttp\\Multiplexing::* constant; received %s.',\get_debug_type($options['multiplex'])));
}
}
private static function assertIfPresentAndNotBoolOrInt(#[\SensitiveParameter]array$options,string$option
):void{
if(\array_key_exists($option,$options)&&!\is_bool($options[$option])&&!\is_int($options[$option])){
self::invalidRequestOptionType($option,'bool|int',$options[$option]);
}
}
private static function assertIfPresentAndNotBoolOrResource(#[\SensitiveParameter]array$options,string$option
):void{
if(\array_key_exists($option,$options)&&!\is_bool($options[$option])&&!\is_resource($options[$option])){
self::invalidRequestOptionType($option,'bool|resource',$options[$option]);
}
}
private static function assertIfPresentAndNotBoolOrString(#[\SensitiveParameter]array$options,string$option
):void{
if(\array_key_exists($option,$options)&&!\is_bool($options[$option])&&!\is_string($options[$option])){
self::invalidRequestOptionType($option,'bool|string',$options[$option]);
}
}
private static function assertIfPresentAndNotCallable(#[\SensitiveParameter]array$options,string$option,?string$path=null
):void{
if(\array_key_exists($option,$options)&&!\is_callable($options[$option])){
self::invalidRequestOptionType($path??$option,'callable',$options[$option]);
}
}
private static function assertIfPresentAndNotInt(#[\SensitiveParameter]array$options,string$option,?string$path=null
):void{
if(\array_key_exists($option,$options)&&!\is_int($options[$option])){
self::invalidRequestOptionType($path??$option,'int',$options[$option]);
}
}
private static function assertIfPresentAndNotNumber(#[\SensitiveParameter]array$options,string$option
):void{
if(\array_key_exists($option,$options)&&!\is_int($options[$option])&&!\is_float($options[$option])){
self::invalidRequestOptionType($option,'int|float',$options[$option]);
}
}
private static function assertIfPresentAndNotFiniteNonNegativeNumber(#[\SensitiveParameter]array$options,string$option
):void{
if(!\array_key_exists($option,$options)){
return;
}
if(!\is_int($options[$option])&&!\is_float($options[$option])){
self::invalidRequestOptionType($option,'finite int|float greater than or equal to 0',$options[$option]);
return;
}
if(!\is_finite((float)$options[$option])||$options[$option]<0){
self::invalidRequestOptionType($option,'finite int|float greater than or equal to 0',$options[$option]);
}
}
private static function assertIfPresentAndNotForceIpResolve(#[\SensitiveParameter]array$options
):void{
if(!\array_key_exists('force_ip_resolve',$options)){
return;
}
if(!\is_string($options['force_ip_resolve'])||($options['force_ip_resolve']!=='v4'&&$options['force_ip_resolve']!=='v6')){
self::invalidRequestOptionType('force_ip_resolve','"v4"|"v6"',$options['force_ip_resolve']);
}
}
private static function assertIfPresentAndNotString(#[\SensitiveParameter]array$options,string$option
):void{
if(\array_key_exists($option,$options)&&!\is_string($options[$option])){
self::invalidRequestOptionType($option,'string',$options[$option]);
}
}
private static function assertIfPresentAndNotProtocolArray(#[\SensitiveParameter]array$options,string$option,?string$path=null
):void{
if(!\array_key_exists($option,$options)){
return;
}
$path=$path??$option;
if(!\is_array($options[$option])||$options[$option]===[]){
self::invalidRequestOptionType($path,'non-empty-array<array-key, "http"|"https">',$options[$option]);
return;
}
foreach($options[$option]as$index=>$protocol){
if(!\is_string($protocol)){
self::invalidRequestOptionType($path.'.'.(string)$index,'string',$protocol);
continue;
}
if($protocol!=='http'&&$protocol!=='https'){
self::invalidRequestOptionType($path.'.'.(string)$index,'"http"|"https"',$protocol);
}
}
}
private static function assertIfPresentAndNotStringOrNumber(#[\SensitiveParameter]array$options,string$option
):void{
if(\array_key_exists($option,$options)&&!\is_string($options[$option])&&!\is_int($options[$option])&&!\is_float($options[$option])){
self::invalidRequestOptionType($option,'string|int|float',$options[$option]);
}
}
private static function invalidRequestOptionType(string$option,string$expected,#[\SensitiveParameter]$value
):void{
throw new InvalidArgumentException(\sprintf('Passing %s to request option "%s" is invalid; expected %s.',\get_debug_type($value),DiagnosticValue::escape($option),$expected
));
}
private function transfer(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$request=$this->applyOptions($request,$options);
$handler=$this->config['handler'];
try{
self::assertRequestProtocolVersion($request);
return P\Create::promiseFor($handler($request,$options));
}catch(\Throwable$e){
return P\Create::rejectionFor($e);
}
}
private function applyOptions(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$options
):RequestInterface{
$modify=['set_headers'=>[],];
self::requireResponseFactory($options[RequestOptions::RESPONSE_FACTORY]??new HttpFactory);
$streamFactory=self::requireStreamFactory($options[RequestOptions::STREAM_FACTORY]??new HttpFactory);
if(isset($options['headers'])){
if(array_keys($options['headers'])===range(0,count($options['headers'])-1)){
throw new InvalidArgumentException('The headers array must have header name as keys.');
}
$modify['set_headers']=$options['headers'];
unset($options['headers']);
}
if(isset($options['form_params'])){
if(isset($options['multipart'])){
throw new InvalidArgumentException('You cannot use '.'form_params and multipart at the same time. Use the '.'form_params option if you want to send application/'.'x-www-form-urlencoded requests, and the multipart '.'option to send multipart/form-data requests.');
}
$options['body']=\http_build_query($options['form_params'],'','&');
unset($options['form_params']);
$options['_conditional']=Psr7\Utils::caselessRemove(['Content-Type'],$options['_conditional']);
$options['_conditional']['Content-Type']='application/x-www-form-urlencoded';
}
if(isset($options['multipart'])){
$options['body']=new Psr7\MultipartStream($options['multipart']);
unset($options['multipart']);
}
if(isset($options['json'])){
try{
$options['body']=\json_encode($options['json'],\JSON_THROW_ON_ERROR);
}catch(\JsonException$e){
throw new InvalidArgumentException('json_encode error: '.$e->getMessage(),0,$e);
}
unset($options['json']);
$options['_conditional']=Psr7\Utils::caselessRemove(['Content-Type'],$options['_conditional']);
$options['_conditional']['Content-Type']='application/json';
}
if(isset($options['decode_content'])&&\is_string($options['decode_content'])){
$options['_conditional']=Psr7\Utils::caselessRemove(['Accept-Encoding'],$options['_conditional']);
$modify['set_headers']['Accept-Encoding']=(string)$options['decode_content'];
}
if(isset($options['body'])){
if(\is_array($options['body'])){
throw$this->invalidBody();
}
$modify['body']=self::createBodyStream($options['body'],$streamFactory);
unset($options['body']);
}
if(isset($options['query'])){
$value=$options['query'];
if(\is_array($value)){
self::assertFiniteFloats($value,'query');
$value=\http_build_query($value,'','&',\PHP_QUERY_RFC3986);
}
if(!\is_string($value)){
throw new InvalidArgumentException('query must be a string or array');
}
$modify['query']=$value;
unset($options['query']);
}
if(isset($options['version'])){
$modify['version']=self::normalizeProtocolVersion($options['version']);
}
$request=Psr7\Utils::modifyRequest($request,$modify);
if($request->getBody()instanceof Psr7\MultipartStream){
$options['_conditional']=Psr7\Utils::caselessRemove(['Content-Type'],$options['_conditional']);
$options['_conditional']['Content-Type']=self::getMultipartContentType($request->getBody());
}
if(isset($options['_conditional'])){
$modify=[];
foreach($options['_conditional']as$k=>$v){
$name=(string)$k;
if(!$request->hasHeader($name)){
$modify['set_headers'][$name]=$v;
}
}
$request=Psr7\Utils::modifyRequest($request,$modify);
unset($options['_conditional']);
}
return$request;
}
private static function normalizeProtocolVersion($version):string
{
$version=\is_float($version)?\number_format($version,1,'.',''):(string)$version;
self::assertProtocolVersion($version);
return$version;
}
private static function assertProtocolVersion(string$version):void
{
if(''===$version){
throw new InvalidArgumentException('HTTP protocol version must not be empty.');
}
if(1!==\preg_match('/^\d+(?:\.\d+)?$/D',$version)){
throw new InvalidArgumentException('HTTP protocol version must be a valid HTTP version number.');
}
}
private static function assertRequestProtocolVersion(#[\SensitiveParameter]RequestInterface$request
):void{
$version=$request->getProtocolVersion();
if(''===$version){
throw new RequestException('HTTP protocol version must not be empty.',$request);
}
if(1!==\preg_match('/^\d+(?:\.\d+)?$/D',$version)){
throw new RequestException('HTTP protocol version must be a valid HTTP version number.',$request);
}
}
private static function getMultipartContentType(Psr7\MultipartStream$body):string
{
$boundary=$body->getBoundary();
if(false!==\strpbrk($boundary,'()<>@,;:\"/[]?= ')){
$boundary='"'.$boundary.'"';
}
return'multipart/form-data; boundary='.$boundary;
}
private function invalidBody():InvalidArgumentException
{
return new InvalidArgumentException('Passing in the "body" request '.'option as an array to send a request is not supported. '.'Please use the "form_params" request option to send a '.'application/x-www-form-urlencoded request, or the "multipart" '.'request option to send a multipart/form-data request.');
}
}
declare(strict_types=1);
namespace GuzzleHttp\Cookie;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
interface CookieJarInterface extends\Countable,\IteratorAggregate
{
function withCookieHeader(RequestInterface$request):RequestInterface;
function extractCookies(RequestInterface$request,ResponseInterface$response):void;
function setCookie(SetCookie$cookie):bool;
function clear(?string$domain=null,?string$path=null,?string$name=null):void;
function clearSessionCookies():void;
function toArray():array;
}
declare(strict_types=1);
namespace GuzzleHttp\Cookie;
use GuzzleHttp\HostIdentity;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
class CookieJar implements CookieJarInterface
{
private const MAX_SET_COOKIE_FIELD_LENGTH=8190;
private const MAX_SET_COOKIE_FIELDS=50;
private const MAX_REQUEST_COOKIES=150;
private const MAX_COOKIE_HEADER_LENGTH=8190;
private array$cookies=[];
private bool$strictMode;
function __construct(bool$strictMode=false,#[\SensitiveParameter]array$cookieArray=[]){
$this->strictMode=$strictMode;
foreach($cookieArray as$cookie){
if(!$cookie instanceof SetCookie){
$cookie=new SetCookie($cookie);
}
$this->setCookie($cookie);
}
}
static function fromArray(#[\SensitiveParameter]array$cookies,string$domain
):self{
$cookieJar=new self;
foreach($cookies as$name=>$value){
if(!\is_scalar($value)&&!(\is_object($value)&&\method_exists($value,'__toString'))){
throw new\InvalidArgumentException('Cookie value must be scalar or stringable');
}
$cookieJar->setCookie(new SetCookie(['Domain'=>$domain,'Name'=>(string)$name,'Value'=>(string)$value,'Discard'=>true,]));
}
return$cookieJar;
}
static function shouldPersist(SetCookie$cookie,bool$allowSessionCookies=false):bool
{
if($cookie->getExpires()||$allowSessionCookies){
if(!$cookie->getDiscard()){
return true;
}
}
return false;
}
function getCookieByName(string$name):?SetCookie
{
foreach($this->cookies as$cookie){
if($cookie->getName()===$name){
return$cookie;
}
}
return;
}
function toArray():array
{
return\array_map(static function(SetCookie$cookie):array{
return$cookie->toArray();
},$this->getIterator()->getArrayCopy());
}
function clear(?string$domain=null,?string$path=null,?string$name=null):void
{
if($domain===null){
$this->cookies=[];
return;
}elseif($path===null){
$this->cookies=\array_filter($this->cookies,static function(SetCookie$cookie)use($domain):bool{
return$cookie->getDomain()===null||!$cookie->matchesDomain($domain);
}
);
}elseif($name===null){
$this->cookies=\array_filter($this->cookies,static function(SetCookie$cookie)use($path,$domain):bool{
return!($cookie->getDomain()!==null
&&$cookie->matchesPath($path)&&$cookie->matchesDomain($domain));
}
);
}else{
$this->cookies=\array_filter($this->cookies,static function(SetCookie$cookie)use($path,$domain,$name):bool{
return!($cookie->getDomain()!==null
&&$cookie->getName()===$name
&&$cookie->matchesPath($path)&&$cookie->matchesDomain($domain));
}
);
}
}
function clearSessionCookies():void
{
$this->cookies=\array_filter($this->cookies,static function(SetCookie$cookie):bool{
return!$cookie->getDiscard()&&$cookie->getExpires();
}
);
}
function setCookie(#[\SensitiveParameter]SetCookie$cookie
):bool{
$name=$cookie->getName();
if(!$name&&$name!=='0'){
return false;
}
$result=$cookie->validate();
if($result!==true){
if($this->strictMode){
throw new\RuntimeException('Invalid cookie: '.$result);
}
$this->removeCookieIfEmpty($cookie);
return false;
}
$maxAge=$cookie->getMaxAge();
if($maxAge!==null&&$maxAge<=0){
if($cookie->getDomain()!==null){
$this->removeCookie($cookie);
}
return false;
}
foreach($this->cookies as$i=>$c){
if($c->getPath()!==$cookie->getPath()||$c->getDomain()!==$cookie->getDomain()||$c->getHostOnly()!==$cookie->getHostOnly()||$c->getName()!==$cookie->getName()){
continue;
}
if(!$cookie->getDiscard()&&$c->getDiscard()){
unset($this->cookies[$i]);
continue;
}
if($cookie->getExpires()>$c->getExpires()){
unset($this->cookies[$i]);
continue;
}
if($cookie->getValue()!==$c->getValue()){
unset($this->cookies[$i]);
continue;
}
return false;
}
$this->cookies[]=$cookie;
return true;
}
function count():int
{
return\count($this->cookies);
}
function getIterator():\ArrayIterator
{
return new\ArrayIterator(\array_values($this->cookies));
}
function extractCookies(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response
):void{
if($cookieHeader=$response->getHeader('Set-Cookie')){
$uri=$request->getUri();
$requestHost=HostIdentity::canonicalHost($uri->getHost());
$secure=$uri->getScheme()==='https';
$accepted=0;
foreach($cookieHeader as$cookie){
if(\strlen($cookie)>self::MAX_SET_COOKIE_FIELD_LENGTH){
continue;
}
$sc=SetCookie::fromString($cookie);
$domain=$sc->getDomain();
if($domain===null||$domain===''){
$sc->setDomain($requestHost);
$sc->setHostOnly(true);
}else{
$sc->setHostOnly(false);
}
if(0!==\strpos($sc->getPath(),'/')){
$sc->setPath($this->getCookiePathFromRequest($request));
}
if(!$sc->matchesDomain($requestHost)){
continue;
}
if(!$secure&&($sc->getSecure()||$this->overlaysSecureCookie($sc))){
continue;
}
$prefixName=Psr7\Utils::asciiToLower((string)$sc->getName());
if(\str_starts_with($prefixName,'__secure-')&&!$sc->getSecure()){
continue;
}
if(\str_starts_with($prefixName,'__host-')&&(!$sc->getSecure()||!$sc->getHostOnly()||$sc->getPath()!=='/'||!self::hasPathAttribute($cookie))){
continue;
}
if($this->setCookie($sc)&&++$accepted===self::MAX_SET_COOKIE_FIELDS){
break;
}
}
}
}
private function overlaysSecureCookie(SetCookie$cookie):bool
{
foreach($this->cookies as$stored){
if(self::isSecureCookieOverlay($cookie,$stored)){
return true;
}
}
return false;
}
private static function isSecureCookieOverlay(SetCookie$cookie,SetCookie$stored):bool
{
if($stored->getName()!==$cookie->getName()||!$stored->getSecure()||$stored->isExpired()){
return false;
}
$domain=$cookie->getDomain();
$storedDomain=$stored->getDomain();
if($domain===null||$storedDomain===null){
return false;
}
if(!HostIdentity::cookieDomainMatches($storedDomain,$domain)&&!HostIdentity::cookieDomainMatches($domain,$storedDomain)){
return false;
}
return$stored->matchesPath($cookie->getPath());
}
private static function hasPathAttribute(string$header):bool
{
$parts=\explode(';',$header);
\array_shift($parts);
foreach($parts as$part){
$separator=\strpos($part,'=');
if($separator!==false&&Psr7\Utils::caselessEquals(\trim(\substr($part,0,$separator)," \t"),'Path')){
return true;
}
}
return false;
}
private function getCookiePathFromRequest(RequestInterface$request):string
{
$uriPath=$request->getUri()->getPath();
if(''===$uriPath){
return'/';
}
if(0!==\strpos($uriPath,'/')){
return'/';
}
if('/'===$uriPath){
return'/';
}
$lastSlashPos=\strrpos($uriPath,'/');
if(0===$lastSlashPos||false===$lastSlashPos){
return'/';
}
return\substr($uriPath,0,$lastSlashPos);
}
function withCookieHeader(#[\SensitiveParameter]RequestInterface$request
):RequestInterface{
$values=[];
$headerLength=8;
$uri=$request->getUri();
$scheme=$uri->getScheme();
$host=HostIdentity::canonicalHost($uri->getHost());
$path=$uri->getPath()?:'/';
foreach($this->cookies as$cookie){
if($cookie->getDomain()!==null
&&$cookie->matchesPath($path)&&$cookie->matchesDomain($host)&&!$cookie->isExpired()&&(!$cookie->getSecure()||$scheme==='https')){
$name=(string)$cookie->getName();
$value=(string)$cookie->getValue();
$separatorLength=$values===[]?0:2;
$valueLength=\strlen($name)+1+\strlen($value);
if($headerLength+$separatorLength+$valueLength>self::MAX_COOKIE_HEADER_LENGTH){
break;
}
$values[]=$name.'='.$value;
$headerLength+=$separatorLength+$valueLength;
if(\count($values)===self::MAX_REQUEST_COOKIES){
break;
}
}
}
return$values
?$request->withHeader('Cookie',\implode('; ',$values)):$request;
}
private function removeCookieIfEmpty(SetCookie$cookie):void
{
$cookieValue=$cookie->getValue();
if(($cookieValue===null||$cookieValue==='')&&$cookie->getDomain()!==null){
$this->removeCookie($cookie);
}
}
private function removeCookie(SetCookie$cookie):void
{
$this->cookies=\array_filter($this->cookies,static function(SetCookie$stored)use($cookie):bool{
return!($stored->getName()===$cookie->getName()&&$stored->getPath()===$cookie->getPath()&&$stored->getDomain()===$cookie->getDomain()&&$stored->getHostOnly()===$cookie->getHostOnly());
}
);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Cookie;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\DiagnosticValue;
class FileCookieJar extends CookieJar
{
use NonSerializableTrait;
private string$filename;
private bool$storeSessionCookies;
private bool$autoSave=false;
function __construct(string$cookieFile,bool$storeSessionCookies=false){
parent::__construct();
$this->filename=$cookieFile;
$this->storeSessionCookies=$storeSessionCookies;
if(\file_exists($cookieFile)){
$this->load($cookieFile);
}
$this->autoSave=true;
}
function __destruct(){
if($this->autoSave){
$this->save($this->filename);
}
}
function __wakeup():void
{
$this->autoSave=false;
}
function __unserialize(array$data):void
{
$this->autoSave=false;
throw new\LogicException(static::class.' should never be unserialized');
}
function save(string$filename):void
{
$json=[];
foreach($this as$cookie){
if(CookieJar::shouldPersist($cookie,$this->storeSessionCookies)){
$data=$cookie->toArray();
$data['HostOnly']=$cookie->getHostOnly();
$json[]=$data;
}
}
try{
$jsonStr=\json_encode($json,\JSON_HEX_TAG|\JSON_THROW_ON_ERROR);
}catch(\JsonException$e){
throw new\RuntimeException('Unable to encode cookie data',0,$e);
}
if(false===\file_put_contents($filename,$jsonStr,\LOCK_EX)){
throw new\RuntimeException(\sprintf('Unable to save file %s',DiagnosticValue::escape($filename)));
}
@\chmod($filename,384);
}
function load(string$filename):void
{
$json=\file_get_contents($filename);
if(false===$json){
throw new\RuntimeException(\sprintf('Unable to load file %s',DiagnosticValue::escape($filename)));
}
if($json===''){
return;
}
$message=\sprintf('Invalid cookie file: %s',DiagnosticValue::escape($filename));
try{
$data=\json_decode($json,true,512,\JSON_THROW_ON_ERROR);
}catch(\JsonException$e){
throw new\RuntimeException($message,0,$e);
}
if(!\is_array($data)||\substr($json,\strspn($json," \t\n\r"),1)!=='['){
throw new\RuntimeException($message);
}
$cookies=[];
foreach($data as$cookie){
if(!\is_array($cookie)||!\array_key_exists('HostOnly',$cookie)||!\is_bool($cookie['HostOnly'])){
throw new\RuntimeException($message);
}
try{
$cookies[]=new SetCookie($cookie);
}catch(\InvalidArgumentException$e){
throw new\RuntimeException($message,0,$e);
}
}
foreach($cookies as$cookie){
$this->setCookie($cookie);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Cookie;
use GuzzleHttp\NonSerializableTrait;
class SessionCookieJar extends CookieJar
{
use NonSerializableTrait;
private string$sessionKey;
private bool$storeSessionCookies;
private bool$autoSave=false;
function __construct(string$sessionKey,bool$storeSessionCookies=false){
parent::__construct();
$this->sessionKey=$sessionKey;
$this->storeSessionCookies=$storeSessionCookies;
$this->load();
$this->autoSave=true;
}
function __destruct(){
if($this->autoSave){
$this->save();
}
}
function __wakeup():void
{
$this->autoSave=false;
}
function __unserialize(array$data):void
{
$this->autoSave=false;
throw new\LogicException(static::class.' should never be unserialized');
}
function save():void
{
$json=[];
foreach($this as$cookie){
if(CookieJar::shouldPersist($cookie,$this->storeSessionCookies)){
$data=$cookie->toArray();
$data['HostOnly']=$cookie->getHostOnly();
$json[]=$data;
}
}
try{
$json=\json_encode($json,\JSON_THROW_ON_ERROR);
}catch(\JsonException$e){
throw new\RuntimeException('Unable to encode cookie data',0,$e);
}
$_SESSION[$this->sessionKey]=$json;
}
protected function load():void
{
if(!isset($_SESSION[$this->sessionKey])){
return;
}
$message='Invalid cookie data';
$json=$_SESSION[$this->sessionKey];
if(!\is_string($json)){
throw new\RuntimeException($message);
}
try{
$data=\json_decode($json,true,512,\JSON_THROW_ON_ERROR);
}catch(\JsonException$e){
throw new\RuntimeException($message,0,$e);
}
if(!\is_array($data)||\substr($json,\strspn($json," \t\n\r"),1)!=='['){
throw new\RuntimeException($message);
}
$cookies=[];
foreach($data as$cookie){
if(!\is_array($cookie)||!\array_key_exists('HostOnly',$cookie)||!\is_bool($cookie['HostOnly'])){
throw new\RuntimeException($message);
}
try{
$cookies[]=new SetCookie($cookie);
}catch(\InvalidArgumentException$e){
throw new\RuntimeException($message,0,$e);
}
}
foreach($cookies as$cookie){
$this->setCookie($cookie);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Cookie;
use GuzzleHttp\HostIdentity;
use GuzzleHttp\Psr7;
class SetCookie
{
private const DEFAULTS=['Name'=>null,'Value'=>null,'Domain'=>null,'Path'=>'/','Max-Age'=>null,'Expires'=>null,'Secure'=>false,'Discard'=>false,'HttpOnly'=>false,];
private array$data;
private bool$hostOnly=false;
static function fromString(#[\SensitiveParameter]string$cookie
):self{
$data=self::DEFAULTS;
$pieces=\array_filter(\array_map(static function(string$piece):string{
return\trim($piece," \t");
},\explode(';',$cookie)));
if(!isset($pieces[0])||\strpos($pieces[0],'=')===false){
return new self($data);
}
foreach($pieces as$part){
$cookieParts=\explode('=',$part,2);
$key=\trim($cookieParts[0]," \t");
$value=isset($cookieParts[1])?\trim($cookieParts[1]," \t"):true;
if(!isset($data['Name'])){
$data['Name']=$key;
$data['Value']=$value;
}else{
foreach(\array_keys(self::DEFAULTS)as$search){
if(Psr7\Utils::caselessEquals($search,$key)){
if($search==='Max-Age'){
if(\is_string($value)&&\preg_match('/^[+-]?[0-9]+$/D',$value)===1){
$maxAge=self::parseNumericInteger($value);
if($maxAge!==null){
$data[$search]=$maxAge;
}
}
}elseif($search==='Secure'||$search==='Discard'||$search==='HttpOnly'){
if($value){
$data[$search]=true;
}
}elseif(\is_string($value)){
$data[$search]=$value;
}
continue 2;
}
}
if(Psr7\Utils::caselessEquals('HostOnly',$key)){
continue;
}
$data[$key]=$value;
}
}
return new self($data);
}
function __construct(#[\SensitiveParameter]array$data=[]){
$this->data=self::DEFAULTS;
self::validateFieldTypes($data);
if(\array_key_exists('HostOnly',$data)){
$this->setHostOnly($data['HostOnly']);
unset($data['HostOnly']);
}
if(isset($data['Name'])){
$this->setName($data['Name']);
}
if(isset($data['Value'])){
$this->setValue($data['Value']);
}
if(isset($data['Domain'])){
$this->setDomain($data['Domain']);
}
if(isset($data['Path'])){
$this->setPath($data['Path']);
}
if(isset($data['Max-Age'])){
$this->setMaxAge($data['Max-Age']);
}
if(isset($data['Expires'])){
$this->setExpires($data['Expires']);
}
if(isset($data['Secure'])){
$this->setSecure($data['Secure']);
}
if(isset($data['Discard'])){
$this->setDiscard($data['Discard']);
}
if(isset($data['HttpOnly'])){
$this->setHttpOnly($data['HttpOnly']);
}
foreach(array_diff(array_keys($data),array_keys(self::DEFAULTS))as$key){
$this->data[$key]=$data[$key];
}
$maxAge=$this->getMaxAge();
if($maxAge!==null){
$this->setExpires(self::maxAgeToExpires($maxAge,\time()));
}
}
function __toString():string
{
$str=$this->data['Name'].'='.($this->data['Value']??'').'; ';
foreach($this->data as$k=>$v){
if($k==='Domain'&&$this->getHostOnly()){
continue;
}
if($k!=='Name'&&$k!=='Value'&&$v!==null&&$v!==false){
if($k==='Expires'){
$str.='Expires='.\gmdate('D, d M Y H:i:s \G\M\T',$v).'; ';
}else{
$str.=($v===true?$k:"{$k}={$v}").'; ';
}
}
}
return\rtrim($str,'; ');
}
function toArray():array
{
$data=$this->data;
if($this->getHostOnly()){
$data['HostOnly']=true;
}
return$data;
}
function getName():?string
{
return$this->data['Name'];
}
function setName(string$name):void
{
$this->data['Name']=$name;
}
function getValue():?string
{
return$this->data['Value'];
}
function setValue(string$value):void
{
$this->data['Value']=$value;
}
function getDomain():?string
{
return$this->data['Domain'];
}
function setDomain(?string$domain):void
{
$this->data['Domain']=null===$domain?null:self::normalizeDomain($domain);
}
function getHostOnly():bool
{
return$this->hostOnly;
}
function setHostOnly(bool$hostOnly):void
{
$this->hostOnly=$hostOnly;
}
function getPath():string
{
return$this->data['Path'];
}
function setPath(string$path):void
{
$this->data['Path']=$path;
}
function getMaxAge():?int
{
return null===$this->data['Max-Age']?null:(int)$this->data['Max-Age'];
}
function setMaxAge(?int$maxAge):void
{
$this->data['Max-Age']=$maxAge;
}
function getExpires():?int
{
return$this->data['Expires'];
}
function setExpires($timestamp):void
{
if(!is_int($timestamp)&&!is_string($timestamp)&&null!==$timestamp){
throw new\TypeError(__METHOD__.'(): Argument #1 ($timestamp) must be of type int|string|null');
}
if($timestamp===null){
$this->data['Expires']=null;
return;
}
if(\is_string($timestamp)){
if(\is_numeric($timestamp)){
$this->data['Expires']=self::parseNumericInteger($timestamp);
return;
}
}elseif(\is_int($timestamp)){
$this->data['Expires']=$timestamp;
return;
}
$expires=\strtotime($timestamp);
$this->data['Expires']=$expires===false?null:$expires;
}
function getSecure():bool
{
return$this->data['Secure'];
}
function setSecure(bool$secure):void
{
$this->data['Secure']=$secure;
}
function getDiscard():bool
{
return$this->data['Discard'];
}
function setDiscard(bool$discard):void
{
$this->data['Discard']=$discard;
}
function getHttpOnly():bool
{
return$this->data['HttpOnly'];
}
function setHttpOnly(bool$httpOnly):void
{
$this->data['HttpOnly']=$httpOnly;
}
function matchesPath(string$requestPath):bool
{
$cookiePath=$this->getPath();
if($cookiePath==='/'||$cookiePath===$requestPath){
return true;
}
if(0!==\strpos($requestPath,$cookiePath)){
return false;
}
if(\substr($cookiePath,-1,1)==='/'){
return true;
}
return\substr($requestPath,\strlen($cookiePath),1)==='/';
}
function matchesDomain(string$domain):bool
{
$cookieDomain=$this->getDomain();
if(null===$cookieDomain||$cookieDomain===''){
return false;
}
if($this->getHostOnly()){
return HostIdentity::canonicalCookieDomain($domain)===HostIdentity::canonicalCookieDomain($cookieDomain);
}
return HostIdentity::cookieDomainMatches($domain,$cookieDomain);
}
function isExpired():bool
{
return$this->getExpires()!==null&&\time()>$this->getExpires();
}
function validate(){
$name=$this->getName();
if($name===null||$name===''){
return'The cookie name must not be empty';
}
if(\preg_match('/[\x00-\x20\x22\x28-\x29\x2c\x2f\x3a-\x40\x5c\x7b\x7d\x7f]/',$name)!==0){
return'Cookie name must not contain invalid characters: ASCII '.'Control characters (0-31;127), space, tab and the '.'following characters: ()<>@,;:\"/?={}';
}
$value=$this->getValue();
if($value===null){
return'The cookie value must not be empty';
}
$domain=$this->getDomain();
if($domain===''||($domain!==null&&\ltrim(\trim($domain," \n\r\t\0\x0B"),'.')==='')){
return'The cookie domain must not be empty';
}
if($this->getHostOnly()&&$domain===null){
return'Host-only cookies must have a domain';
}
return true;
}
private static function normalizeDomain(string$domain):string
{
$domain=Psr7\Utils::asciiToLower($domain);
if($domain!==''&&\substr($domain,-1)==='.'&&\trim($domain,'.')!==''){
return'';
}
if($domain!==''&&$domain!=='.'&&$domain[0]==='.'){
$domain=\substr_replace($domain,'',0,1);
}
return HostIdentity::canonicalCookieDomain($domain);
}
private static function maxAgeToExpires(int$maxAge,int$now):int
{
if($maxAge<=0){
return$now-1;
}
if($maxAge>\PHP_INT_MAX-$now){
return\PHP_INT_MAX;
}
return$now+$maxAge;
}
private static function parseNumericInteger(string$value):?int
{
if(!\is_numeric($value)){
return;
}
if(\preg_match('/^[+-]?[0-9]+$/D',$value)===1){
$negative=$value[0]==='-';
$digits=\ltrim($value,'+-');
$digits=\ltrim($digits,'0');
$digits=$digits===''?'0':$digits;
$limit=$negative?\substr((string)\PHP_INT_MIN,1):(string)\PHP_INT_MAX;
if(\strlen($digits)>\strlen($limit)||(\strlen($digits)===\strlen($limit)&&\strcmp($digits,$limit)>0)){
return;
}
return(int)($negative?'-'.$digits:$digits);
}
$number=(float)$value;
if(!\is_finite($number)||$number<\PHP_INT_MIN||$number>\PHP_INT_MAX){
return;
}
if(\PHP_INT_SIZE===8&&($number<=(float)\PHP_INT_MIN||$number>=(float)\PHP_INT_MAX)){
return;
}
return(int)$number;
}
private static function validateFieldTypes(#[\SensitiveParameter]array$data
):void{
foreach(['Name','Value','Domain','Path']as$field){
if(isset($data[$field])&&!\is_string($data[$field])){
throw new\InvalidArgumentException(\sprintf('Cookie field "%s" must be a string',$field));
}
}
if(isset($data['Max-Age'])&&!\is_int($data['Max-Age'])){
throw new\InvalidArgumentException('Cookie field "Max-Age" must be an integer');
}
if(isset($data['Expires'])&&!\is_int($data['Expires'])&&!\is_string($data['Expires'])){
throw new\InvalidArgumentException('Cookie field "Expires" must be an integer or string');
}
foreach(['Secure','Discard','HttpOnly']as$field){
if(isset($data[$field])&&!\is_bool($data[$field])){
throw new\InvalidArgumentException(\sprintf('Cookie field "%s" must be a boolean',$field));
}
}
if(\array_key_exists('HostOnly',$data)&&!\is_bool($data['HostOnly'])){
throw new\InvalidArgumentException('Cookie field "HostOnly" must be a boolean');
}
}
}
declare(strict_types=1);
namespace GuzzleHttp;
final class Env
{
private function __construct(){
}
static function get(string$name):?string
{
if(isset($_SERVER[$name])){
return(string)$_SERVER[$name];
}
if(\PHP_SAPI==='cli'&&($value=\getenv($name))!==false&&$value!==null){
return(string)$value;
}
return;
}
}
namespace Psr\Http\Client;
interface ClientExceptionInterface extends\Throwable
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
use Psr\Http\Client\ClientExceptionInterface;
interface GuzzleException extends ClientExceptionInterface
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
use Psr\Http\Message\RequestInterface;
class TransferException extends\RuntimeException implements GuzzleException
{
private RequestInterface$request;
function __construct(string$message,RequestInterface$request,int$code=0,?\Throwable$previous=null
){
parent::__construct($message,$code,$previous);
$this->request=$request;
}
function getRequest():RequestInterface
{
return$this->request;
}
}
namespace Psr\Http\Client;
use Psr\Http\Message\RequestInterface;
interface RequestExceptionInterface extends ClientExceptionInterface
{
function getRequest():RequestInterface;
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
use GuzzleHttp\BodySummarizer;
use GuzzleHttp\BodySummarizerInterface;
use GuzzleHttp\Psr7\DiagnosticValue;
use Psr\Http\Client\RequestExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
class RequestException extends TransferException implements RequestExceptionInterface
{
function __construct(string$message,RequestInterface$request,int$code=0,?\Throwable$previous=null
){
parent::__construct($message,$request,$code,$previous);
}
static function create(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]?ResponseInterface$response=null,#[\SensitiveParameter]?\Throwable$previous=null,?BodySummarizerInterface$bodySummarizer=null
):self{
if(!$response){
return new self('Error completing request',$request,0,$previous
);
}
$level=(int)\floor($response->getStatusCode()/100);
if($level===4){
$label='Client error';
}elseif($level===5){
$label='Server error';
}else{
$label='Unsuccessful request';
}
$uri=\GuzzleHttp\Psr7\Utils::redactUriForMessage($request->getUri());
$message=\sprintf('%s: `%s %s` resulted in a `%s %s` response',$label,DiagnosticValue::escape($request->getMethod()),$uri,$response->getStatusCode(),DiagnosticValue::escape($response->getReasonPhrase()));
$summary=($bodySummarizer??new BodySummarizer)->summarize($response);
if($summary!==null){
$message.=\sprintf(': %s',DiagnosticValue::escape($summary));
}
if($level===4){
return new ClientException($message,$request,$response,$previous);
}
if($level===5){
return new ServerException($message,$request,$response,$previous);
}
return new ResponseException($message,$request,$response,$previous);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
class ResponseException extends RequestException
{
private ResponseInterface$response;
final  function __construct(string$message,#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]?\Throwable$previous=null
){
parent::__construct($message,$request,$response->getStatusCode(),$previous);
$this->response=$response;
}
function withResponse(#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]?\Throwable$previous=null
):self{
if($response->getStatusCode()!==$this->response->getStatusCode()){
throw new InvalidArgumentException('Cannot replace response with a different status code.');
}
return new static($this->getMessage(),$this->getRequest(),$response,$previous??$this->getPrevious());
}
function getResponse():ResponseInterface
{
return$this->response;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class BadResponseException extends ResponseException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class ClientException extends BadResponseException
{
}
namespace Psr\Http\Client;
use Psr\Http\Message\RequestInterface;
interface NetworkExceptionInterface extends ClientExceptionInterface
{
function getRequest():RequestInterface;
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
class NetworkException extends TransferException implements NetworkExceptionInterface
{
function __construct(string$message,RequestInterface$request,?\Throwable$previous=null
){
parent::__construct($message,$request,0,$previous);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class ConnectException extends NetworkException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class ConnectTimeoutException extends ConnectException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class HandlerClosedException extends TransferException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
final class InvalidArgumentException extends\InvalidArgumentException implements GuzzleException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class NetworkTimeoutException extends NetworkException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class ResponseTransferException extends ResponseException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class ResponseTimeoutException extends ResponseTransferException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class ServerException extends BadResponseException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Exception;
class TooManyRedirectsException extends ResponseException
{
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\DiagnosticValue;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
class HandlerStack
{
use NonSerializableTrait;
private$handler;
private array$stack=[];
private$cached;
static function create(?callable$handler=null):self
{
$stack=new self($handler?:Utils::chooseHandler());
$stack->push(Middleware::httpErrors(),'http_errors');
$stack->push(Middleware::redirect(),'allow_redirects');
$stack->push(Middleware::auth(),'auth');
$stack->push(Middleware::cookies(),'cookies');
$stack->push(Middleware::prepareBody(),'prepare_body');
return$stack;
}
function __construct(?callable$handler=null){
$this->handler=$handler;
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
){
$handler=$this->resolve();
return$handler($request,$options);
}
function setHandler(callable$handler):void
{
$this->handler=$handler;
$this->cached=null;
}
function hasHandler():bool
{
return$this->handler!==null;
}
function unshift(callable$middleware,?string$name=null):void
{
\array_unshift($this->stack,[$middleware,$name]);
$this->cached=null;
}
function push(callable$middleware,string$name=''):void
{
$this->stack[]=[$middleware,$name];
$this->cached=null;
}
function before(string$findName,callable$middleware,string$withName=''):void
{
$this->splice($findName,$withName,$middleware,true);
}
function after(string$findName,callable$middleware,string$withName=''):void
{
$this->splice($findName,$withName,$middleware,false);
}
function remove($remove):void
{
if(!\is_string($remove)&&!\is_callable($remove)){
throw new\TypeError(__METHOD__.'(): Argument #1 ($remove) must be of type callable|string');
}
$this->cached=null;
if(\is_string($remove)){
$count=\count($this->stack);
$this->stack=\array_values(\array_filter($this->stack,static function(array$tuple)use($remove):bool{
return$tuple[1]!==$remove;
}
));
if($count!==\count($this->stack)||!\is_callable($remove)){
return;
}
}
$this->stack=\array_values(\array_filter($this->stack,static function(array$tuple)use($remove):bool{
return$tuple[0]!==$remove;
}
));
}
function resolve():callable
{
if($this->cached===null){
if(($prev=$this->handler)===null){
throw new\LogicException('No handler has been specified');
}
if(!\is_callable($prev)){
throw new\LogicException('Handler must be callable');
}
foreach(\array_reverse($this->stack)as$fn){
if(!\is_array($fn)||!\array_key_exists(0,$fn)||!\is_callable($fn[0])){
throw new\LogicException('Middleware must be callable');
}
$prev=$fn[0]($prev);
if(!\is_callable($prev)){
throw new\LogicException('Middleware must return a callable');
}
}
$this->cached=$prev;
}
return$this->cached;
}
function __unserialize(array$data):void
{
$this->handler=null;
$this->stack=[];
$this->cached=null;
throw new\LogicException(static::class.' should never be unserialized');
}
private function findByName(string$name):int
{
foreach($this->stack as$k=>$v){
if($v[1]===$name){
return$k;
}
}
throw new\InvalidArgumentException(\sprintf('Middleware not found: %s',DiagnosticValue::escape($name)));
}
private function splice(string$findName,string$withName,callable$middleware,bool$before):void
{
$this->cached=null;
$idx=$this->findByName($findName);
$tuple=[$middleware,$withName];
if($before){
if($idx===0){
\array_unshift($this->stack,$tuple);
}else{
$replacement=[$tuple,$this->stack[$idx]];
\array_splice($this->stack,$idx,1,$replacement);
}
}elseif($idx===\count($this->stack)-1){
$this->stack[]=$tuple;
}else{
$replacement=[$this->stack[$idx],$tuple];
\array_splice($this->stack,$idx,1,$replacement);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
trait StreamDecoratorTrait
{
function __construct(StreamInterface$stream){
$this->stream=$stream;
}
function __get(string$name):StreamInterface
{
if($name==='stream'){
$this->stream=$this->createStream();
return$this->stream;
}
throw new\UnexpectedValueException(\sprintf('%s not found on class',DiagnosticValue::escape($name)));
}
function __toString():string
{
if($this->isSeekable()){
$this->seek(0);
}
return$this->getContents();
}
function getContents():string
{
return Utils::copyToString($this);
}
function __call(string$method,array$args){
$callable=[$this->stream,$method];
$result=($callable)(...$args);
return$result===$this->stream?$this:$result;
}
function close():void
{
$this->stream->close();
}
function getMetadata(?string$key=null){
return$this->stream->getMetadata($key);
}
function detach(){
return$this->stream->detach();
}
function getSize():?int
{
return$this->stream->getSize();
}
function eof():bool
{
return$this->stream->eof();
}
function tell():int
{
return$this->stream->tell();
}
function isReadable():bool
{
return$this->stream->isReadable();
}
function isWritable():bool
{
return$this->stream->isWritable();
}
function isSeekable():bool
{
return$this->stream->isSeekable();
}
function rewind():void
{
$this->seek(0);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
$this->stream->seek($offset,$whence);
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
return$this->stream->read($length);
}
function write(string$string):int
{
return$this->stream->write($string);
}
protected function createStream():StreamInterface
{
throw new\BadMethodCallException('Not implemented');
}
}
namespace Psr\Http\Message;
interface StreamInterface
{
function __toString():string;
function close():void;
function detach();
function getSize():?int;
function tell():int;
function eof():bool;
function isSeekable():bool;
function seek(int$offset,int$whence=SEEK_SET):void;
function rewind():void;
function isWritable():bool;
function write(string$string):int;
function isReadable():bool;
function read(int$length):string;
function getContents():string;
function getMetadata(?string$key=null);
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\StreamWrapper;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
final class ChunkedBodyStream implements StreamInterface
{
use NonSerializableTrait;
use StreamDecoratorTrait;
private const READ_SIZE=8192;
private const MAX_SIZE_DIGITS=17;
private const MAX_TRAILER_LINE_LENGTH=4093;
private const MAX_TRAILER_SECTION_LENGTH=307200;
private const SIZE=0;
private const SIZE_LINE=1;
private const DATA=2;
private const DATA_END=3;
private const TRAILER=4;
private const TRAILER_CR=5;
private const FINAL_CR=6;
private const DONE=7;
private StreamInterface$stream;
private string$buffer='';
private int$offset=0;
private int$state=self::SIZE;
private string$digits='';
private int$remaining=0;
private string$line='';
private int$trailerLength=0;
private int$position=0;
private?\RuntimeException$failure=null;
private bool$detachable=true;
function __construct(StreamInterface$stream){
$this->stream=$stream;
}
function __clone(){
$this->detachable=false;
}
function read(int$length):string
{
if($this->failure!==null){
throw$this->failure;
}
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
do{
$data=$this->decode($length);
}while($data===''&&$length>0&&!$this->eof()&&$this->fill());
$this->position=TransferByteCounter::add($this->position,\strlen($data),'Response body exceeds the maximum integer size supported on this platform');
return$data;
}
function eof():bool
{
return$this->state===self::DONE;
}
function getMetadata(?string$key=null){
if($this->failure!==null&&$key==='timed_out'){
return false;
}
$metadata=$this->stream->getMetadata($key);
if($this->failure!==null&&$key===null&&\is_array($metadata)){
$metadata['timed_out']=false;
}
return$metadata;
}
function tell():int
{
return$this->position;
}
function getSize():?int
{
return;
}
function isSeekable():bool
{
return false;
}
function seek(int$offset,int$whence=\SEEK_SET):void
{
throw new\RuntimeException('Cannot seek a chunked response body');
}
function isWritable():bool
{
return false;
}
function write(string$string):int
{
throw new\RuntimeException('Cannot write to a chunked response body');
}
function close():void
{
$this->buffer='';
$this->offset=0;
$this->detachable=false;
$this->stream->close();
}
function detach(){
if(!$this->detachable){
return;
}
if($this->state===self::DONE){
return$this->stream->detach();
}
if($this->buffer===''&&$this->failure===null){
$resource=$this->stream->detach();
if(\is_resource($resource)){
\stream_filter_append($resource,'dechunk',\STREAM_FILTER_READ);
}
return$resource;
}
$decoder=clone$this;
$this->buffer='';
$this->offset=0;
$this->detachable=false;
$this->stream=Utils::streamFor('');
$this->stream->detach();
return StreamWrapper::getResource($decoder);
}
private function fill():bool
{
$data=$this->stream->read(self::READ_SIZE);
if($data===''){
if(!$this->stream->eof()){
return false;
}
$this->failure=new\RuntimeException('Response body ended before the chunked body was complete');
throw$this->failure;
}
$this->buffer=\substr($this->buffer,$this->offset).$data;
$this->offset=0;
return true;
}
private function decode(int$length):string
{
$data='';
try{
while($this->offset<\strlen($this->buffer)&&$this->state!==self::DONE){
if($this->state===self::DATA){
$take=\min($this->remaining,$length-\strlen($data),\strlen($this->buffer)-$this->offset);
if($take===0){
break;
}
$data.=\substr($this->buffer,$this->offset,$take);
$this->offset+=$take;
$this->remaining-=$take;
if($this->remaining===0){
$this->state=self::DATA_END;
}
}elseif($this->state===self::SIZE){
$chunks=$this->digits===''?$this->decodeChunks($length-\strlen($data)):null;
if($chunks===null){
$this->decodeSize();
}else{
$data.=$chunks;
}
}elseif($this->state===self::SIZE_LINE){
$this->skipSizeLine();
}elseif($this->state===self::DATA_END){
$this->decodeDataEnd();
}else{
$this->decodeTrailer();
}
}
}catch(\RuntimeException$e){
$this->failure=$e;
if($data===''){
throw$e;
}
}
return$data;
}
private function decodeChunks(int$length):?string
{
$buffer=$this->buffer;
$end=\strlen($buffer);
$offset=$this->offset;
$data='';
while(true){
$digits=\strspn($buffer,'0123456789abcdefABCDEF',$offset,8);
if($digits===0||$digits===8){
break;
}
$lineEnd=\strpos($buffer,"\n",$offset+$digits);
if($lineEnd===false){
break;
}
$size=(int)\hexdec(\substr($buffer,$offset,$digits));
$offset=$lineEnd+1;
if($size===0){
$this->state=self::TRAILER;
break;
}
if($size>$length||$offset+$size>$end){
$this->remaining=$size;
$this->state=self::DATA;
break;
}
$data.=\substr($buffer,$offset,$size);
$length-=$size;
$offset+=$size;
if($offset+1<$end&&$buffer[$offset]==="\r"&&$buffer[$offset+1]==="\n"){
$offset+=2;
}elseif($offset<$end&&$buffer[$offset]==="\n"){
++$offset;
}else{
$this->state=self::DATA_END;
break;
}
}
if($offset===$this->offset){
return;
}
$this->offset=$offset;
return$data;
}
private function decodeSize():void
{
$count=\strspn($this->buffer,'0123456789abcdefABCDEF',$this->offset);
$this->digits.=\substr($this->buffer,$this->offset,$count);
$this->offset+=$count;
if(\strlen($this->digits)>self::MAX_SIZE_DIGITS){
throw new\RuntimeException('Invalid chunked response body: invalid chunk size');
}
if($this->offset===\strlen($this->buffer)){
return;
}
if($this->digits===''){
throw new\RuntimeException('Invalid chunked response body: invalid chunk size');
}
$significant=\ltrim($this->digits,'0');
if(\strlen($significant)>16||(\strlen($significant)===16&&$significant[0]>'7')){
throw new\RuntimeException('Invalid chunked response body: invalid chunk size');
}
$size=\hexdec($this->digits);
if(!\is_int($size)){
throw new\OverflowException('Chunk size exceeds the maximum integer size supported on this platform');
}
$this->digits='';
$this->remaining=$size;
$this->state=self::SIZE_LINE;
}
private function skipSizeLine():void
{
$end=\strpos($this->buffer,"\n",$this->offset);
if($end===false){
$this->offset=\strlen($this->buffer);
return;
}
$this->offset=$end+1;
$this->state=$this->remaining===0?self::TRAILER:self::DATA;
}
private function decodeDataEnd():void
{
$this->offset+=\strspn($this->buffer,"\r",$this->offset);
if($this->offset===\strlen($this->buffer)){
return;
}
if($this->buffer[$this->offset]!=="\n"){
throw new\RuntimeException('Invalid chunked response body: missing CRLF after chunk data');
}
++$this->offset;
$this->state=self::SIZE;
}
private function decodeTrailer():void
{
if($this->state!==self::TRAILER){
if($this->buffer[$this->offset]!=="\n"){
throw new\RuntimeException('Invalid chunked response body: invalid trailer section');
}
++$this->offset;
$this->state=$this->state===self::FINAL_CR?self::DONE:self::TRAILER;
return;
}
$count=\strcspn($this->buffer,"\r\n",$this->offset);
$this->line.=\substr($this->buffer,$this->offset,$count);
$this->offset+=$count;
$this->trailerLength+=$count;
if(\strlen($this->line)>self::MAX_TRAILER_LINE_LENGTH||$this->trailerLength>self::MAX_TRAILER_SECTION_LENGTH){
throw new\RuntimeException('Invalid chunked response body: invalid trailer section');
}
if($this->offset===\strlen($this->buffer)){
return;
}
$carriageReturn=$this->buffer[$this->offset]==="\r";
++$this->offset;
if($this->line===''){
$this->state=$carriageReturn?self::FINAL_CR:self::DONE;
return;
}
if(\strpos($this->line,"\0")!==false||\strpos($this->line,':')===false){
throw new\RuntimeException('Invalid chunked response body: invalid trailer section');
}
$this->line='';
if($carriageReturn){
$this->state=self::TRAILER_CR;
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
final class Clock
{
private function __construct(){
}
static function now():float
{
return\hrtime(true)/1e9;
}
static function sleep(int$microseconds):void
{
while($microseconds>0){
$slice=\min($microseconds,4294967295);
\usleep($slice);
$microseconds-=$slice;
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use Psr\Http\Message\RequestInterface;
interface CurlFactoryInterface
{
function create(RequestInterface$request,array$options):EasyHandle;
function release(EasyHandle$easy):void;
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ConnectTimeoutException;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\NetworkException;
use GuzzleHttp\Exception\NetworkTimeoutException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Exception\ResponseTimeoutException;
use GuzzleHttp\Exception\ResponseTransferException;
use GuzzleHttp\Multiplexing;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\ProxyOptions;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\LazyOpenStream;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\TransferStats;
use GuzzleHttp\TransportSharing;
use GuzzleHttp\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
final class CurlFactory implements CurlFactoryInterface
{
use NonSerializableTrait;
private const DELEGATED_PROXY_TUNNEL_OWNER='proxy-tunnel:delegated-to-libcurl';
private const STRINGABLE_PROXY_CREDENTIAL_OPTIONS=['CURLOPT_PROXYUSERPWD','CURLOPT_PROXYUSERNAME','CURLOPT_PROXYPASSWORD','CURLOPT_PROXY_SSLCERT','CURLOPT_PROXY_SSLKEY','CURLOPT_PROXY_KEYPASSWD','CURLOPT_PROXY_TLSAUTH_USERNAME','CURLOPT_PROXY_TLSAUTH_PASSWORD',];
private const PERSISTENT_REQUIRE_FRESH_PROXY_TUNNEL_MESSAGE='Persistent cURL sharing is required, but this request requires a fresh proxy tunnel connection.';
private const CURL_CONNECTION_ERRORS=[5=>true,6=>true,7=>true,35=>true,51=>true,60=>true,83=>true,90=>true,91=>true,96=>true,97=>true,98=>true,101=>true,];
private const CURL_NETWORK_ERRORS=[16=>true,52=>true,55=>true,56=>true,92=>true,95=>true,];
private const CURL_RESPONSE_TRANSFER_ERRORS=[8=>true,18=>true,23=>true,61=>true,];
private const CURL_CONNECT_TIMEOUT_ERRORS=['Connection timed out','Connection timeout','Connection time-out','Resolving timed out','name lookup timed out','Proxy CONNECT aborted due to timeout','SSL connection timeout',];
private const CURL_READFUNC_ABORT=268435456;
private const CURL_SEEKFUNC_OK=0;
private const CURL_SEEKFUNC_FAIL=1;
private const CURL_SEEKFUNC_CANTSEEK=2;
private const CURL_SEEK_MAX_REPLAYS=3;
private const CURLE_SEND_FAIL_REWIND=65;
private const DEFAULT_CONNECT_TIMEOUT_MS=60000;
private const CONNECT_TIMEOUT_DISABLED_MS=2147483647;
private array$handles=[];
private?string$proxyTunnelOwner=null;
private bool$poolMayHoldTunnels=false;
private int$maxHandles;
private bool$closed=false;
private$shareHandle;
private string$shareMode;
private bool$opaqueShareConnectionCache=false;
function __construct(int$maxHandles,string$shareMode=TransportSharing::NONE,$shareHandle=null){
$this->maxHandles=$maxHandles;
$this->shareMode=CurlShareHandleState::normalizeMode($shareMode,'transport_sharing');
if($shareHandle instanceof CurlShareHandleState){
if($shareHandle->mode!==$this->shareMode){
throw new InvalidArgumentException('The cURL share handle state mode does not match the configured transport sharing mode.');
}
$this->opaqueShareConnectionCache=$shareHandle->mode===TransportSharing::PERSISTENT_PREFER
||$shareHandle->mode===TransportSharing::PERSISTENT_REQUIRE;
$shareHandle=$shareHandle->handle;
}elseif($shareHandle!==null){
$this->opaqueShareConnectionCache=true;
}
if($this->shareMode===TransportSharing::NONE&&$shareHandle!==null){
throw new InvalidArgumentException('A cURL share handle cannot be provided when transport sharing is disabled.');
}
if($this->shareMode!==TransportSharing::NONE&&$shareHandle===null){
throw new InvalidArgumentException('A cURL share handle is required when transport sharing is enabled.');
}
if($shareHandle!==null&&!self::isCurlShareHandle($shareHandle)){
throw new InvalidArgumentException('A cURL share handle must be an instance of CurlShareHandle, CurlSharePersistentHandle, or a curl_share resource.');
}
$this->shareHandle=$shareHandle;
}
private static function isCurlShareHandle($value):bool
{
if(\PHP_VERSION_ID<80000){
return\is_resource($value)&&\get_resource_type($value)==='curl_share';
}
if($value instanceof\CurlShareHandle){
return true;
}
return\class_exists('CurlSharePersistentHandle')&&$value instanceof\CurlSharePersistentHandle;
}
function create(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):EasyHandle{
$this->assertOpen();
self::validateRequestUriScheme($request);
$protocolVersion=$request->getProtocolVersion();
if(''===$protocolVersion){
throw new RequestException('HTTP protocol version must not be empty.',$request);
}
if(1!==\preg_match('/^\d+(?:\.\d+)?$/D',$protocolVersion)){
throw new RequestException('HTTP protocol version must be a valid HTTP version number.',$request);
}
CurlVersion::ensureSupported($request);
$multiplex=self::normalizeMultiplex($options);
if('3'===$protocolVersion||'3.0'===$protocolVersion){
if(!CurlVersion::supportsHttp3()){
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new RequestException('Required multiplexing for HTTP/3 needs libcurl 8.13.0 or newer built with HTTP/3 support.',$request);
}
throw new RequestException('HTTP/3 is supported by the cURL handler, however the installed PHP cURL extension or libcurl does not support HTTP/3.',$request);
}
}elseif('2'===$protocolVersion||'2.0'===$protocolVersion){
if(!CurlVersion::supportsHttp2()){
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new RequestException('Required multiplexing needs libcurl 8.14.0 or newer built with HTTP/2 support.',$request);
}
throw new RequestException('HTTP/2 is supported by the cURL handler, however libcurl 7.65.2 or newer built with HTTP/2 support is required.',$request);
}
}elseif('1.0'!==$protocolVersion&&'1.1'!==$protocolVersion){
throw new RequestException(sprintf('HTTP/%s is not supported by the cURL handler.',$protocolVersion),$request);
}
if(isset($options['curl']['body_as_string'])){
$options['_body_as_string']=$options['curl']['body_as_string'];
unset($options['curl']['body_as_string']);
}
self::rejectUnsupportedRequestOptions($options);
self::assertOnStatsCallable($options);
self::assertOnTrailersCallable($options);
$this->rejectRequestLevelShareConflict($options);
$this->rejectPersistentRequireConnectionReuseConflicts($options);
self::rejectUnsupportedCurlOptions($options);
self::rejectConflictingCurlOptions($options);
$framing=RequestFraming::analyze($request,$request->getMethod()!=='HEAD');
$request=$framing->request;
$managedProxyAuthorization=self::managedProxyAuthorizationHeaderLines($request);
$easy=new EasyHandle;
$easy->request=$request;
$easy->options=$options;
$conf=$this->getDefaultConf($easy);
$this->applyMethod($easy,$conf,$framing);
$this->applyHandlerOptions($easy,$conf);
$this->applyHeaders($easy,$conf);
unset($conf['_headers']);
if(isset($options['curl'])){
$conf=\array_replace($conf,$options['curl']);
}
self::normalizeStringableProxyCredentialOptions($conf);
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
self::assertRequiredMultiplexAuthSupported($conf);
}
self::applyProxyConnectHeaderSuppression($request,$conf);
self::normalizeCurlHeaderOptions($conf);
self::applyProxyAuthorizationHeaderHandling($request,$conf,$managedProxyAuthorization);
self::normalizeCurlHeaderOptions($conf);
if($this->shareHandle!==null){
$this->forceFreshConnectionForAuthenticatedProxy($request,$conf);
}else{
$signature=self::proxyTunnelSignature($request,$conf);
$easy->proxyTunnelSignature=$signature;
if($signature!==null&&$signature!==$this->proxyTunnelOwner){
if($this->poolMayHoldTunnels){
$this->discardIdleHandles();
$this->poolMayHoldTunnels=false;
}
$this->proxyTunnelOwner=$signature;
}
}
$easy->effectiveProxy=self::getEffectiveProxy($conf);
$conf[\CURLOPT_HEADERFUNCTION]=$this->createHeaderFn($easy);
if($this->shareHandle!==null){
if(!\defined('CURLOPT_SHARE')){
throw new RequestException('The configured cURL share handle requires CURLOPT_SHARE, but it is not available in the installed PHP cURL extension.',$easy->request);
}
$conf[(int)\constant('CURLOPT_SHARE')]=$this->shareHandle;
}
if(\defined('CURLOPT_PIPEWAIT')){
$easy->usesPipewait=!empty($conf[(int)\constant('CURLOPT_PIPEWAIT')]);
}
$handle=$this->handles?\array_pop($this->handles):\curl_init();
if(false===$handle){
throw new RequestException('Can not initialize cURL handle.',$request);
}
$easy->handle=$handle;
try{
$this->applyCurlOptions($handle,$conf);
}catch(\Throwable$e){
if(PHP_VERSION_ID<80000&&\is_resource($handle)){
\curl_close($handle);
}
unset($easy->handle);
throw$e;
}
return$easy;
}
private function applyCurlOptions(#[\SensitiveParameter]$handle,#[\SensitiveParameter]array$conf
):void{
foreach($conf as$option=>$value){
if(!\is_int($option)){
throw new InvalidArgumentException(\sprintf('Invalid cURL option %s.',self::formatCurlOption($option)));
}
try{
$success=curl_setopt($handle,$option,$value);
}catch(\Throwable$e){
throw new InvalidArgumentException(\sprintf('Unable to set cURL option %s: %s',self::formatCurlOption($option),$e->getMessage()),0,$e
);
}
if(!$success){
throw new InvalidArgumentException(\sprintf('Unable to set cURL option %s.',self::formatCurlOption($option)));
}
}
}
private static function normalizeStringableProxyCredentialOptions(#[\SensitiveParameter]array&$conf
):void{
foreach(self::STRINGABLE_PROXY_CREDENTIAL_OPTIONS as$name){
if(!\defined($name)){
continue;
}
$option=(int)\constant($name);
if(!isset($conf[$option])||!\is_object($conf[$option])||!\method_exists($conf[$option],'__toString')){
continue;
}
try{
$conf[$option]=(string)$conf[$option];
}catch(\Throwable$e){
throw new InvalidArgumentException(\sprintf('Unable to set cURL option %s: %s',self::formatCurlOption($option),$e->getMessage()),0,$e
);
}
}
}
private function rejectRequestLevelShareConflict(#[\SensitiveParameter]array$options
):void{
if($this->shareHandle===null){
return;
}
if(!\defined('CURLOPT_SHARE')||!isset($options['curl'])||!\is_array($options['curl'])||!\array_key_exists((int)\constant('CURLOPT_SHARE'),$options['curl'])){
return;
}
throw new InvalidArgumentException('The request-level CURLOPT_SHARE cURL option cannot be combined with configured transport sharing.');
}
private function rejectPersistentRequireConnectionReuseConflicts(#[\SensitiveParameter]array$options
):void{
if($this->shareMode!==TransportSharing::PERSISTENT_REQUIRE
||!isset($options['curl'])||!\is_array($options['curl'])){
return;
}
if(!empty($options['curl'][\CURLOPT_FRESH_CONNECT])){
throw new InvalidArgumentException('The CURLOPT_FRESH_CONNECT cURL option cannot be used when persistent cURL sharing is required because it disables connection reuse.');
}
if(!empty($options['curl'][\CURLOPT_FORBID_REUSE])){
throw new InvalidArgumentException('The CURLOPT_FORBID_REUSE cURL option cannot be used when persistent cURL sharing is required because it disables connection reuse.');
}
}
private static function normalizeMultiplex(#[\SensitiveParameter]array$options
):string{
$multiplex=$options['multiplex']??null;
if($multiplex===null){
return Multiplexing::WAIT;
}
if(!\in_array($multiplex,[Multiplexing::NONE,Multiplexing::EAGER,Multiplexing::WAIT,Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new InvalidArgumentException(\sprintf('The "multiplex" option must be null or a GuzzleHttp\\Multiplexing::* constant; received %s.',\get_debug_type($multiplex)));
}
return$multiplex;
}
private static function assertRequiredMultiplexSupported(#[\SensitiveParameter]EasyHandle$easy
):void{
if(!CurlVersion::supportsRequiredHttp2Multiplex()){
throw new RequestException('Required multiplexing needs libcurl 8.14.0 or newer built with HTTP/2 support.',$easy->request);
}
$proxy=ProxyEnv::resolveProxySelection($easy->request->getUri(),$easy->options['proxy']??null);
self::assertSelectedProxySupported($proxy->getProxy(),$easy->request);
if('https'!==$easy->request->getUri()->getScheme()&&$proxy->hasProxy()){
throw new RequestException('Required multiplexing cannot be guaranteed for cleartext requests sent through a proxy.',$easy->request);
}
}
private static function assertRequiredMultiplexAuthSupported(#[\SensitiveParameter]array$conf
):void{
if(!\array_key_exists(\CURLOPT_HTTPAUTH,$conf)){
return;
}
$auth=$conf[\CURLOPT_HTTPAUTH];
if(!\is_scalar($auth)){
throw new InvalidArgumentException('The "multiplex" request option cannot be required when the final CURLOPT_HTTPAUTH cURL option value is not an integer.');
}
$ntlmBits=\CURLAUTH_NTLM;
if(\defined('CURLAUTH_NTLM_WB')){
$ntlmBits|=(int)\constant('CURLAUTH_NTLM_WB');
}
if(((int)$auth&$ntlmBits)!==0){
throw new InvalidArgumentException('The "multiplex" request option cannot be required when the final CURLOPT_HTTPAUTH cURL option value permits NTLM; libcurl retries NTLM authentication over HTTP/1.1.');
}
}
private static function assertSelectedProxySupported(#[\SensitiveParameter]?string$selectedProxy,#[\SensitiveParameter]RequestInterface$request
):void{
if($selectedProxy===null||$selectedProxy===''){
return;
}
$scheme=ProxyOptions::proxyScheme($selectedProxy);
if(!\in_array($scheme,['http','https','socks4','socks4a','socks5','socks5h'],true)){
throw new InvalidArgumentException(\sprintf('The "%s" proxy scheme is not supported by the cURL handler.',Psr7\DiagnosticValue::escape($scheme)));
}
if($scheme==='https'&&!CurlVersion::supportsHttpsProxy()){
throw new RequestException('HTTPS proxies are not supported by the installed libcurl; libcurl 7.54.0 or newer built with HTTPS-proxy support is required.',$request);
}
}
private static function formatCurlOption($option):string
{
if(!\is_int($option)){
return\sprintf('"%s"',Psr7\DiagnosticValue::escape((string)$option));
}
static$names=null;
if(null===$names){
$names=[];
foreach(\get_defined_constants(true)['curl']??[]as$name=>$value){
if(\is_int($value)&&\strpos($name,'CURLOPT_')===0&&!isset($names[$value])){
$names[$value]=$name;
}
}
}
if(isset($names[$option])){
return\sprintf('%s (%d)',$names[$option],$option);
}
return(string)$option;
}
private static function rejectConflictingCurlOptions(#[\SensitiveParameter]array$options
):void{
if(!isset($options['curl'])||!\is_array($options['curl'])||$options['curl']===[]){
return;
}
$conflictingOptions=self::conflictingCurlOptions();
foreach($options['curl']as$option=>$_){
if(!\array_key_exists($option,$conflictingOptions)){
continue;
}
$name=self::formatCurlOption($option);
$replacement=$conflictingOptions[$option];
if($replacement!==null){
throw new InvalidArgumentException(\sprintf('Passing %s in the "curl" request option is not supported because it conflicts with Guzzle-managed request handling. Use %s instead.',$name,$replacement
));
}
throw new InvalidArgumentException(\sprintf('Passing %s in the "curl" request option is not supported because it conflicts with Guzzle-managed cURL internals.',$name
));
}
}
private static function rejectUnsupportedCurlOptions(#[\SensitiveParameter]array$options
):void{
if(!isset($options['curl'])||!\is_array($options['curl'])||$options['curl']===[]){
return;
}
$supportedOptions=self::supportedCurlOptions();
$conflictingOptions=self::conflictingCurlOptions();
foreach($options['curl']as$option=>$_){
if(!\is_int($option)||\array_key_exists($option,$supportedOptions)||\array_key_exists($option,$conflictingOptions)){
continue;
}
throw new InvalidArgumentException(\sprintf('Passing %s in the "curl" request option is not supported because it is outside the built-in cURL handlers\' allow-list.',self::formatCurlOption($option)));
}
}
private static function rejectUnsupportedRequestOptions(#[\SensitiveParameter]array$options
):void{
if(\array_key_exists('stream_context',$options)){
throw new InvalidArgumentException('Passing the "stream_context" request option to a cURL handler is not supported because cURL handlers ignore PHP stream context options.');
}
}
private static function assertOnStatsCallable(#[\SensitiveParameter]array$options
):void{
if(isset($options['on_stats'])&&!\is_callable($options['on_stats'])){
throw new InvalidArgumentException('on_stats must be callable');
}
}
private static function assertOnTrailersCallable(#[\SensitiveParameter]array$options
):void{
if(isset($options['on_trailers'])&&!\is_callable($options['on_trailers'])){
throw new InvalidArgumentException('on_trailers must be callable');
}
}
private static function conflictingCurlOptions():array
{
static$options=null;
if($options!==null){
return$options;
}
$options=[];
self::addConflictingCurlOption($options,'CURLOPT_SHARE','the "transport_sharing" client option or cURL handler option');
self::addConflictingCurlOption($options,'CURLOPT_URL','the request URI');
self::addConflictingCurlOption($options,'CURLOPT_PORT','the request URI');
self::addConflictingCurlOption($options,'CURLOPT_CUSTOMREQUEST','the request method');
self::addConflictingCurlOption($options,'CURLOPT_HTTPGET','the request method');
self::addConflictingCurlOption($options,'CURLOPT_POST','the request method and body');
self::addConflictingCurlOption($options,'CURLOPT_PUT','the request method and body');
self::addConflictingCurlOption($options,'CURLOPT_NOBODY','the request method');
self::addConflictingCurlOption($options,'CURLOPT_UPLOAD','the request body');
self::addConflictingCurlOption($options,'CURLOPT_POSTFIELDS','the request body');
self::addConflictingCurlOption($options,'CURLOPT_READFUNCTION','the request body');
self::addConflictingCurlOption($options,'CURLOPT_SEEKFUNCTION','the request body');
self::addConflictingCurlOption($options,'CURLOPT_READDATA','the request body');
self::addConflictingCurlOption($options,'CURLOPT_INFILE','the request body');
self::addConflictingCurlOption($options,'CURLOPT_INFILESIZE','the request body');
self::addConflictingCurlOption($options,'CURLOPT_INFILESIZE_LARGE','the request body');
self::addConflictingCurlOption($options,'CURLOPT_HTTPHEADER','the request headers');
self::addConflictingCurlOption($options,'CURLOPT_USERAGENT','the request headers');
self::addConflictingCurlOption($options,'CURLOPT_REFERER','the request headers');
self::addConflictingCurlOption($options,'CURLOPT_HEADERFUNCTION','the "on_headers" request option');
self::addConflictingCurlOption($options,'CURLOPT_WRITEFUNCTION','the "sink" request option');
self::addConflictingCurlOption($options,'CURLOPT_FILE','the "sink" request option');
self::addConflictingCurlOption($options,'CURLOPT_TIMEOUT','the "timeout" request option');
self::addConflictingCurlOption($options,'CURLOPT_TIMEOUT_MS','the "timeout" request option');
self::addConflictingCurlOption($options,'CURLOPT_CONNECTTIMEOUT','the "connect_timeout" request option');
self::addConflictingCurlOption($options,'CURLOPT_CONNECTTIMEOUT_MS','the "connect_timeout" request option');
self::addConflictingCurlOption($options,'CURLOPT_NOSIGNAL','the "timeout" or "connect_timeout" request option');
self::addConflictingCurlOption($options,'CURLOPT_NOPROGRESS','the "progress" request option');
self::addConflictingCurlOption($options,'CURLOPT_PROGRESSFUNCTION','the "progress" request option');
self::addConflictingCurlOption($options,'CURLOPT_XFERINFOFUNCTION','the "progress" request option');
self::addConflictingCurlOption($options,'CURLOPT_VERBOSE','the "debug" request option');
self::addConflictingCurlOption($options,'CURLOPT_STDERR','the "debug" request option');
self::addConflictingCurlOption($options,'CURLOPT_PROXY','the "proxy" request option');
self::addConflictingCurlOption($options,'CURLOPT_NOPROXY','the "proxy" request option');
self::addConflictingCurlOption($options,'CURLOPT_PROXYTYPE','the "proxy" request option with a scheme-prefixed URL');
self::addConflictingCurlOption($options,'CURLOPT_FOLLOWLOCATION','the "allow_redirects" request option');
self::addConflictingCurlOption($options,'CURLOPT_MAXREDIRS','the "allow_redirects" request option');
self::addConflictingCurlOption($options,'CURLOPT_POSTREDIR','the "allow_redirects" request option');
self::addConflictingCurlOption($options,'CURLOPT_REDIR_PROTOCOLS','the "allow_redirects" request option');
self::addConflictingCurlOption($options,'CURLOPT_REDIR_PROTOCOLS_STR','the "allow_redirects" request option');
self::addConflictingCurlOption($options,'CURLOPT_PROTOCOLS','the "protocols" request option');
self::addConflictingCurlOption($options,'CURLOPT_PROTOCOLS_STR','the "protocols" request option');
self::addConflictingCurlOption($options,'CURLOPT_HTTP_VERSION','the request protocol version');
self::addConflictingCurlOption($options,'CURLOPT_PIPEWAIT','the "multiplex" request option');
self::addConflictingCurlOption($options,'CURLOPT_IPRESOLVE','the "force_ip_resolve" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSL_VERIFYPEER','the "verify" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSL_VERIFYHOST','the "verify" request option');
self::addConflictingCurlOption($options,'CURLOPT_CAINFO','the "verify" request option');
self::addConflictingCurlOption($options,'CURLOPT_CAPATH','the "verify" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLVERSION','the "crypto_method" or "crypto_method_max" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLCERT','the "cert" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLCERTPASSWD','the "cert" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLCERTTYPE','the "cert_type" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLKEY','the "ssl_key" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLKEYPASSWD','the "ssl_key" request option');
self::addConflictingCurlOption($options,'CURLOPT_KEYPASSWD','the "ssl_key" request option');
self::addConflictingCurlOption($options,'CURLOPT_SSLKEYTYPE','the "ssl_key_type" request option');
self::addConflictingCurlOption($options,'CURLOPT_COOKIE','the "Cookie" request header or Guzzle cookie middleware');
self::addConflictingCurlOption($options,'CURLOPT_COOKIEFILE','Guzzle cookie middleware');
self::addConflictingCurlOption($options,'CURLOPT_COOKIEJAR','Guzzle cookie middleware');
self::addConflictingCurlOption($options,'CURLOPT_COOKIELIST','Guzzle cookie middleware');
self::addConflictingCurlOption($options,'CURLOPT_COOKIESESSION','Guzzle cookie middleware');
return$options;
}
private static function supportedCurlOptions():array
{
static$options=null;
if($options!==null){
return$options;
}
$options=[];
self::addSupportedCurlOption($options,'CURLOPT_ADDRESS_SCOPE');
self::addSupportedCurlOption($options,'CURLOPT_CERTINFO');
self::addSupportedCurlOption($options,'CURLOPT_CONNECT_TO');
self::addSupportedCurlOption($options,'CURLOPT_DNS_CACHE_TIMEOUT');
self::addSupportedCurlOption($options,'CURLOPT_DNS_INTERFACE');
self::addSupportedCurlOption($options,'CURLOPT_DNS_LOCAL_IP4');
self::addSupportedCurlOption($options,'CURLOPT_DNS_LOCAL_IP6');
self::addSupportedCurlOption($options,'CURLOPT_DNS_SERVERS');
self::addSupportedCurlOption($options,'CURLOPT_DNS_SHUFFLE_ADDRESSES');
self::addSupportedCurlOption($options,'CURLOPT_ENCODING');
self::addSupportedCurlOption($options,'CURLOPT_FORBID_REUSE');
self::addSupportedCurlOption($options,'CURLOPT_FRESH_CONNECT');
self::addSupportedCurlOption($options,'CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS');
self::addSupportedCurlOption($options,'CURLOPT_HTTPAUTH');
self::addSupportedCurlOption($options,'CURLOPT_INTERFACE');
self::addSupportedCurlOption($options,'CURLOPT_LOCALPORT');
self::addSupportedCurlOption($options,'CURLOPT_LOCALPORTRANGE');
self::addSupportedCurlOption($options,'CURLOPT_LOW_SPEED_LIMIT');
self::addSupportedCurlOption($options,'CURLOPT_LOW_SPEED_TIME');
self::addSupportedCurlOption($options,'CURLOPT_MAXAGE_CONN');
self::addSupportedCurlOption($options,'CURLOPT_MAXCONNECTS');
self::addSupportedCurlOption($options,'CURLOPT_MAXLIFETIME_CONN');
self::addSupportedCurlOption($options,'CURLOPT_HTTPPROXYTUNNEL');
self::addSupportedCurlOption($options,'CURLOPT_PREREQFUNCTION');
self::addSupportedCurlOption($options,'CURLOPT_PROXYHEADER');
self::addSupportedCurlOption($options,'CURLOPT_PROXYUSERPWD');
self::addSupportedCurlOption($options,'CURLOPT_RESOLVE');
self::addSupportedCurlOption($options,'CURLOPT_SSL_CIPHER_LIST');
self::addSupportedCurlOption($options,'CURLOPT_SSL_EC_CURVES');
self::addSupportedCurlOption($options,'CURLOPT_TCP_FASTOPEN');
self::addSupportedCurlOption($options,'CURLOPT_TCP_KEEPALIVE');
self::addSupportedCurlOption($options,'CURLOPT_TCP_KEEPIDLE');
self::addSupportedCurlOption($options,'CURLOPT_TCP_KEEPINTVL');
self::addSupportedCurlOption($options,'CURLOPT_TCP_KEEPCNT');
self::addSupportedCurlOption($options,'CURLOPT_TCP_NODELAY');
self::addSupportedCurlOption($options,'CURLOPT_TLS13_CIPHERS');
self::addSupportedCurlOption($options,'CURLOPT_UNIX_SOCKET_PATH');
self::addSupportedCurlOption($options,'CURLOPT_USERPWD');
return$options;
}
private static function addSupportedCurlOption(array&$options,string$constant):void
{
if(!\defined($constant)){
return;
}
$value=\constant($constant);
if(\is_int($value)){
$options[$value]=true;
}
}
private static function addConflictingCurlOption(array&$options,string$constant,?string$replacement):void
{
if(!\defined($constant)){
return;
}
$value=\constant($constant);
if(\is_int($value)){
$options[$value]=$replacement;
}
}
private static function validateRequestUriScheme(#[\SensitiveParameter]RequestInterface$request
):void{
$scheme=$request->getUri()->getScheme();
if($scheme===''){
throw new RequestException('URI must include a scheme and host. Use an absolute URI, a network-path reference starting with //, or configure a base_uri.',$request);
}
if(!\in_array($scheme,['http','https'],true)){
throw new RequestException(\sprintf("The scheme '%s' is not supported.",Psr7\DiagnosticValue::escape($scheme)),$request);
}
}
function release(#[\SensitiveParameter]EasyHandle$easy
):void{
$this->assertOpen();
$resource=$easy->handle;
unset($easy->handle);
if(\count($this->handles)>=$this->maxHandles
||($easy->proxyTunnelSignature!==null&&$easy->proxyTunnelSignature!==$this->proxyTunnelOwner)){
$this->discardHandle($resource);
return;
}
if($easy->proxyTunnelSignature!==null){
$this->poolMayHoldTunnels=true;
}
$this->clearEasyHandleCallbacks($resource);
\curl_reset($resource);
$this->handles[]=$resource;
}
function close():void
{
$this->doClose(true);
}
private function assertOpen():void
{
if($this->closed){
throw new\BadMethodCallException('Cannot use the cURL factory after it has been closed.');
}
}
private function doClose(bool$explicit):void
{
if($this->closed){
return;
}
$this->closed=true;
$failure=null;
try{
foreach($this->handles as$id=>$handle){
try{
$this->discardHandle($handle);
}catch(\Throwable$e){
if($failure===null){
$failure=$e;
}
}finally{
unset($this->handles[$id]);
}
}
}finally{
$this->shareMode=TransportSharing::NONE;
$this->shareHandle=null;
}
if($explicit&&$failure!==null){
throw$failure;
}
}
private function discardHandle(#[\SensitiveParameter]$handle
):void{
$failure=null;
try{
$this->clearEasyHandleCallbacks($handle);
}catch(\Throwable$e){
$failure=$e;
}
try{
if(PHP_VERSION_ID<80000&&\is_resource($handle)){
\curl_close($handle);
}
}catch(\Throwable$e){
if($failure===null){
$failure=$e;
}
}
if($failure!==null){
throw$failure;
}
}
private function clearEasyHandleCallbacks(#[\SensitiveParameter]$handle
):void{
curl_setopt($handle,\CURLOPT_HEADERFUNCTION,null);
curl_setopt($handle,\CURLOPT_READFUNCTION,null);
curl_setopt($handle,\CURLOPT_WRITEFUNCTION,null);
curl_setopt($handle,\CURLOPT_PROGRESSFUNCTION,null);
if(\defined('CURLOPT_PREREQFUNCTION')){
curl_setopt($handle,(int)\constant('CURLOPT_PREREQFUNCTION'),null);
}
if(\defined('CURLOPT_SEEKFUNCTION')){
curl_setopt($handle,(int)\constant('CURLOPT_SEEKFUNCTION'),null);
}
if(\defined('CURLOPT_XFERINFOFUNCTION')){
curl_setopt($handle,(int)\constant('CURLOPT_XFERINFOFUNCTION'),null);
}
}
static function finish(callable$handler,#[\SensitiveParameter]EasyHandle$easy,CurlFactoryInterface$factory
):PromiseInterface{
$onStats=$easy->options['on_stats']??null;
$stats=$onStats!==null?self::createStats($easy):null;
if(self::shouldFinishWithError($easy)){
return self::finishError($handler,$easy,$factory,$stats,$onStats);
}
$response=$easy->response;
$factory->release($easy);
$body=$response->getBody();
try{
if($body->isSeekable()){
$body->rewind();
}
}catch(\Exception$e){
$reason=new ResponseException($e->getMessage()!==''?$e->getMessage():'Failed to rewind the response body',$easy->request,$response,$e
);
if($onStats!==null&&$stats!==null){
$onStats(new TransferStats($easy->request,$response,$stats->getTransferTime(),$reason,$stats->getHandlerStats()));
}
return P\Create::rejectionFor($reason);
}
if(isset($easy->options['on_trailers'])){
$onTrailers=$easy->options['on_trailers'];
try{
$onTrailers(self::headersFromTrailerLines($easy->trailers),$response,$easy->request);
}catch(\Throwable$e){
$reason=new ResponseException('An error was encountered during the on_trailers event',$easy->request,$response,$e
);
if($onStats!==null&&$stats!==null){
$onStats(new TransferStats($easy->request,$response,$stats->getTransferTime(),$reason,$stats->getHandlerStats()));
}
return P\Create::rejectionFor($reason);
}
}
if($onStats!==null&&$stats!==null){
$onStats($stats);
}
return P\Create::promiseFor($response);
}
private static function createStats(#[\SensitiveParameter]EasyHandle$easy
):TransferStats{
$curlStats=\curl_getinfo($easy->handle);
$curlStats['appconnect_time']=\curl_getinfo($easy->handle,\CURLINFO_APPCONNECT_TIME);
if($easy->createResponseException){
$curlStats=['total_time'=>$curlStats['total_time'],'appconnect_time'=>$curlStats['appconnect_time'],];
}
$handlerErrorData=$easy->responseHeaderException??$easy->responseBodySizeException??$easy->errno;
return new TransferStats($easy->request,$easy->response,$curlStats['total_time'],$handlerErrorData,$curlStats
);
}
private static function finishError(callable$handler,#[\SensitiveParameter]EasyHandle$easy,CurlFactoryInterface$factory,?TransferStats$stats,?callable$onStats
):PromiseInterface{
$ctx=self::createErrorContext($easy);
if(self::shouldRetryFailedRewind($easy)){
try{
if($onStats!==null&&$stats!==null){
$onStats($stats);
}
return self::retryFailedRewind($handler,$easy,$ctx);
}finally{
$factory->release($easy);
}
}
$factory->release($easy);
if($onStats!==null&&$stats!==null){
$onStats($stats);
}
if(self::isResponseRewindFailure($easy)){
$status=$easy->response!==null?$easy->response->getStatusCode():0;
$ctx['error']=$status===401||$status===407
?'The server issued an authentication challenge '.'after the request body had already been sent, and the body '.'could not be rewound to resend it. The request was not '.'retried because a retry replays the same challenge. See '.'https://bugs.php.net/bug.php?id=47204 for more information.':'The server responded after the request body had already '.'been sent, and the body could not be rewound for '.'libcurl\'s automatic retry. The request was not retried '.'because a retry replays the same response. See '.'https://bugs.php.net/bug.php?id=47204 for more information.';
}
return self::createRejection($easy,$ctx);
}
private static function shouldFinishWithError(EasyHandle$easy):bool
{
return!$easy->response
||$easy->errno!==0
||self::hasLocalFailure($easy);
}
private static function hasLocalFailure(EasyHandle$easy):bool
{
return$easy->bodyReadTimeoutException!==null
||$easy->bodyRewindTimeoutException!==null
||$easy->bodyRewindException!==null
||$easy->bodyReadException!==null
||$easy->responseHeaderException!==null
||$easy->sinkWriteTimeoutException!==null
||$easy->sinkWriteException!==null
||$easy->sinkWriteIncomplete
||$easy->responseBodySizeException!==null;
}
private static function shouldRetryFailedRewind(EasyHandle$easy):bool
{
if(self::hasLocalFailure($easy)){
return false;
}
if(self::isResponseRewindFailure($easy)){
return false;
}
return$easy->errno===0||$easy->errno===self::CURLE_SEND_FAIL_REWIND;
}
private static function isResponseRewindFailure(EasyHandle$easy):bool
{
return$easy->errno===self::CURLE_SEND_FAIL_REWIND
&&$easy->response!==null
&&!self::hasLocalFailure($easy);
}
private static function createErrorContext(EasyHandle$easy):array
{
return['errno'=>$easy->errno,'error'=>\curl_error($easy->handle),];
}
private static function createRejection(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array$ctx,#[\SensitiveParameter]?\Throwable$previous=null
):PromiseInterface{
if($easy->createResponseException){
return P\Create::rejectionFor(new RequestException('An error was encountered while creating the response',$easy->request,0,$easy->createResponseException
));
}
if($easy->responseHeaderException){
return P\Create::rejectionFor($easy->responseHeaderException);
}
if($easy->onHeadersException){
return self::createRequestOrResponseRejection($easy,'An error was encountered during the on_headers event',$easy->onHeadersException
);
}
if($easy->progressException){
return self::createRequestOrResponseRejection($easy,'An error was encountered during the progress event',$easy->progressException
);
}
if($easy->bodyReadTimeoutException){
return self::createRequestOrResponseRejection($easy,'Timed out while reading the request body',$easy->bodyReadTimeoutException
);
}
if($easy->bodyRewindTimeoutException){
return self::createRequestOrResponseRejection($easy,'Timed out while rewinding the request body',$easy->bodyRewindTimeoutException
);
}
if($easy->bodyRewindException){
$message=$easy->bodyRewindException->getMessage()!==''?$easy->bodyRewindException->getMessage():'Failed to rewind the request body';
return self::createRequestOrResponseRejection($easy,$message,$easy->bodyRewindException);
}
if($easy->bodyReadException){
$message=$easy->bodyReadException->getMessage()!==''?$easy->bodyReadException->getMessage():'Failed to read the request body';
return self::createRequestOrResponseRejection($easy,$message,$easy->bodyReadException);
}
if($easy->sinkWriteTimeoutException){
return self::createRequestOrResponseRejection($easy,'Timed out while writing the response body',$easy->sinkWriteTimeoutException
);
}
if($easy->sinkWriteException){
$message=$easy->sinkWriteException->getMessage()!==''?$easy->sinkWriteException->getMessage():'Failed to write the response body';
return self::createRequestOrResponseRejection($easy,$message,$easy->sinkWriteException);
}
if($easy->sinkWriteIncomplete){
return self::createRequestOrResponseRejection($easy,'Unable to write to stream');
}
if($easy->responseBodySizeException){
return self::createRequestOrResponseRejection($easy,$easy->responseBodySizeException->getMessage(),$easy->responseBodySizeException
);
}
if($easy->progressAborted&&$easy->errno===\CURLE_ABORTED_BY_CALLBACK){
return self::createRequestOrResponseRejection($easy,'The transfer was aborted by the progress callback');
}
$uri=$easy->request->getUri();
$sanitizedError=self::sanitizeCurlError($ctx['error']??'',$uri,$easy->effectiveProxy);
$message=\sprintf('cURL error %s: %s (%s)',$ctx['errno'],$sanitizedError,'see https://curl.se/libcurl/c/libcurl-errors.html');
if(''!==$sanitizedError){
$safeUri=Psr7\Utils::redactUriForMessage($uri);
if($safeUri!==''&&false===\strpos($sanitizedError,$safeUri)){
$message.=\sprintf(' for %s',$safeUri);
}
}
if($easy->errno===\CURLE_OPERATION_TIMEOUTED){
if($easy->response!==null){
$error=new ResponseTimeoutException($message,$easy->request,$easy->response,$previous);
}elseif(self::isConnectTimeoutError($ctx['error']??'')){
$error=new ConnectTimeoutException($message,$easy->request,$previous);
}else{
$error=new NetworkTimeoutException($message,$easy->request,$previous);
}
}elseif($easy->response){
$error=self::isResponseTransferError($easy->errno)?new ResponseTransferException($message,$easy->request,$easy->response,$previous):new ResponseException($message,$easy->request,$easy->response,$previous);
}elseif(self::isConnectionError($easy->errno)){
$error=new ConnectException($message,$easy->request,$previous);
}elseif(self::isNetworkError($easy->errno)){
$error=new NetworkException($message,$easy->request,$previous);
}else{
$error=new RequestException($message,$easy->request,0,$previous);
}
return P\Create::rejectionFor($error);
}
private static function createRequestOrResponseRejection(#[\SensitiveParameter]EasyHandle$easy,string$message,#[\SensitiveParameter]?\Throwable$previous=null
):PromiseInterface{
if($easy->response!==null){
return P\Create::rejectionFor(new ResponseException($message,$easy->request,$easy->response,$previous));
}
return P\Create::rejectionFor(new RequestException($message,$easy->request,0,$previous));
}
private static function isConnectionError(int$errno):bool
{
return isset(self::CURL_CONNECTION_ERRORS[$errno]);
}
private static function isNetworkError(int$errno):bool
{
return isset(self::CURL_NETWORK_ERRORS[$errno]);
}
private static function isResponseTransferError(int$errno):bool
{
return self::isConnectionError($errno)||self::isNetworkError($errno)||isset(self::CURL_RESPONSE_TRANSFER_ERRORS[$errno]);
}
private static function isConnectTimeoutError(string$error):bool
{
if(''===$error){
return false;
}
foreach(self::CURL_CONNECT_TIMEOUT_ERRORS as$connectTimeoutError){
if(Psr7\Utils::caselessContains($error,$connectTimeoutError)){
return true;
}
}
return Psr7\Utils::caselessContains($error,'Failed to resolve')&&Psr7\Utils::caselessContains($error,'timeout');
}
private static function sanitizeCurlError(#[\SensitiveParameter]string$error,#[\SensitiveParameter]UriInterface$uri,#[\SensitiveParameter]?string$proxy=null
):string{
if(''===$error){
return$error;
}
$error=self::redactProxyUserInfo($error,$proxy);
return UriDiagnostic::redactInMessage($error,$uri);
}
private static function redactProxyUserInfo(#[\SensitiveParameter]string$error,#[\SensitiveParameter]?string$proxy
):string{
if($proxy===null||$proxy===''){
return$error;
}
return Psr7\Utils::redactUserInfoInString($error,$proxy);
}
private function forceFreshConnectionForAuthenticatedProxy(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$conf
):void{
$proxy=self::getEffectiveProxy($conf);
if($proxy===null
||(!self::requiresFreshConnectionForAuthenticatedProxy($request,$proxy,$conf)&&!$this->isOpaqueShareAnonymousProxyTunnel($request,$proxy,$conf))){
return;
}
if($this->shareMode===TransportSharing::PERSISTENT_REQUIRE){
throw new InvalidArgumentException(self::PERSISTENT_REQUIRE_FRESH_PROXY_TUNNEL_MESSAGE);
}
$conf[\CURLOPT_FRESH_CONNECT]=true;
$conf[\CURLOPT_FORBID_REUSE]=true;
}
private function isOpaqueShareAnonymousProxyTunnel(RequestInterface$request,string$proxy,array$conf):bool
{
if(!$this->opaqueShareConnectionCache||!CurlVersion::supportsShareConnectionCaches()){
return false;
}
if(!self::usesProxyTunnel($request,$conf)||!self::isHttpProxyForConnectionReuse($proxy,$conf)){
return false;
}
if(self::hasCurlProxyAuthorizationHeader($conf)||self::hasCurlProxyTlsCredentials($conf)||self::hasCurlProxyCredentials($conf)){
return false;
}
$proxyForParsing=\strpos($proxy,'://')===false?'http://'.$proxy:$proxy;
$proxyParts=\parse_url($proxyForParsing);
if(\is_array($proxyParts)&&(\array_key_exists('user',$proxyParts)||\array_key_exists('pass',$proxyParts))){
return false;
}
return true;
}
private static function getEffectiveProxy(array$conf):?string
{
if(!\array_key_exists(\CURLOPT_PROXY,$conf)){
return;
}
$proxy=$conf[\CURLOPT_PROXY];
return\is_string($proxy)&&$proxy!==''?$proxy:null;
}
private static function normalizeCurlHeaderOptions(#[\SensitiveParameter]array&$conf
):void{
$options=[\CURLOPT_HTTPHEADER=>'CURLOPT_HTTPHEADER'];
if(\defined('CURLOPT_PROXYHEADER')){
$options[(int)\constant('CURLOPT_PROXYHEADER')]='CURLOPT_PROXYHEADER';
}
foreach($options as$option=>$label){
if(!\array_key_exists($option,$conf)||!\is_array($conf[$option])){
continue;
}
$normalized=[];
foreach($conf[$option]as$key=>$entry){
if(\is_object($entry)&&\method_exists($entry,'__toString')){
$entry=(string)$entry;
}elseif(!\is_string($entry)){
throw new InvalidArgumentException(\sprintf('%s entries must be strings or stringable objects.',$label));
}
if(\strpbrk($entry,"\r\n")!==false){
throw new InvalidArgumentException(\sprintf('%s entries must not contain a carriage return or line feed.',$label));
}
$normalized[$key]=$entry;
}
$conf[$option]=$normalized;
}
}
private static function requiresFreshConnectionForAuthenticatedProxy(RequestInterface$request,string$proxy,array$conf):bool
{
if(self::isSocksProxy($proxy,$conf)){
return!CurlVersion::supportsSocksProxyCredentialAwareConnectionReuse();
}
if(!self::usesProxyTunnel($request,$conf)||!self::isHttpProxyForConnectionReuse($proxy,$conf)){
return false;
}
$proxyForParsing=\strpos($proxy,'://')===false?'http://'.$proxy:$proxy;
$proxyParts=\parse_url($proxyForParsing);
if(!\is_array($proxyParts)){
return false;
}
if(self::hasCurlProxyAuthorizationHeader($conf)){
return true;
}
if(!CurlVersion::supportsProxyTlsCredentialAwareConnectionReuse()&&self::hasCurlProxyTlsCredentials($conf)){
return true;
}
if(CurlVersion::supportsProxyCredentialAwareConnectionReuse()){
return false;
}
return\array_key_exists('user',$proxyParts)||\array_key_exists('pass',$proxyParts)||self::hasCurlProxyCredentials($conf);
}
private static function applyProxyConnectHeaderSuppression(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$conf
):void{
$proxy=$conf[\CURLOPT_PROXY]??null;
if(!\is_string($proxy)||$proxy===''||self::isSocksProxy($proxy,$conf)||!self::usesProxyTunnel($request,$conf)){
return;
}
if(!CurlVersion::supportsProxyTunneling()){
throw new RequestException('Tunneling requests through an HTTP proxy is not supported by the installed libcurl; libcurl 7.54.0 or newer is required.',$request);
}
$conf[(int)\constant('CURLOPT_SUPPRESS_CONNECT_HEADERS')]=true;
}
private static function usesProxyTunnel(RequestInterface$request,array$conf):bool
{
$scheme=$request->getUri()->getScheme();
if('https'===$scheme){
return true;
}
if('http'===$scheme&&self::hasCurlConnectTo($conf)){
return true;
}
return\defined('CURLOPT_HTTPPROXYTUNNEL')&&\array_key_exists((int)\constant('CURLOPT_HTTPPROXYTUNNEL'),$conf)&&(bool)$conf[(int)\constant('CURLOPT_HTTPPROXYTUNNEL')];
}
private static function hasCurlConnectTo(array$conf):bool
{
if(!\defined('CURLOPT_CONNECT_TO')){
return false;
}
$option=(int)\constant('CURLOPT_CONNECT_TO');
if(!\array_key_exists($option,$conf)){
return false;
}
$value=$conf[$option];
return\is_array($value)?$value!==[]:$value!==null&&$value!==false&&$value!=='';
}
private static function isHttpProxyForConnectionReuse(string$proxy,array$conf):bool
{
if(\strpos($proxy,'://')!==false){
$proxyParts=\parse_url($proxy);
if(!\is_array($proxyParts)||!isset($proxyParts['scheme'])){
return false;
}
$proxyScheme=Psr7\Utils::asciiToLower($proxyParts['scheme']);
return$proxyScheme==='http'||$proxyScheme==='https';
}
return!self::isSocksProxyType($conf[\CURLOPT_PROXYTYPE]??null);
}
private static function proxyScheme(string$proxy):?string
{
$position=\strpos($proxy,'://');
return$position===false?null:Psr7\Utils::asciiToLower(\substr($proxy,0,$position));
}
private static function isSocksProxy(string$proxy,array$conf):bool
{
$scheme=self::proxyScheme($proxy);
if($scheme!==null){
if(\in_array($scheme,['socks','socks4','socks4a','socks5','socks5h'],true)){
return true;
}
if($scheme!=='http'){
return false;
}
}
return self::isSocksProxyType($conf[\CURLOPT_PROXYTYPE]??null);
}
private static function socksProxySignature(#[\SensitiveParameter]string$proxy,#[\SensitiveParameter]array$conf
):?string{
if(CurlVersion::supportsSocksProxyCredentialAwareConnectionReuse()){
return;
}
$credentialState=[];
foreach(['CURLOPT_PROXYUSERPWD','CURLOPT_PROXYUSERNAME','CURLOPT_PROXYPASSWORD','CURLOPT_PROXYTYPE']as$name){
$credentialState[$name]=\defined($name)?($conf[(int)\constant($name)]??null):null;
}
return\hash('sha256',\serialize(['socks',$proxy,$credentialState]));
}
private static function isSocksProxyType($proxyType):bool
{
if(!\is_int($proxyType)){
return false;
}
foreach(['CURLPROXY_SOCKS4'=>4,'CURLPROXY_SOCKS5'=>5,'CURLPROXY_SOCKS4A'=>6,'CURLPROXY_SOCKS5_HOSTNAME'=>7,]as$name=>$fallback){
$value=\defined($name)?(int)\constant($name):$fallback;
if($proxyType===$value){
return true;
}
}
return false;
}
private static function hasCurlProxyCredentials(array$conf):bool
{
foreach(['CURLOPT_PROXYUSERPWD','CURLOPT_PROXYUSERNAME','CURLOPT_PROXYPASSWORD']as$option){
if(\defined($option)&&\array_key_exists((int)\constant($option),$conf)){
return true;
}
}
return false;
}
private static function hasCurlProxyTlsCredentials(array$conf):bool
{
foreach(['CURLOPT_PROXY_SSLCERT','CURLOPT_PROXY_SSLCERT_BLOB','CURLOPT_PROXY_TLSAUTH_USERNAME','CURLOPT_PROXY_TLSAUTH_PASSWORD',]as$option){
if(\defined($option)&&\array_key_exists((int)\constant($option),$conf)){
return true;
}
}
return false;
}
private static function hasCurlProxyAuthorizationHeader(array$conf):bool
{
return self::curlProxyAuthorizationHeaderValues($conf)!==[];
}
private static function managedProxyAuthorizationHeaderLines(#[\SensitiveParameter]RequestInterface$request
):array{
$headers=[];
foreach($request->getHeader('Proxy-Authorization')as$value){
$headers[]=$value===''?'Proxy-Authorization;':'Proxy-Authorization: '.$value;
}
return$headers;
}
private static function applyProxyAuthorizationHeaderHandling(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$conf,#[\SensitiveParameter]array$managedHeaders
):void{
if($managedHeaders!==[]||self::hasCurlProxyHeaderOption($conf)){
if(!CurlVersion::supportsProxyHeaderSeparation()){
throw new RequestException('Proxy headers require libcurl 7.37.0 or newer built with proxy header separation support.',$request);
}
if($managedHeaders!==[]){
self::appendCurlProxyHeaders($conf,$managedHeaders);
}
$conf[(int)\constant('CURLOPT_HEADEROPT')]=(int)\constant('CURLHEADER_SEPARATE');
}
$proxy=self::getEffectiveProxy($conf);
if(CurlVersion::supportsProxyHeaderSeparation()&&$proxy!==null
&&self::isHttpProxyForConnectionReuse($proxy,$conf)&&self::usesProxyTunnel($request,$conf)){
$conf[(int)\constant('CURLOPT_HEADEROPT')]=(int)\constant('CURLHEADER_SEPARATE');
}
}
private static function appendCurlProxyHeaders(#[\SensitiveParameter]array&$conf,#[\SensitiveParameter]array$headers
):void{
$option=(int)\constant('CURLOPT_PROXYHEADER');
if(\array_key_exists($option,$conf)){
if(!\is_array($conf[$option])){
throw new InvalidArgumentException('CURLOPT_PROXYHEADER must be an array when a Proxy-Authorization request header is routed to the proxy header channel.');
}
$headers=\array_merge($conf[$option],$headers);
}
$conf[$option]=$headers;
}
private static function hasCurlProxyHeaderOption(array$conf):bool
{
return\defined('CURLOPT_PROXYHEADER')&&\array_key_exists((int)\constant('CURLOPT_PROXYHEADER'),$conf);
}
private static function proxyAuthorizationHeaderValuesFromList(array$headers):array
{
$values=[];
foreach($headers as$header){
if(!\is_string($header)){
continue;
}
$position=\strpos($header,':');
if($position===false){
continue;
}
if(!Psr7\Utils::caselessEquals(\trim(\substr($header,0,$position)," \n\r\t\0\x0B"),'Proxy-Authorization')){
continue;
}
$value=\trim(\substr($header,$position+1)," \n\r\t\0\x0B");
if($value!==''){
$values[]=$value;
}
}
return$values;
}
private static function proxyTunnelSignature(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$conf
):?string{
$proxy=self::getEffectiveProxy($conf);
if($proxy===null){
return;
}
if(self::isSocksProxy($proxy,$conf)){
return self::socksProxySignature($proxy,$conf);
}
if(!self::usesProxyTunnel($request,$conf)||!self::isHttpProxyForConnectionReuse($proxy,$conf)){
return;
}
$headerAuth=self::curlProxyAuthorizationHeaderValues($conf);
if($headerAuth===[]&&CurlVersion::supportsProxyCredentialAwareConnectionReuse()){
return self::DELEGATED_PROXY_TUNNEL_OWNER;
}
$credentialState=[];
foreach(['CURLOPT_PROXYUSERPWD','CURLOPT_PROXYUSERNAME','CURLOPT_PROXYPASSWORD','CURLOPT_PROXYTYPE','CURLOPT_PROXY_SSLCERT','CURLOPT_PROXY_SSLCERT_BLOB','CURLOPT_PROXY_SSLKEY','CURLOPT_PROXY_KEYPASSWD','CURLOPT_PROXY_TLSAUTH_USERNAME','CURLOPT_PROXY_TLSAUTH_PASSWORD','CURLOPT_PROXY_SSLVERSION',]as$name){
$credentialState[$name]=\defined($name)?($conf[(int)\constant($name)]??null):null;
}
return\hash('sha256',\serialize([$proxy,$credentialState,$headerAuth]));
}
private static function curlProxyAuthorizationHeaderValues(array$conf):array
{
if(!\defined('CURLOPT_PROXYHEADER')){
return[];
}
$option=(int)\constant('CURLOPT_PROXYHEADER');
if(!\array_key_exists($option,$conf)){
return[];
}
$headers=$conf[$option];
if(!\is_array($headers)){
return[];
}
return self::proxyAuthorizationHeaderValuesFromList($headers);
}
private function discardIdleHandles():void
{
foreach($this->handles as$id=>$handle){
try{
$this->discardHandle($handle);
}catch(\Throwable$e){
}finally{
unset($this->handles[$id]);
}
}
}
private function getDefaultConf(#[\SensitiveParameter]EasyHandle$easy
):array{
$uri=$easy->request->getUri();
$protocols=Utils::normalizeProtocols($easy->options['protocols']??['http','https']);
$scheme=$uri->getScheme();
if(!\in_array($scheme,$protocols,true)){
throw new RequestException(\sprintf('The scheme "%s" is not allowed by the protocols request option.',Psr7\DiagnosticValue::escape($scheme)),$easy->request);
}
if($uri->getHost()===''){
throw new RequestException('URI must include a scheme and host. Use an absolute URI, a network-path reference starting with //, or configure a base_uri.',$easy->request);
}
$conf=['_headers'=>$easy->request->getHeaders(),\CURLOPT_CUSTOMREQUEST=>$easy->request->getMethod(),\CURLOPT_URL=>(string)$uri->withFragment(''),\CURLOPT_RETURNTRANSFER=>false,\CURLOPT_HEADER=>false,\CURLOPT_CONNECTTIMEOUT_MS=>self::DEFAULT_CONNECT_TIMEOUT_MS,];
if(CurlVersion::supportsProtocolsStr()){
$conf[(int)\constant('CURLOPT_PROTOCOLS_STR')]=\implode(',',$protocols);
}else{
$conf[\CURLOPT_PROTOCOLS]=self::curlProtocolMask($protocols);
}
$version=$easy->request->getProtocolVersion();
$multiplex=self::normalizeMultiplex($easy->options);
if('3'===$version||'3.0'===$version){
if(!\defined('CURL_HTTP_VERSION_3')){
throw new RequestException('HTTP/3 is not supported by this cURL installation.',$easy->request);
}
$proxy=ProxyEnv::resolveProxySelection($easy->request->getUri(),$easy->options['proxy']??null);
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
self::assertSelectedProxySupported($proxy->getProxy(),$easy->request);
if($proxy->hasProxy()){
throw new RequestException('Required multiplexing cannot be guaranteed for HTTP/3 requests sent through a proxy.',$easy->request);
}
if(!CurlVersion::supportsRequiredHttp3Multiplex()){
throw new RequestException('Required multiplexing for HTTP/3 needs libcurl 8.13.0 or newer built with HTTP/3 support.',$easy->request);
}
$conf[\CURLOPT_HTTP_VERSION]=(int)\constant('CURL_HTTP_VERSION_3ONLY');
}else{
$conf[\CURLOPT_HTTP_VERSION]=$proxy->hasProxy()?(CurlVersion::supportsHttp2()?\CURL_HTTP_VERSION_2_0:\CURL_HTTP_VERSION_1_1):(int)\constant('CURL_HTTP_VERSION_3');
}
}elseif('2'===$version||'2.0'===$version){
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
self::assertRequiredMultiplexSupported($easy);
$conf[\CURLOPT_HTTP_VERSION]=(int)\constant('CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE');
}else{
$conf[\CURLOPT_HTTP_VERSION]=\CURL_HTTP_VERSION_2_0;
}
}elseif('1.1'===$version){
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new RequestException(\sprintf('The "multiplex" request option cannot be required for HTTP/%s requests; use protocol version 2 or 3.',$version),$easy->request);
}
$conf[\CURLOPT_HTTP_VERSION]=\CURL_HTTP_VERSION_1_1;
}else{
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new RequestException(\sprintf('The "multiplex" request option cannot be required for HTTP/%s requests; use protocol version 2 or 3.',$version),$easy->request);
}
$conf[\CURLOPT_HTTP_VERSION]=\CURL_HTTP_VERSION_1_0;
}
$resolvedVersion=$conf[\CURLOPT_HTTP_VERSION];
if(\in_array($multiplex,[Multiplexing::WAIT,Multiplexing::REQUIRE_WAIT],true)&&CurlVersion::supportsMultiplex()&&($resolvedVersion===\CURL_HTTP_VERSION_2_0
||(\defined('CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE')&&$resolvedVersion===(int)\constant('CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE'))||(\defined('CURL_HTTP_VERSION_3')&&$resolvedVersion===(int)\constant('CURL_HTTP_VERSION_3'))||(\defined('CURL_HTTP_VERSION_3ONLY')&&$resolvedVersion===(int)\constant('CURL_HTTP_VERSION_3ONLY')))){
$conf[(int)\constant('CURLOPT_PIPEWAIT')]=true;
}
return$conf;
}
private static function curlProtocolMask(array$protocols):int
{
$mask=0;
if(\in_array('http',$protocols,true)){
$mask|=\CURLPROTO_HTTP;
}
if(\in_array('https',$protocols,true)){
$mask|=\CURLPROTO_HTTPS;
}
return$mask;
}
private static function normalizeTlsFileType(string$option,$type):string
{
if(!\is_string($type)||$type===''){
throw new InvalidArgumentException(\sprintf('%s must be a non-empty string',$option));
}
return Psr7\Utils::asciiToUpper($type);
}
private static function shouldValidateSslKeyFile(?string$type):bool
{
return$type!=='ENG'&&$type!=='PROV';
}
private function applyMethod(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array&$conf,RequestFraming$framing
):void{
if($easy->request->getMethod()==='HEAD'){
$conf[\CURLOPT_CUSTOMREQUEST]=null;
$conf[\CURLOPT_NOBODY]=true;
unset($conf[\CURLOPT_WRITEFUNCTION],$conf[\CURLOPT_READFUNCTION],$conf[\CURLOPT_FILE],$conf[\CURLOPT_INFILE]);
if(\defined('CURLOPT_SEEKFUNCTION')){
unset($conf[(int)\constant('CURLOPT_SEEKFUNCTION')]);
}
if(\trim($easy->request->getHeaderLine('Content-Length')," \n\r\t\0\x0B")!=='0'){
$this->removeHeader('Content-Length',$conf);
}
$this->removeHeader('Transfer-Encoding',$conf);
if(Psr7\Utils::caselessEquals(\trim($easy->request->getHeaderLine('Expect')," \n\r\t\0\x0B"),'100-continue')){
$this->removeHeader('Expect',$conf);
}
return;
}
if($framing->bodySize!==0&&$framing->contentLength!==0){
$this->applyBody($easy,$conf,$framing);
}
}
private function applyBody(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array&$conf,RequestFraming$framing
):void{
$request=$easy->request;
$options=$easy->options;
$contentLength=$framing->contentLength;
if(($framing->bodySize!==null&&$framing->bodySize<1000000)||!empty($options['_body_as_string'])){
$conf[\CURLOPT_POSTFIELDS]=$framing->materialize();
$this->removeHeader('Content-Length',$conf);
$this->removeHeader('Transfer-Encoding',$conf);
}else{
$conf[\CURLOPT_UPLOAD]=true;
if($contentLength!==null){
$this->removeHeader('Content-Length',$conf);
$conf[self::curlInputSizeOption($request,$contentLength)]=$contentLength;
}
$body=$request->getBody();
try{
if($body->isSeekable()){
$body->rewind();
}
}catch(\Exception$e){
$message=$e instanceof TimeoutException
?'Timed out while rewinding the request body':($e->getMessage()!==''?$e->getMessage():'Failed to rewind the request body');
throw new RequestException($message,$request,0,$e);
}
$remaining=$contentLength;
$conf[\CURLOPT_READFUNCTION]=static function(#[\SensitiveParameter]$ch,#[\SensitiveParameter]$fd,int$length
)use($easy,$body,&$remaining){
if($remaining===0){
return'';
}
$limit=$remaining===null?$length:\min($length,$remaining);
try{
$data=$body->read($limit);
}catch(TimeoutException$e){
$easy->bodyReadTimeoutException=$e;
return self::CURL_READFUNC_ABORT;
}catch(\Throwable$e){
$easy->bodyReadException=$e;
return self::CURL_READFUNC_ABORT;
}
$dataLength=\strlen($data);
if($dataLength>$limit){
$easy->bodyReadException=new\RuntimeException('Request body stream returned more bytes than requested');
return self::CURL_READFUNC_ABORT;
}
if($remaining!==null){
if($data===''){
$easy->bodyReadException=new\RuntimeException('Request body ended before the declared Content-Length was reached');
return self::CURL_READFUNC_ABORT;
}
$remaining-=$dataLength;
}
return$data;
};
if(\defined('CURLOPT_SEEKFUNCTION')){
$successfulSeeks=0;
$conf[(int)\constant('CURLOPT_SEEKFUNCTION')]=static function(#[\SensitiveParameter]$ch,int$offset,int$origin
)use($easy,$body,$contentLength,&$remaining,&$successfulSeeks):int{
if($origin!==\SEEK_SET){
return self::CURL_SEEKFUNC_CANTSEEK;
}
try{
if(!$body->isSeekable()){
return self::CURL_SEEKFUNC_CANTSEEK;
}
if($offset<0||($contentLength!==null&&$offset>$contentLength)){
throw new\RuntimeException('Request body seek offset is outside the declared Content-Length');
}
if($successfulSeeks>=self::CURL_SEEK_MAX_REPLAYS){
throw new\RuntimeException(\sprintf('Request body cannot be replayed more than %d times',self::CURL_SEEK_MAX_REPLAYS));
}
$body->seek($offset,\SEEK_SET);
}catch(TimeoutException$e){
$easy->bodyRewindTimeoutException=$e;
return self::CURL_SEEKFUNC_FAIL;
}catch(\Throwable$e){
$easy->bodyRewindException=$e;
return self::CURL_SEEKFUNC_FAIL;
}
$remaining=$contentLength===null?null:$contentLength-$offset;
++$successfulSeeks;
return self::CURL_SEEKFUNC_OK;
};
}
}
if(!$request->hasHeader('Expect')){
$conf[\CURLOPT_HTTPHEADER][]='Expect:';
}
if(!$request->hasHeader('Content-Type')){
$conf[\CURLOPT_HTTPHEADER][]='Content-Type:';
}
}
private static function curlInputSizeOption(#[\SensitiveParameter]RequestInterface$request,int$contentLength
):int{
$option=\defined('CURLOPT_INFILESIZE_LARGE')?(int)\constant('CURLOPT_INFILESIZE_LARGE'):\CURLOPT_INFILESIZE;
if(\PHP_OS_FAMILY==='Windows'&&$option===\CURLOPT_INFILESIZE&&$contentLength>2147483647){
throw new RequestException('Content-Length exceeds the maximum cURL upload size supported by this PHP build',$request);
}
return$option;
}
private function applyHeaders(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array&$conf
):void{
foreach($conf['_headers']as$name=>$values){
if(Psr7\Utils::caselessEquals((string)$name,'Proxy-Authorization')){
continue;
}
foreach($values as$value){
$value=(string)$value;
if($value===''){
$conf[\CURLOPT_HTTPHEADER][]="$name;";
}else{
$conf[\CURLOPT_HTTPHEADER][]="$name: $value";
}
}
}
if(!$easy->request->hasHeader('Accept')){
$conf[\CURLOPT_HTTPHEADER][]='Accept:';
}
}
private function removeHeader(string$name,array&$options):void
{
foreach(\array_keys($options['_headers'])as$key){
if(Psr7\Utils::caselessEquals((string)$key,$name)){
unset($options['_headers'][$key]);
return;
}
}
}
private static function streamForResourceSink(StreamInterface$stream):StreamInterface
{
return FnStream::decorate($stream,['close'=>static function()use($stream):void{
$stream->detach();
},]);
}
private static function requireStreamFactory($factory):StreamFactoryInterface
{
if(!$factory instanceof StreamFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::STREAM_FACTORY,StreamFactoryInterface::class
));
}
return$factory;
}
private function applyHandlerOptions(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array&$conf
):void{
$options=$easy->options;
if(isset($options['verify'])){
if($options['verify']===false){
unset($conf[\CURLOPT_CAINFO]);
$conf[\CURLOPT_SSL_VERIFYHOST]=0;
$conf[\CURLOPT_SSL_VERIFYPEER]=false;
}else{
$conf[\CURLOPT_SSL_VERIFYHOST]=2;
$conf[\CURLOPT_SSL_VERIFYPEER]=true;
if(\is_string($options['verify'])){
if(!\file_exists($options['verify'])){
throw new InvalidArgumentException(\sprintf('SSL CA bundle not found: %s',Psr7\DiagnosticValue::escape($options['verify'])));
}
if(\is_dir($options['verify'])||(\is_link($options['verify'])===true
&&($verifyLink=\readlink($options['verify']))!==false
&&\is_dir($verifyLink))){
$conf[\CURLOPT_CAPATH]=$options['verify'];
}else{
$conf[\CURLOPT_CAINFO]=$options['verify'];
}
}
}
}
if(!isset($options['curl'][\CURLOPT_ENCODING])&&isset($options['decode_content'])&&$options['decode_content']!==false){
$accept=$easy->request->getHeaderLine('Accept-Encoding');
if($accept!==''){
$conf[\CURLOPT_ENCODING]=$accept;
}else{
$conf[\CURLOPT_ENCODING]='';
$conf[\CURLOPT_HTTPHEADER][]='Accept-Encoding:';
}
}
$streamFactory=self::requireStreamFactory($options[RequestOptions::STREAM_FACTORY]??new HttpFactory);
$hasSink=isset($options['sink']);
if(!$hasSink){
$options['sink']=Psr7\Utils::tryFopen('php://temp','w+');
}
$sink=$options['sink'];
if($hasSink&&\is_resource($sink)){
$sink=self::streamForResourceSink(Psr7\Utils::streamFor($sink));
}elseif(\is_resource($sink)){
$sink=$streamFactory->createStreamFromResource($sink);
}elseif(!\is_string($sink)){
$sink=Psr7\Utils::streamFor($sink);
}elseif(!\is_dir(\dirname($sink))){
throw new RequestException(\sprintf('Directory %s does not exist for sink value of %s',Psr7\DiagnosticValue::escape(\dirname($sink)),Psr7\DiagnosticValue::escape($sink)),$easy->request);
}else{
$sink=new LazyOpenStream($sink,'w+');
}
$easy->sink=$sink;
$conf[\CURLOPT_WRITEFUNCTION]=static function($ch,string$write)use($easy,$sink):int{
$length=\strlen($write);
try{
$newResponseBodyBytes=TransferByteCounter::add($easy->responseBodyBytes,$length,'Response body exceeds the maximum integer size supported on this platform');
}catch(\OverflowException$e){
$easy->responseBodySizeException=$e;
return 0;
}
try{
$written=$sink->write($write);
}catch(TimeoutException$e){
$easy->sinkWriteTimeoutException=$e;
return 0;
}catch(\Throwable$e){
$easy->sinkWriteException=$e;
return 0;
}
if($written!==$length){
$easy->sinkWriteIncomplete=true;
return 0;
}
$easy->responseBodyBytes=$newResponseBodyBytes;
return$written;
};
$timeoutRequiresNoSignal=false;
if(isset($options['timeout'])){
$timeout=Timeout::toMilliseconds($options['timeout'],'timeout');
$timeoutRequiresNoSignal|=$timeout>0&&$timeout<1000;
$conf[\CURLOPT_TIMEOUT_MS]=$timeout;
}
if(isset($options['force_ip_resolve'])){
if('v4'===$options['force_ip_resolve']){
$conf[\CURLOPT_IPRESOLVE]=\CURL_IPRESOLVE_V4;
}elseif('v6'===$options['force_ip_resolve']){
$conf[\CURLOPT_IPRESOLVE]=\CURL_IPRESOLVE_V6;
}
}
if(isset($options['connect_timeout'])){
$connectTimeout=Timeout::toMilliseconds($options['connect_timeout'],'connect_timeout');
if($connectTimeout>0){
$timeoutRequiresNoSignal|=$connectTimeout<1000;
$conf[\CURLOPT_CONNECTTIMEOUT_MS]=$connectTimeout;
}else{
$conf[\CURLOPT_CONNECTTIMEOUT_MS]=self::CONNECT_TIMEOUT_DISABLED_MS;
}
}
if($timeoutRequiresNoSignal&&\PHP_OS_FAMILY!=='Windows'){
$conf[\CURLOPT_NOSIGNAL]=true;
}
$proxy=ProxyEnv::resolveProxySelection($easy->request->getUri(),$options['proxy']??null);
$selectedProxy=$proxy->getProxy();
if($selectedProxy!==null){
self::assertSelectedProxySupported($selectedProxy,$easy->request);
$conf[\CURLOPT_PROXY]=$selectedProxy;
$conf[\CURLOPT_NOPROXY]='';
}else{
$conf[\CURLOPT_PROXY]='';
$conf[\CURLOPT_NOPROXY]=$proxy->isBypassed()?'*':'';
}
$this->applyTlsVersionRange($easy,$conf);
$certType=null;
if(isset($options['cert_type'])){
$certType=self::normalizeTlsFileType('cert_type',$options['cert_type']);
$conf[\CURLOPT_SSLCERTTYPE]=$certType;
}
if(isset($options['cert'])){
$cert=$options['cert'];
if(\is_array($cert)){
if(!isset($cert[0])||!\is_string($cert[0])){
throw new InvalidArgumentException('Invalid cert request option');
}
if(isset($cert[1])){
if(!\is_string($cert[1])){
throw new InvalidArgumentException('Invalid cert request option');
}
$conf[\CURLOPT_SSLCERTPASSWD]=$cert[1];
}
$cert=$cert[0];
}
if(!\is_string($cert)){
throw new InvalidArgumentException('Invalid cert request option');
}
if(!\file_exists($cert)){
throw new InvalidArgumentException(\sprintf('SSL certificate not found: %s',Psr7\DiagnosticValue::escape($cert)));
}
$ext=pathinfo($cert,\PATHINFO_EXTENSION);
if($certType===null&&preg_match('#^(der|p12)$#iD',$ext)){
$conf[\CURLOPT_SSLCERTTYPE]=Psr7\Utils::asciiToUpper($ext);
}
$conf[\CURLOPT_SSLCERT]=$cert;
}
$sslKeyType=null;
if(isset($options['ssl_key_type'])){
$sslKeyType=self::normalizeTlsFileType('ssl_key_type',$options['ssl_key_type']);
$conf[\CURLOPT_SSLKEYTYPE]=$sslKeyType;
}
if(isset($options['ssl_key'])){
if(\is_array($options['ssl_key'])){
if(!isset($options['ssl_key'][0])||!\is_string($options['ssl_key'][0])){
throw new InvalidArgumentException('Invalid ssl_key request option');
}
if(isset($options['ssl_key'][1])){
if(!\is_string($options['ssl_key'][1])){
throw new InvalidArgumentException('Invalid ssl_key request option');
}
$conf[\CURLOPT_SSLKEYPASSWD]=$options['ssl_key'][1];
}
$sslKey=$options['ssl_key'][0];
}
$sslKey=$sslKey??$options['ssl_key'];
if(!\is_string($sslKey)){
throw new InvalidArgumentException('Invalid ssl_key request option');
}
if(self::shouldValidateSslKeyFile($sslKeyType)&&!\file_exists($sslKey)){
throw new InvalidArgumentException(\sprintf('SSL private key not found: %s',Psr7\DiagnosticValue::escape($sslKey)));
}
$conf[\CURLOPT_SSLKEY]=$sslKey;
}
$progress=$options['progress']??null;
if($progress!==null&&!\is_callable($progress)){
throw new InvalidArgumentException('progress client option must be callable');
}
$abortsOnBodyReadFailure=isset($conf[\CURLOPT_READFUNCTION]);
if($progress!==null||$abortsOnBodyReadFailure){
$conf[\CURLOPT_NOPROGRESS]=false;
$progressCallback=static function($resource,$downloadSize,$downloaded,$uploadSize,$uploaded)use($easy,$progress):int{
if($easy->bodyReadTimeoutException!==null||$easy->bodyRewindTimeoutException!==null||$easy->bodyRewindException!==null||$easy->bodyReadException!==null){
return 1;
}
if($progress===null){
return 0;
}
try{
if($progress(TransferByteCounter::progressValueToInt($downloadSize),TransferByteCounter::progressValueToInt($downloaded),TransferByteCounter::progressValueToInt($uploadSize),TransferByteCounter::progressValueToInt($uploaded))){
$easy->progressAborted=true;
return 1;
}
return 0;
}catch(\Throwable$e){
$easy->progressException=$e;
return 1;
}
};
if(\defined('CURLOPT_XFERINFOFUNCTION')){
$conf[(int)\constant('CURLOPT_XFERINFOFUNCTION')]=$progressCallback;
}else{
$conf[\CURLOPT_PROGRESSFUNCTION]=$progressCallback;
}
}
if(!empty($options['debug'])){
$conf[\CURLOPT_STDERR]=Utils::debugResource($options['debug']);
$conf[\CURLOPT_VERBOSE]=true;
}
}
private function applyTlsVersionRange(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array&$conf
):void{
$options=$easy->options;
$cryptoMethod=$options['crypto_method']??null;
$cryptoMethodMax=$options['crypto_method_max']??null;
if($cryptoMethod===null&&'https'===$easy->request->getUri()->getScheme()){
$cryptoMethod=\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
}
if($cryptoMethod===null&&$cryptoMethodMax===null){
return;
}
$protocolVersion=$easy->request->getProtocolVersion();
$isHttp3='3'===$protocolVersion||'3.0'===$protocolVersion;
$isHttp2='2'===$protocolVersion||'2.0'===$protocolVersion;
if(($isHttp2||$isHttp3)&&$cryptoMethodMax!==null&&TlsVersion::ordinal('crypto_method_max',$cryptoMethodMax)<12){
throw new InvalidArgumentException('Invalid crypto_method_max request option: HTTP/2 and HTTP/3 require TLS 1.2 or higher');
}
if(($isHttp2||$isHttp3)&&$cryptoMethod!==null&&TlsVersion::ordinal('crypto_method',$cryptoMethod)<12){
$cryptoMethod=\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
}
TlsVersion::assertRange($cryptoMethod,$cryptoMethodMax);
$sslVersion=$cryptoMethod===null
?\CURL_SSLVERSION_DEFAULT
:self::curlMinSslVersion($easy,$cryptoMethod);
if($cryptoMethodMax!==null){
$sslVersion|=self::curlMaxSslVersion($easy,$cryptoMethodMax);
}
$conf[\CURLOPT_SSLVERSION]=$sslVersion;
}
private static function curlMinSslVersion(#[\SensitiveParameter]EasyHandle$easy,int$value
):int{
if($value===\STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT){
return\CURL_SSLVERSION_TLSv1_0;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT){
return\CURL_SSLVERSION_TLSv1_1;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT){
return\CURL_SSLVERSION_TLSv1_2;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT){
if(!CurlVersion::supportsTls13()){
throw new RequestException('Invalid crypto_method request option: TLS 1.3 not supported by your version of cURL',$easy->request
);
}
return\CURL_SSLVERSION_TLSv1_3;
}
throw new InvalidArgumentException('Invalid crypto_method request option: unknown version provided');
}
private static function curlMaxSslVersion(#[\SensitiveParameter]EasyHandle$easy,int$value
):int{
if($value===\STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT){
return self::requireCurlMaxSslVersion($easy,'CURL_SSLVERSION_MAX_TLSv1_0');
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT){
return self::requireCurlMaxSslVersion($easy,'CURL_SSLVERSION_MAX_TLSv1_1');
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT){
return self::requireCurlMaxSslVersion($easy,'CURL_SSLVERSION_MAX_TLSv1_2');
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT){
return self::requireCurlMaxSslVersion($easy,'CURL_SSLVERSION_MAX_TLSv1_3');
}
throw new InvalidArgumentException('Invalid crypto_method_max request option: unknown version provided');
}
private static function requireCurlMaxSslVersion(#[\SensitiveParameter]EasyHandle$easy,string$constant
):int{
if(\defined($constant)){
return\constant($constant);
}
throw new RequestException('Invalid crypto_method_max request option: maximum TLS version control is not supported by your version of cURL',$easy->request
);
}
private static function retryFailedRewind(callable$handler,#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array$ctx
):PromiseInterface{
try{
$body=$easy->request->getBody();
if($body->tell()>0){
$body->rewind();
}
}catch(\Exception$e){
$ctx['error']='The connection unexpectedly failed without providing an error. The request would have been retried, but attempting to rewind the request body failed.';
return self::createRejection($easy,$ctx,$e);
}
if(!isset($easy->options['_curl_retries'])){
$easy->options['_curl_retries']=1;
}elseif($easy->options['_curl_retries']==2){
$ctx['error']='The cURL request was retried 3 times '.'and did not succeed. The most likely reason for the failure '.'is that cURL was unable to rewind the body of the request '.'and subsequent retries resulted in the same error. Turn on '.'the debug option to see what went wrong. See '.'https://bugs.php.net/bug.php?id=47204 for more information.';
return self::createRejection($easy,$ctx);
}else{
++$easy->options['_curl_retries'];
}
return$handler($easy->request,$easy->options);
}
private static function headersFromTrailerLines(array$lines):array
{
$headers=[];
foreach($lines as$line){
[$name,$value]=\explode(':',$line,2);
$name=Psr7\Utils::asciiToLower(\trim($name," \n\r\t\0\x0B"));
$headers[$name][]=\trim($value," \n\r\t\0\x0B");
}
return$headers;
}
private function createHeaderFn(#[\SensitiveParameter]EasyHandle$easy
):callable{
if(isset($easy->options['on_headers'])){
$onHeaders=$easy->options['on_headers'];
if(!\is_callable($onHeaders)){
throw new InvalidArgumentException('on_headers must be callable');
}
}else{
$onHeaders=null;
}
$startingResponse=false;
$collectingTrailers=false;
$retainTrailers=isset($easy->options['on_trailers']);
return static function($ch,string$h)use($onHeaders,$easy,&$startingResponse,&$collectingTrailers,$retainTrailers
):int{
$value=\trim($h," \n\r\t\0\x0B");
if($h==="\r\n"||$h==="\n"||$h==="\r"||$h===''){
if($collectingTrailers){
return\strlen($h);
}
$startingResponse=true;
try{
$easy->createResponse();
}catch(\Throwable$e){
$easy->response=null;
$easy->createResponseException=$e;
return-1;
}
if($easy->responseHeaderException!==null){
return-1;
}
if($onHeaders!==null&&$easy->response!==null){
try{
$onHeaders($easy->response,$easy->request);
}catch(\Throwable$e){
$easy->onHeadersException=$e;
return-1;
}
}
}elseif($startingResponse||$collectingTrailers){
if($easy->response!==null&&!HeaderProcessor::isStatusLineCandidate($h)){
$collectingTrailers=true;
if($retainTrailers&&HeaderProcessor::isValidHeaderFieldLine($h)){
$easy->trailers[]=$value;
}
}else{
$collectingTrailers=false;
$easy->trailers=[];
$easy->headers=[$value];
}
$startingResponse=false;
}else{
$easy->headers[]=$value;
}
return\strlen($h);
};
}
function __destruct(){
try{
$this->doClose(false);
}catch(\Throwable$e){
}
}
function __unserialize(array$data):void
{
$this->closed=true;
$this->handles=[];
$this->shareHandle=null;
throw new\LogicException(static::class.' should never be unserialized');
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\DiagnosticValue;
use GuzzleHttp\TransportSharing;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class CurlHandler
{
use NonSerializableTrait;
private const KNOWN_CONSTRUCTOR_OPTIONS=['handle_factory'=>true,'transport_sharing'=>true,];
private CurlFactoryInterface$factory;
private bool$ownsFactory;
private bool$closed=false;
private?CurlShareHandleState$shareHandleState;
function __construct(array$options=[]){
foreach($options as$name=>$_){
if(!isset(self::KNOWN_CONSTRUCTOR_OPTIONS[$name])){
throw new InvalidArgumentException(\sprintf('Invalid CurlHandler constructor option "%s".',DiagnosticValue::escape((string)$name)));
}
}
CurlShareHandleState::assertNoRequiredSharingCustomFactoryConflict($options,'CurlHandler');
$transportSharing=$options['transport_sharing']??null;
$sharingMode=CurlShareHandleState::normalizeMode($transportSharing,'transport_sharing');
if(\array_key_exists('handle_factory',$options)&&$options['handle_factory']!==null){
$this->shareHandleState=null;
$this->factory=$options['handle_factory'];
$this->ownsFactory=false;
return;
}
$this->shareHandleState=$sharingMode!==TransportSharing::NONE
?CurlShareHandleState::fromOption($transportSharing):null;
$this->factory=$this->shareHandleState!==null
?new CurlFactory(3,$this->shareHandleState->mode,$this->shareHandleState):new CurlFactory(3);
$this->ownsFactory=true;
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$this->assertOpen();
HostValidator::assertRequestHost($request);
if(isset($options['delay'])){
Clock::sleep((int)($options['delay']*1000));
}
$easy=$this->factory->create($request,$options);
\curl_exec($easy->handle);
$easy->errno=\curl_errno($easy->handle);
return CurlFactory::finish($this,$easy,$this->factory);
}
function close():void
{
$this->doClose(true);
}
function __destruct(){
try{
$this->doClose(false);
}catch(\Throwable$e){
}
}
function __unserialize(array$data):void
{
$this->closed=true;
throw new\LogicException(static::class.' should never be unserialized');
}
private function assertOpen():void
{
if($this->closed){
throw new\BadMethodCallException('Cannot use the cURL handler after it has been closed.');
}
}
private function doClose(bool$explicit):void
{
if($this->closed){
return;
}
$this->closed=true;
try{
if($this->ownsFactory&&$this->factory instanceof CurlFactory){
$this->factory->close();
}
}catch(\Throwable$e){
if($explicit){
throw$e;
}
}finally{
$this->shareHandleState=null;
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use Closure;
use GuzzleHttp\Exception\HandlerClosedException;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Multiplexing;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7;
use GuzzleHttp\TransportSharing;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class CurlMultiHandler
{
use NonSerializableTrait;
private const KNOWN_CONSTRUCTOR_OPTIONS=['handle_factory'=>true,'max_host_connections'=>true,'max_total_connections'=>true,'multiplex'=>true,'options'=>true,'select_timeout'=>true,'transport_sharing'=>true,];
private const CONNECTION_CAP_OPTIONS=['max_host_connections'=>'CURLMOPT_MAX_HOST_CONNECTIONS','max_total_connections'=>'CURLMOPT_MAX_TOTAL_CONNECTIONS',];
private const PROXY_TUNNEL_ISOLATION_OPTIONS=['CURLOPT_FRESH_CONNECT','CURLOPT_FORBID_REUSE',];
private CurlFactoryInterface$factory;
private bool$ownsFactory;
private?CurlShareHandleState$shareHandleState;
private float$selectTimeout;
private int$active=0;
private array$handles=[];
private array$delays=[];
private array$options=[];
private bool$multiplexDisabled=false;
private$multiHandle;
private bool$closed=false;
private bool$closing=false;
private int$multiExecDepth=0;
private bool$finishingDeferredWork=false;
private array$deferredCancels=[];
private array$deferredAdds=[];
private bool$deferredClose=false;
private bool$deferredCloseExplicit=false;
private?string$proxyTunnelOwner=null;
private array$activeProxyTunnelSignatures=[];
private array$activeProxyTunnelHandles=[];
private int$messageProcessingDepth=0;
function __construct(array$options=[]){
foreach($options as$name=>$_){
if(!isset(self::KNOWN_CONSTRUCTOR_OPTIONS[$name])){
throw new InvalidArgumentException(\sprintf('Invalid CurlMultiHandler constructor option "%s".',Psr7\DiagnosticValue::escape((string)$name)));
}
}
$handlerMultiplex=$options['multiplex']??null;
if(null!==$handlerMultiplex&&Multiplexing::NONE!==$handlerMultiplex){
if(\in_array($handlerMultiplex,[Multiplexing::EAGER,Multiplexing::WAIT,Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new InvalidArgumentException('The "multiplex" CurlMultiHandler option only accepts Multiplexing::NONE; the eager, wait, and required modes are request options.');
}
throw new InvalidArgumentException(\sprintf('The "multiplex" CurlMultiHandler option must be null or Multiplexing::NONE; received %s.',\get_debug_type($handlerMultiplex)));
}
$this->multiplexDisabled=null!==$handlerMultiplex;
if($this->multiplexDisabled&&!\defined('CURLMOPT_PIPELINING')){
throw new InvalidArgumentException('The "multiplex" CurlMultiHandler option requires CURLMOPT_PIPELINING, but it is not available in the installed PHP cURL extension.');
}
CurlShareHandleState::assertNoRequiredSharingCustomFactoryConflict($options,'CurlMultiHandler');
$transportSharing=$options['transport_sharing']??null;
$sharingMode=CurlShareHandleState::normalizeMode($transportSharing,'transport_sharing');
$selectTimeout=$options['select_timeout']??1.0;
Timeout::toMilliseconds($selectTimeout,'select_timeout');
$this->selectTimeout=(float)$selectTimeout;
$multiOptions=$options['options']??[];
if(!\is_array($multiOptions)){
throw new InvalidArgumentException('options must be an array of cURL multi options');
}
$this->options=$multiOptions;
self::rejectConflictingCurlMultiOptions($this->options);
$this->addConnectionCapOptions($options);
if($this->multiplexDisabled){
$this->options[\CURLMOPT_PIPELINING]=0;
}
$connectionCapOption=self::firstConnectionCapOption($options);
if($connectionCapOption!==null&&!CurlVersion::supportsSharedPoolConnectionCaps()){
$persistentShareState=$transportSharing instanceof CurlShareHandleState
&&\in_array($sharingMode,[TransportSharing::PERSISTENT_PREFER,TransportSharing::PERSISTENT_REQUIRE],true);
if($persistentShareState||$sharingMode===TransportSharing::PERSISTENT_REQUIRE){
throw new InvalidArgumentException(\sprintf('%s cannot be combined with persistent transport sharing because applying connection caps to shared connection pools requires libcurl %s or higher.',$connectionCapOption,CurlVersion::SHARED_POOL_CONNECTION_CAP_VERSION));
}
if($sharingMode===TransportSharing::PERSISTENT_PREFER){
$transportSharing=TransportSharing::HANDLER_PREFER;
$sharingMode=TransportSharing::HANDLER_PREFER;
}
}
if(\array_key_exists('handle_factory',$options)&&$options['handle_factory']!==null){
$this->shareHandleState=null;
$this->factory=$options['handle_factory'];
$this->ownsFactory=false;
}else{
$this->shareHandleState=$sharingMode!==TransportSharing::NONE
?CurlShareHandleState::fromOption($transportSharing):null;
$this->factory=$this->shareHandleState!==null
?new CurlFactory(50,$this->shareHandleState->mode,$this->shareHandleState):new CurlFactory(50);
$this->ownsFactory=true;
}
}
function __destruct(){
try{
$this->doClose(false);
}catch(\Throwable$e){
}
}
function __unserialize(array$data):void
{
$this->closed=true;
throw new\LogicException(static::class.' should never be unserialized');
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$this->assertOpen();
HostValidator::assertRequestHost($request);
$easy=$this->factory->create($request,$options);
try{
$this->rejectDisabledMultiplexConflict($easy,$options);
$this->applyMultiplexNone($easy,$options);
$this->applyProxyTunnelOwnership($easy);
}catch(\Throwable$e){
try{
$this->factory->release($easy);
}catch(\Throwable$releaseFailure){
}
throw$e;
}
$id=(int)$easy->handle;
$waitToken=new\stdClass;
$promise=null;
$promise=new Promise(function()use($id,$waitToken,$easy,&$promise):void{
$stalled=$this->multiExecDepth>0
?$this->failNestedWait($id,$waitToken):$this->executeUntil($id,$waitToken);
P\Utils::queue()->run();
if($easy->deferredSettled||!P\State::isPending($promise)){
return;
}
$message=\sprintf('Waiting on cURL multi handler transfer %d cannot make progress (%s).',$id,$stalled);
$response=$easy->response;
$failure=$response!==null
?new ResponseException($message,$easy->request,$response):new RequestException($message,$easy->request);
$promise->reject($failure);
},function()use($id,$waitToken):void{
$this->cancel($id,$waitToken);
}
);
$entry=['easy'=>$easy,'deferred'=>$promise,'wait_token'=>$waitToken];
try{
$this->addRequest($entry);
}catch(\Throwable$e){
throw$this->discardPendingRequest($id,$entry,$e);
}
return$promise;
}
private function rejectDisabledMultiplexConflict(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array$options
):void{
if(!$this->multiplexDisabled){
return;
}
$multiplex=$options['multiplex']??null;
if(Multiplexing::WAIT===$multiplex&&!$easy->usesPipewait){
return;
}
if(!\in_array($multiplex,[Multiplexing::WAIT,Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
return;
}
throw new InvalidArgumentException('The "multiplex" request option cannot be combined with a CurlMultiHandler whose "multiplex" option is Multiplexing::NONE; remove the handler option or set the request option to "eager".');
}
private function applyMultiplexNone(#[\SensitiveParameter]EasyHandle$easy,#[\SensitiveParameter]array$options
):void{
if(Multiplexing::NONE!==($options['multiplex']??null)||$this->multiplexDisabled){
return;
}
if(!$this->ownsFactory){
throw new InvalidArgumentException('The "multiplex" request option can only be Multiplexing::NONE on a CurlMultiHandler with a custom "handle_factory" when the handler\'s own "multiplex" option is Multiplexing::NONE, because the guarantee is enforced against the native easy handle the factory controls.');
}
$version=$easy->request->getProtocolVersion();
if('1.0'!==$version&&'1.1'!==$version){
throw new InvalidArgumentException('The "multiplex" request option can only be Multiplexing::NONE for an HTTP/1.x request on a CurlMultiHandler that permits multiplexing; set the "multiplex" client or CurlMultiHandler constructor option to Multiplexing::NONE to disable multiplexing for every transfer, or send the request with its "version" option set to "1.1".');
}
if(null!==$this->shareHandleState&&TransportSharing::PERSISTENT_REQUIRE===$this->shareHandleState->mode){
throw new InvalidArgumentException('The "multiplex" request option cannot be Multiplexing::NONE on a CurlMultiHandler that permits multiplexing and requires persistent transport sharing; set the "multiplex" client or CurlMultiHandler constructor option to Multiplexing::NONE, or use TransportSharing::PERSISTENT_PREFER.');
}
if(\defined('CURLOPT_HTTPAUTH')&&isset($options['curl'])&&\is_array($options['curl'])&&\array_key_exists((int)\constant('CURLOPT_HTTPAUTH'),$options['curl'])){
throw new InvalidArgumentException('The "multiplex" request option cannot be Multiplexing::NONE combined with the raw CURLOPT_HTTPAUTH cURL option on a CurlMultiHandler that permits multiplexing; remove the raw option, or set the "multiplex" client or CurlMultiHandler constructor option to Multiplexing::NONE.');
}
if(Psr7\Utils::caselessContains($easy->request->getHeaderLine('Expect'),'100-continue')){
throw new InvalidArgumentException('The "multiplex" request option cannot be Multiplexing::NONE for a request carrying an "Expect: 100-continue" header on a CurlMultiHandler that permits multiplexing; remove the explicitly supplied "Expect" header, set the "expect" request option to false to prevent it being added automatically, or set the "multiplex" client or CurlMultiHandler constructor option to Multiplexing::NONE.');
}
if(CurlVersion::supportsHttpVersionReuseMatching()){
return;
}
if(true!==curl_setopt($easy->handle,\CURLOPT_FRESH_CONNECT,true)){
throw new InvalidArgumentException('Unable to set cURL option CURLOPT_FRESH_CONNECT.');
}
}
private static function rejectConflictingCurlMultiOptions(array$options):void
{
if($options===[]){
return;
}
$conflictingOptions=self::conflictingCurlMultiOptions();
foreach($options as$option=>$_){
if(\array_key_exists($option,$conflictingOptions)){
throw new InvalidArgumentException(\sprintf('Passing %s in the cURL multi handler "options" is not supported. Use %s instead.',self::formatCurlMultiOption($option),$conflictingOptions[$option]));
}
}
}
private static function firstConnectionCapOption(array$options):?string
{
foreach(self::CONNECTION_CAP_OPTIONS as$name=>$_){
if(($options[$name]??null)!==null){
return$name;
}
}
return;
}
private function addConnectionCapOptions(array$options):void
{
foreach(self::CONNECTION_CAP_OPTIONS as$name=>$constant){
$value=$options[$name]??null;
if($value===null){
continue;
}
if(!\is_int($value)||$value<1){
throw new InvalidArgumentException(\sprintf('%s must be a positive integer.',$name));
}
if(!\defined($constant)){
throw new InvalidArgumentException(\sprintf('%s requires %s, but it is not available in the installed PHP cURL extension.',$name,$constant));
}
$option=\constant($constant);
if(\array_key_exists($option,$this->options)){
throw new InvalidArgumentException(\sprintf('%s conflicts with a %s entry in the "options" array.',$name,$constant));
}
$this->options[$option]=$value;
}
}
private static function formatCurlMultiOption($option):string
{
if(!\is_int($option)){
return\sprintf('"%s"',Psr7\DiagnosticValue::escape((string)$option));
}
static$names=null;
if(null===$names){
$names=[];
foreach(\get_defined_constants(true)['curl']??[]as$name=>$value){
if(\is_int($value)&&\strpos($name,'CURLMOPT_')===0&&!isset($names[$value])){
$names[$value]=$name;
}
}
}
if(isset($names[$option])){
return\sprintf('%s (%d)',$names[$option],$option);
}
return(string)$option;
}
private static function conflictingCurlMultiOptions():array
{
static$options=null;
if($options!==null){
return$options;
}
$options=[];
self::addConflictingCurlMultiOption($options,'CURLMOPT_MAX_HOST_CONNECTIONS','the "max_host_connections" client option or cURL multi handler option');
self::addConflictingCurlMultiOption($options,'CURLMOPT_MAX_TOTAL_CONNECTIONS','the "max_total_connections" client option or cURL multi handler option');
self::addConflictingCurlMultiOption($options,'CURLMOPT_PIPELINING','Multiplexing::NONE via the "multiplex" cURL multi handler or client option to disable multiplexing, or remove the raw option for the runtime default (multiplexing defaults on from libcurl 7.62, except 7.65.0 and 7.65.1)');
return$options;
}
private static function addConflictingCurlMultiOption(array&$options,string$constant,string$replacement):void
{
if(!\defined($constant)){
return;
}
$value=\constant($constant);
if(\is_int($value)){
$options[$value]=$replacement;
}
}
private function applyProxyTunnelOwnership(#[\SensitiveParameter]EasyHandle$easy
):void{
$signature=$easy->proxyTunnelSignature;
if($signature===null||$signature===$this->proxyTunnelOwner){
return;
}
if($this->proxyTunnelOwner===null){
$this->proxyTunnelOwner=$signature;
return;
}
if($this->handles===[]&&0===$this->multiExecDepth
&&0===$this->messageProcessingDepth
&&$this->deferredCancels===[]&&!$this->deferredClose
){
if($this->multiHandle!==null){
\curl_multi_close($this->multiHandle);
$this->multiHandle=null;
}
$this->proxyTunnelOwner=$signature;
return;
}
$this->isolateProxyTunnelTransfer($easy);
}
private function addHandleToMulti(int$id,#[\SensitiveParameter]EasyHandle$easy
):void{
$this->isolateFromForeignActiveProxyTunnel($easy);
$multiHandle=$this->getMultiHandle();
$result=curl_multi_add_handle($multiHandle,$easy->handle);
if(\CURLM_OK!==$result){
if(\PHP_VERSION_ID<80226||(\PHP_VERSION_ID>=80300&&\PHP_VERSION_ID<80314)){
\curl_multi_remove_handle($multiHandle,$easy->handle);
}
throw new RequestException(\sprintf('Unable to add the cURL handle to the cURL multi handler: %s (%d).',(string)\curl_multi_strerror($result),$result),$easy->request);
}
$this->markProxyTunnelActive($id,$easy);
if(isset($this->handles[$id])){
$this->handles[$id]['attached']=true;
}
}
private function isolateFromForeignActiveProxyTunnel(#[\SensitiveParameter]EasyHandle$easy
):void{
$signature=$easy->proxyTunnelSignature;
if($signature===null||$this->activeProxyTunnelSignatures===[]){
return;
}
if(\count($this->activeProxyTunnelSignatures)===1&&isset($this->activeProxyTunnelSignatures[$signature])){
return;
}
$this->isolateProxyTunnelTransfer($easy);
}
private function isolateProxyTunnelTransfer(#[\SensitiveParameter]EasyHandle$easy
):void{
foreach(self::PROXY_TUNNEL_ISOLATION_OPTIONS as$name){
try{
$applied=curl_setopt($easy->handle,(int)\constant($name),true);
}catch(\Throwable$e){
throw new RequestException(self::proxyTunnelIsolationFailureMessage($name),$easy->request,0,$e);
}
if(true!==$applied){
throw new RequestException(self::proxyTunnelIsolationFailureMessage($name),$easy->request);
}
}
}
private static function proxyTunnelIsolationFailureMessage(string$name):string
{
return\sprintf('Unable to apply the %s cURL option required to isolate the transfer from foreign proxy tunnel connections.',$name);
}
private function markProxyTunnelActive(int$id,EasyHandle$easy):void
{
$signature=$easy->proxyTunnelSignature;
if($signature===null){
return;
}
if(isset($this->activeProxyTunnelHandles[$id])){
if($this->activeProxyTunnelHandles[$id]===$signature){
return;
}
$this->unmarkProxyTunnelActiveById($id);
}
$this->activeProxyTunnelHandles[$id]=$signature;
$this->activeProxyTunnelSignatures[$signature]=($this->activeProxyTunnelSignatures[$signature]??0)+1;
}
private function unmarkProxyTunnelActiveById(int$id):void
{
if(!isset($this->activeProxyTunnelHandles[$id])){
return;
}
$signature=$this->activeProxyTunnelHandles[$id];
unset($this->activeProxyTunnelHandles[$id]);
if(!isset($this->activeProxyTunnelSignatures[$signature])){
return;
}
--$this->activeProxyTunnelSignatures[$signature];
if($this->activeProxyTunnelSignatures[$signature]<=0){
unset($this->activeProxyTunnelSignatures[$signature]);
}
}
function tick():void
{
$this->tickFor(null,null);
}
private function tickFor(?int$targetId,?object$waitToken):void
{
$this->assertOpen();
if($this->delays&&0===$this->multiExecDepth){
$currentTime=Clock::now();
foreach($this->delays as$id=>$delay){
if($currentTime>=$delay){
$entry=$this->handles[$id];
unset($this->delays[$id]);
try{
$this->addHandleToMulti($id,$entry['easy']);
}catch(\Throwable$e){
$rejection=$this->discardPendingRequest($id,$entry,$e);
if(P\State::isPending($entry['deferred'])){
$entry['deferred']->reject($rejection);
}
}
}
}
}
do{
P\Utils::queue()->add(Closure::fromCallable([$this,'tickInQueue']));
P\Utils::queue()->run();
if($this->multiExecDepth>0){
return;
}
if($this->closed||$this->closing||!$this->hasMultiHandle()){
return;
}
$this->processMessages();
if($this->closed||$this->closing||!$this->hasMultiHandle()){
return;
}
}while(!P\Utils::queue()->isEmpty());
if($targetId!==null&&!$this->hasRequest($targetId,$waitToken)){
return;
}
if($this->active&&\curl_multi_select($this->getMultiHandle(),$this->effectiveSelectTimeout())===-1){
\usleep(250);
}
do{
$exec=$this->executeMulti();
if($this->closed||$this->closing||!$this->hasMultiHandle()){
return;
}
if($exec===\CURLM_CALL_MULTI_PERFORM){
\curl_multi_select($this->getMultiHandle(),$this->effectiveSelectTimeout());
}
}while($exec===\CURLM_CALL_MULTI_PERFORM);
$this->processMessages();
}
private function tickInQueue():void
{
if($this->multiExecDepth>0){
return;
}
if($this->closed||$this->closing||!$this->hasMultiHandle()){
return;
}
$exec=$this->executeMulti();
if($this->closed||$this->closing||!$this->hasMultiHandle()){
return;
}
if($exec===\CURLM_CALL_MULTI_PERFORM){
\curl_multi_select($this->getMultiHandle(),0);
P\Utils::queue()->add(Closure::fromCallable([$this,'tickInQueue']));
}
}
function execute():void
{
$this->assertOpen();
if($this->multiExecDepth>0){
throw new\LogicException('Cannot run the cURL multi event loop from inside a cURL callback; the callback must return before transfers can progress.');
}
$queue=P\Utils::queue();
while(!$this->closed&&!$this->closing&&($this->handles||!$queue->isEmpty())){
if(!$this->active&&$this->delays&&$queue->isEmpty()){
Clock::sleep($this->timeToNext());
}
$this->tick();
}
}
private function executeUntil(int$id,object$waitToken):string
{
$this->assertOpen();
$queue=P\Utils::queue();
while(!$this->closed
&&!$this->closing
&&$this->hasRequest($id,$waitToken)){
if(!$this->active&&isset($this->delays[$id])&&$queue->isEmpty()){
Clock::sleep($this->timeToNext());
}
$this->tickFor($id,$waitToken);
}
$stalled=$this->describeStalledWait($id,$waitToken);
if(!$this->closed&&!$this->closing&&!$queue->isEmpty()){
$queue->run();
}
return$stalled;
}
private function describeStalledWait(int$id,object$waitToken):string
{
if($this->hasRequest($id,$waitToken)){
return'the handler stopped driving it while it was still tracked';
}
return isset($this->handles[$id])?'its native cURL handle ID was reused by another request':'its entry was removed without settling';
}
private function hasRequest(int$id,?object$waitToken=null):bool
{
if(!isset($this->handles[$id])){
return false;
}
return$waitToken===null||($this->handles[$id]['wait_token']??null)===$waitToken;
}
function close():void
{
$this->doClose(true);
}
private function assertOpen():void
{
if($this->closed||$this->closing){
throw new\BadMethodCallException('Cannot use the cURL multi handler after it has been closed.');
}
}
private function doClose(bool$explicit):void
{
if($this->closed||$this->closing){
return;
}
$this->closing=true;
$failure=null;
if($this->multiExecDepth>0||$this->messageProcessingDepth>0){
$this->deferClose($explicit,$failure);
if($explicit&&$failure!==null){
throw$failure;
}
return;
}
try{
$this->cleanupPendingTransfers($explicit,$failure);
$this->closeMultiHandle($failure);
$this->closeOwnedFactory($failure);
}finally{
$this->finishClose();
}
if($explicit&&$failure!==null){
throw$failure;
}
}
private function deferClose(bool$explicit,?\Throwable&$failure):void
{
$this->deferredClose=true;
$this->deferredCloseExplicit=$this->deferredCloseExplicit||$explicit;
$entries=$this->handles;
$this->handles=[];
$this->delays=[];
$this->deferredAdds=[];
foreach($entries as$id=>$entry){
$this->deferredCancels[$id]=['easy'=>$entry['easy'],'attached'=>!empty($entry['attached']),];
if($explicit&&P\State::isPending($entry['deferred'])){
$this->captureFailure($failure,function()use($entry):void{
$entry['deferred']->reject(new HandlerClosedException('The cURL multi handler was closed before the transfer completed.',$entry['easy']->request));
});
}
}
}
private function finishClose():void
{
$this->handles=[];
$this->delays=[];
$this->deferredCancels=[];
$this->deferredAdds=[];
$this->activeProxyTunnelSignatures=[];
$this->activeProxyTunnelHandles=[];
$this->active=0;
$this->shareHandleState=null;
$this->deferredClose=false;
$this->deferredCloseExplicit=false;
$this->closed=true;
$this->closing=false;
}
private function captureFailure(?\Throwable&$failure,callable$callback):void
{
try{
$callback();
}catch(\Throwable$e){
if($failure===null){
$failure=$e;
}
}
}
private function discardPendingRequest(int$id,array$entry,\Throwable$failure):\Throwable
{
unset($this->handles[$id],$this->delays[$id],$this->deferredAdds[$id]);
try{
$this->disposeEasyHandle($entry['easy']);
}catch(\Throwable$e){
}
return$failure;
}
private function cleanupPendingTransfers(bool$reject,?\Throwable&$failure):void
{
$entries=$this->handles;
$this->handles=[];
$this->delays=[];
$this->deferredAdds=[];
foreach($entries as$id=>$entry){
$easy=$entry['easy'];
$attached=!empty($entry['attached']);
if($attached&&$this->hasMultiHandle()&&self::hasEasyHandle($easy)){
$this->captureFailure($failure,function()use($id,$easy):void{
$this->removeHandleFromMulti($id,$easy->handle);
});
}
if($reject&&P\State::isPending($entry['deferred'])){
$this->captureFailure($failure,function()use($entry):void{
$entry['deferred']->reject(new HandlerClosedException('The cURL multi handler was closed before the transfer completed.',$entry['easy']->request));
});
}
$this->captureFailure($failure,function()use($easy):void{
$this->disposeEasyHandle($easy);
});
}
}
private function closeMultiHandle(?\Throwable&$failure):void
{
if($this->multiHandle===null){
return;
}
$multiHandle=$this->multiHandle;
$this->captureFailure($failure,function()use($multiHandle):void{
try{
\curl_multi_close($multiHandle);
}finally{
$this->multiHandle=null;
}
});
}
private function closeOwnedFactory(?\Throwable&$failure):void
{
$factory=$this->factory;
if(!$this->ownsFactory||!$factory instanceof CurlFactory){
return;
}
$this->captureFailure($failure,static function()use($factory):void{
$factory->close();
});
}
private function executeMulti():int
{
++$this->multiExecDepth;
try{
return\curl_multi_exec($this->getMultiHandle(),$this->active);
}finally{
--$this->multiExecDepth;
$this->finishDeferredWork();
}
}
private function finishDeferredWork():void
{
if($this->multiExecDepth>0||$this->finishingDeferredWork){
return;
}
$this->finishingDeferredWork=true;
try{
if(!$this->closed&&!$this->closing){
$this->flushDeferredAdds();
}
if($this->messageProcessingDepth>0){
return;
}
$failure=null;
do{
$this->cleanupDeferredCancels($failure);
if(!$this->closed&&!$this->closing){
$this->flushDeferredAdds();
}
}while($this->deferredCancels!==[]||(!$this->closed&&!$this->closing&&$this->deferredAdds!==[]));
if($this->deferredClose){
$explicit=$this->deferredCloseExplicit;
try{
$this->closeMultiHandle($failure);
$this->closeOwnedFactory($failure);
}finally{
$this->finishClose();
}
if($explicit&&$failure!==null){
throw$failure;
}
return;
}
if($failure!==null){
throw$failure;
}
}finally{
$this->finishingDeferredWork=false;
}
}
private function flushDeferredAdds():void
{
if($this->deferredAdds===[]){
return;
}
$adds=$this->deferredAdds;
$this->deferredAdds=[];
foreach($adds as$id=>$token){
if(!$this->hasRequest($id,$token)){
continue;
}
$entry=$this->handles[$id];
try{
$this->addHandleToMulti($id,$entry['easy']);
}catch(\Throwable$e){
$rejection=$this->discardPendingRequest($id,$entry,$e);
if(P\State::isPending($entry['deferred'])){
$entry['deferred']->reject($rejection);
}
}
}
}
private function failNestedWait(int$id,object$token):string
{
$stalled=$this->describeStalledWait($id,$token);
if(!$this->hasRequest($id,$token)){
return$stalled;
}
$entry=$this->handles[$id];
$message='Cannot synchronously wait for a transfer from inside a cURL callback on the same cURL multi handler; the callback must return before the transfer can progress.';
$response=$entry['easy']->response;
$failure=$response!==null
?new ResponseException($message,$entry['easy']->request,$response):new RequestException($message,$entry['easy']->request);
if(!empty($entry['attached'])){
unset($this->handles[$id],$this->delays[$id],$this->deferredAdds[$id]);
$this->deferredCancels[$id]=['easy'=>$entry['easy'],'attached'=>true];
}else{
$this->discardPendingRequest($id,$entry,$failure);
}
$entry['deferred']->reject($failure);
return$stalled;
}
private function disposeEasyHandle(#[\SensitiveParameter]EasyHandle$easy
):void{
if(!self::hasEasyHandle($easy)){
return;
}
$handle=$easy->handle;
unset($easy->handle);
$failure=null;
try{
$this->clearEasyHandleCallbacks($handle);
}catch(\Throwable$e){
$failure=$e;
}
try{
if(PHP_VERSION_ID<80000&&\is_resource($handle)){
\curl_close($handle);
}
}catch(\Throwable$e){
if($failure===null){
$failure=$e;
}
}
if($failure!==null){
throw$failure;
}
}
private function clearEasyHandleCallbacks(#[\SensitiveParameter]$handle
):void{
curl_setopt($handle,\CURLOPT_HEADERFUNCTION,null);
curl_setopt($handle,\CURLOPT_READFUNCTION,null);
curl_setopt($handle,\CURLOPT_WRITEFUNCTION,null);
curl_setopt($handle,\CURLOPT_PROGRESSFUNCTION,null);
if(\defined('CURLOPT_PREREQFUNCTION')){
curl_setopt($handle,(int)\constant('CURLOPT_PREREQFUNCTION'),null);
}
if(\defined('CURLOPT_SEEKFUNCTION')){
curl_setopt($handle,(int)\constant('CURLOPT_SEEKFUNCTION'),null);
}
if(\defined('CURLOPT_XFERINFOFUNCTION')){
curl_setopt($handle,(int)\constant('CURLOPT_XFERINFOFUNCTION'),null);
}
}
private function removeHandleFromMulti(int$id,#[\SensitiveParameter]$handle
):void{
++$this->multiExecDepth;
try{
\curl_multi_remove_handle($this->getMultiHandle(),$handle);
}finally{
--$this->multiExecDepth;
$this->unmarkProxyTunnelActiveById($id);
$this->finishDeferredWork();
}
}
private function hasMultiHandle():bool
{
return$this->multiHandle!==null;
}
private static function hasEasyHandle(EasyHandle$easy):bool
{
return\array_key_exists('handle',\get_object_vars($easy));
}
private function addRequest(#[\SensitiveParameter]array$entry
):void{
$easy=$entry['easy'];
$id=(int)$easy->handle;
$entry['attached']=false;
$displaced=$this->handles[$id]??null;
if($displaced!==null){
unset($this->handles[$id],$this->delays[$id],$this->deferredAdds[$id]);
if(P\State::isPending($displaced['deferred'])){
$message=\sprintf('cURL multi handler transfer %d was displaced by another request that reused its native cURL handle ID.',$id);
$response=$displaced['easy']->response;
$failure=$response!==null
?new ResponseException($message,$displaced['easy']->request,$response):new RequestException($message,$displaced['easy']->request);
$displaced['deferred']->reject($failure);
}
}
$this->handles[$id]=$entry;
if(!empty($easy->options['delay'])){
$this->delays[$id]=Clock::now()+($easy->options['delay']/1000);
}elseif($this->multiExecDepth>0){
$this->deferredAdds[$id]=$entry['wait_token']??null;
}else{
$this->addHandleToMulti($id,$easy);
}
}
private function cancel(int$id,?object$waitToken=null):bool
{
if(!$this->hasRequest($id,$waitToken)){
return false;
}
$entry=$this->handles[$id];
$easy=$entry['easy'];
$attached=!empty($entry['attached']);
unset($this->delays[$id],$this->deferredAdds[$id],$this->handles[$id]);
if($this->multiExecDepth>0){
$this->deferredCancels[$id]=['easy'=>$easy,'attached'=>$attached];
return true;
}
$failure=null;
if($attached&&$this->hasMultiHandle()&&self::hasEasyHandle($easy)){
$this->captureFailure($failure,function()use($id,$easy):void{
$this->removeHandleFromMulti($id,$easy->handle);
});
}
$this->captureFailure($failure,function()use($easy):void{
$this->disposeEasyHandle($easy);
});
if($failure!==null){
throw$failure;
}
return true;
}
private function cleanupDeferredCancels(?\Throwable&$failure):void
{
if($this->deferredCancels===[]){
return;
}
$entries=$this->deferredCancels;
$this->deferredCancels=[];
foreach($entries as$id=>$entry){
$easy=$entry['easy'];
if($entry['attached']&&$this->hasMultiHandle()&&self::hasEasyHandle($easy)){
$this->captureFailure($failure,function()use($id,$easy):void{
$this->removeHandleFromMulti($id,$easy->handle);
});
}
$this->captureFailure($failure,function()use($easy):void{
$this->disposeEasyHandle($easy);
});
}
}
private function processMessages():void
{
++$this->messageProcessingDepth;
try{
while(!$this->closed&&!$this->closing){
$done=\curl_multi_info_read($this->getMultiHandle());
if(false===$done){
break;
}
if($done['msg']!==\CURLMSG_DONE){
continue;
}
if(!isset($done['handle'])){
continue;
}
$id=(int)$done['handle'];
$this->removeHandleFromMulti($id,$done['handle']);
if(!isset($this->handles[$id])){
continue;
}
$entry=$this->handles[$id];
unset($this->handles[$id],$this->delays[$id]);
$entry['easy']->errno=$done['result'];
try{
$result=CurlFactory::finish($this,$entry['easy'],$this->factory);
}catch(\Throwable$e){
if(P\State::isPending($entry['deferred'])){
$entry['easy']->deferredSettled=true;
$entry['deferred']->reject($e);
}
continue;
}
if(P\State::isPending($entry['deferred'])){
$entry['easy']->deferredSettled=true;
$entry['deferred']->resolve($result);
}
}
}finally{
--$this->messageProcessingDepth;
$this->finishDeferredWork();
}
}
private function effectiveSelectTimeout():float
{
if($this->delays===[]){
return$this->selectTimeout;
}
return\min($this->selectTimeout,$this->secondsToNext());
}
private function secondsToNext():float
{
$currentTime=Clock::now();
$nextTime=\PHP_FLOAT_MAX;
foreach($this->delays as$time){
if($time<$nextTime){
$nextTime=$time;
}
}
return\max(0.0,$nextTime-$currentTime);
}
private function timeToNext():int
{
return(int)\min(\PHP_INT_MAX,$this->secondsToNext()*1000000);
}
private function getMultiHandle(){
if($this->multiHandle!==null){
return$this->multiHandle;
}
$this->assertOpen();
$multiHandle=\curl_multi_init();
if(false===$multiHandle){
throw new\RuntimeException('Can not initialize curl multi handle.');
}
try{
foreach($this->options as$option=>$value){
if(!\is_int($option)){
throw new InvalidArgumentException(\sprintf('Invalid cURL multi option "%s".',Psr7\DiagnosticValue::escape((string)$option)));
}
try{
$applied=@curl_multi_setopt($multiHandle,$option,$value);
}catch(\Throwable$e){
throw new InvalidArgumentException(\sprintf('Unable to apply the cURL multi option %s; it was rejected by the runtime libcurl.',self::formatCurlMultiOption($option)),0,$e
);
}
if(true!==$applied){
throw new InvalidArgumentException(\sprintf('Unable to apply the cURL multi option %s; it was rejected by the runtime libcurl.',self::formatCurlMultiOption($option)));
}
}
}catch(\Throwable$e){
\curl_multi_close($multiHandle);
throw$e;
}
$this->multiHandle=$multiHandle;
return$this->multiHandle;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\TransportSharing;
final class CurlShareHandleState
{
use NonSerializableTrait;
var$handle;
string$mode;
private function __construct(string$mode,$handle){
$this->mode=$mode;
$this->handle=$handle;
}
static function fromOption($sharing):?self
{
if($sharing instanceof self){
return$sharing;
}
$mode=self::normalizeMode($sharing,'transport_sharing');
if($mode===TransportSharing::NONE){
return;
}
if($mode===TransportSharing::HANDLER_PREFER){
return self::createHandlerShareOrNull($mode);
}
if($mode===TransportSharing::HANDLER_REQUIRE){
return self::createHandlerShare($mode);
}
if($mode===TransportSharing::PERSISTENT_PREFER){
return self::createPersistentShareOrFallback();
}
return self::createPersistentShare($mode);
}
static function normalizeMode($sharing,string$option):string
{
if($sharing instanceof self){
return$sharing->mode;
}
if($sharing===null||$sharing===TransportSharing::NONE){
return TransportSharing::NONE;
}
if($sharing===TransportSharing::HANDLER_PREFER
||$sharing===TransportSharing::HANDLER_REQUIRE
||$sharing===TransportSharing::PERSISTENT_PREFER
||$sharing===TransportSharing::PERSISTENT_REQUIRE
){
return$sharing;
}
throw new InvalidArgumentException(\sprintf('The "%s" option must be null or a GuzzleHttp\\TransportSharing::* constant; received %s.',$option,\get_debug_type($sharing)));
}
static function assertNoRequiredSharingCustomFactoryConflict(array$options,string$handlerName):void
{
if(!\array_key_exists('handle_factory',$options)||$options['handle_factory']===null){
return;
}
$mode=self::normalizeMode($options['transport_sharing']??null,'transport_sharing');
if(!\in_array($mode,[TransportSharing::HANDLER_REQUIRE,TransportSharing::PERSISTENT_REQUIRE],true)){
return;
}
throw new InvalidArgumentException(\sprintf('The "transport_sharing" %s option cannot require sharing with a custom "handle_factory" because Guzzle cannot ensure that the custom factory applies CURLOPT_SHARE.',$handlerName
));
}
static function supportsHandlerRequireShare():bool
{
return CurlVersion::supportsHandlerSharing()&&CurlVersion::supportsSslSessionSharing()&&\function_exists('curl_share_init')&&\function_exists('curl_share_setopt')&&\defined('CURLOPT_SHARE')&&\defined('CURLSHOPT_SHARE')&&\defined('CURL_LOCK_DATA_DNS')&&\defined('CURL_LOCK_DATA_SSL_SESSION');
}
private static function createHandlerShareOrNull(string$mode):?self
{
try{
return self::createHandlerShare($mode);
}catch(\Throwable$e){
return;
}
}
private static function createHandlerShare(string$mode):self
{
if(!\function_exists('curl_share_init')||!\function_exists('curl_share_setopt')){
throw new InvalidArgumentException('The "transport_sharing" option requires cURL share support.');
}
self::requireCurlConstant('CURLOPT_SHARE');
$shareOption=self::requireCurlConstant('CURLSHOPT_SHARE');
$locks=self::handlerLocks($mode);
$handle=curl_share_init();
try{
foreach($locks as$lock){
try{
$success=curl_share_setopt($handle,$shareOption,$lock);
}catch(\Throwable$e){
throw new InvalidArgumentException('Unable to configure cURL share handle: '.$e->getMessage(),0,$e);
}
if(!$success){
throw new InvalidArgumentException(\sprintf('Unable to configure cURL share handle with lock data %d.',$lock));
}
}
}catch(\Throwable$e){
self::closeHandlerShareHandleOnPhp7($handle);
throw$e;
}
return new self($mode,$handle);
}
private static function createPersistentShareOrFallback():?self
{
if(self::supportsPersistentShare()){
try{
return self::createPersistentShare(TransportSharing::PERSISTENT_PREFER);
}catch(\Throwable$e){
}
}
return self::createHandlerShareOrNull(TransportSharing::HANDLER_PREFER);
}
private static function createPersistentShare(string$mode):self
{
CurlVersion::ensureConnectionSharingSupported();
CurlVersion::ensureSslSessionSharingSupported();
if(!self::supportsPersistentShare()){
throw new InvalidArgumentException('The "transport_sharing" option requires persistent cURL share handle support.');
}
self::requireCurlConstant('CURLOPT_SHARE');
try{
$handle=curl_share_init_persistent(self::persistentLocks());
}catch(\Throwable$e){
throw new InvalidArgumentException('Unable to create persistent cURL share handle: '.$e->getMessage(),0,$e
);
}
return new self($mode,$handle);
}
private static function supportsPersistentShare():bool
{
return CurlVersion::supportsConnectionSharing()&&CurlVersion::supportsSslSessionSharing()&&\function_exists('curl_share_init_persistent')&&\class_exists('CurlSharePersistentHandle')&&\defined('CURL_LOCK_DATA_DNS')&&\defined('CURL_LOCK_DATA_CONNECT')&&\defined('CURL_LOCK_DATA_SSL_SESSION');
}
private static function handlerLocks(string$mode):array
{
CurlVersion::ensureHandlerSharingSupported();
if($mode===TransportSharing::HANDLER_REQUIRE){
CurlVersion::ensureSslSessionSharingSupported();
}
$locks=[self::requireCurlConstant('CURL_LOCK_DATA_DNS'),];
if(CurlVersion::supportsSslSessionSharing()){
$locks[]=self::requireCurlConstant('CURL_LOCK_DATA_SSL_SESSION');
}
return$locks;
}
private static function persistentLocks():array
{
return[self::requireCurlConstant('CURL_LOCK_DATA_DNS'),self::requireCurlConstant('CURL_LOCK_DATA_CONNECT'),self::requireCurlConstant('CURL_LOCK_DATA_SSL_SESSION'),];
}
private static function requireCurlConstant(string$constant):int
{
if(!\defined($constant)){
throw new InvalidArgumentException(\sprintf('The "transport_sharing" option requires %s, but it is not available in the installed PHP cURL extension.',$constant
));
}
$value=\constant($constant);
if(!\is_int($value)){
throw new InvalidArgumentException(\sprintf('The cURL constant %s must resolve to an integer.',$constant));
}
return$value;
}
private static function closeHandlerShareHandleOnPhp7($handle):void
{
if(\PHP_VERSION_ID<80000&&\is_resource($handle)){
curl_share_close($handle);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
final class CurlVersion
{
private const MIN_VERSION='7.34.0';
private const TLS_13_VERSION='7.52.0';
private const MULTIPLEX_VERSION='7.65.2';
private const HTTP_VERSION_REUSE_MATCH_VERSION='7.77.0';
private const HTTP_VERSION_REUSE_MATCH_REGRESSION='8.11.0';
private const HTTP_VERSION_REUSE_MATCH_RESTORED='8.13.0';
private const REQUIRED_HTTP2_MULTIPLEX_VERSION='8.14.0';
private const REQUIRED_HTTP3_MULTIPLEX_VERSION='8.13.0';
private const HTTPS_PROXY_VERSION='7.54.0';
private const HTTP_3_VERSION='7.88.0';
private const PROTOCOLS_STR_VERSION='7.85.0';
private const HANDLER_SHARING_VERSION='7.35.0';
private const SSL_SESSION_SHARING_VERSION='8.6.0';
private const CONNECTION_SHARING_VERSION='8.12.0';
private const SHARE_CONNECTION_CACHE_VERSION='7.57.0';
const SHARED_POOL_CONNECTION_CAP_VERSION='8.22.0';
private const PROXY_TLS_CREDENTIAL_REUSE_VERSION='7.83.1';
private const PROXY_CREDENTIAL_REUSE_VERSION='8.20.0';
private const SOCKS_PROXY_CREDENTIAL_REUSE_VERSION='7.69.0';
private const PROXY_HEADER_SEPARATION_VERSION='7.37.0';
private const PROXY_TUNNEL_VERSION='7.54.0';
private static$versionInfo;
private function __construct(){
}
static function supportsCurlHandler():bool
{
$versionInfo=self::getVersionInfo();
return\defined('CURL_VERSION_SSL')&&\defined('CURL_SSLVERSION_TLSv1_2')&&\defined('CURLMOPT_MAX_HOST_CONNECTIONS')&&\defined('CURLMOPT_MAX_TOTAL_CONNECTIONS')&&null!==$versionInfo
&&version_compare($versionInfo['version'],self::MIN_VERSION,'>=')&&0!==(\CURL_VERSION_SSL&$versionInfo['features']);
}
static function supportsTls13():bool
{
$version=self::get();
return\defined('CURL_SSLVERSION_TLSv1_3')&&null!==$version
&&version_compare($version,self::TLS_13_VERSION,'>=');
}
static function supportsMultiplex():bool
{
$version=self::get();
return\defined('CURLOPT_PIPEWAIT')&&null!==$version
&&version_compare($version,self::MULTIPLEX_VERSION,'>=');
}
static function supportsHttpVersionReuseMatching():bool
{
$version=self::get();
if(null===$version||version_compare($version,self::HTTP_VERSION_REUSE_MATCH_VERSION,'<')){
return false;
}
return version_compare($version,self::HTTP_VERSION_REUSE_MATCH_REGRESSION,'<')||version_compare($version,self::HTTP_VERSION_REUSE_MATCH_RESTORED,'>=');
}
static function supportsRequiredHttp2Multiplex():bool
{
$version=self::get();
return\defined('CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE')&&null!==$version
&&self::supportsHttp2()&&version_compare($version,self::REQUIRED_HTTP2_MULTIPLEX_VERSION,'>=');
}
static function supportsHttp2():bool
{
$versionInfo=self::getVersionInfo();
return\defined('CURL_VERSION_HTTP2')&&null!==$versionInfo
&&self::supportsMultiplex()&&0!==(\CURL_VERSION_HTTP2&$versionInfo['features']);
}
static function supportsHttp3():bool
{
if(!\defined('CURL_VERSION_HTTP3')||!\defined('CURL_HTTP_VERSION_3')||!\defined('CURL_HTTP_VERSION_3ONLY')){
return false;
}
$versionInfo=self::getVersionInfo();
if(null===$versionInfo||version_compare($versionInfo['version'],self::HTTP_3_VERSION,'<')){
return false;
}
return 0!==((int)\constant('CURL_VERSION_HTTP3')&$versionInfo['features']);
}
static function supportsRequiredHttp3Multiplex():bool
{
$version=self::get();
return self::supportsHttp3()&&null!==$version
&&version_compare($version,self::REQUIRED_HTTP3_MULTIPLEX_VERSION,'>=');
}
static function supportsHttpsProxy():bool
{
$versionInfo=self::getVersionInfo();
return\defined('CURL_VERSION_HTTPS_PROXY')&&null!==$versionInfo
&&version_compare($versionInfo['version'],self::HTTPS_PROXY_VERSION,'>=')&&0!==(\CURL_VERSION_HTTPS_PROXY&$versionInfo['features']);
}
static function supportsHandlerSharing():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::HANDLER_SHARING_VERSION,'>=');
}
static function ensureHandlerSharingSupported():void
{
if(!self::supportsHandlerSharing()){
throw new InvalidArgumentException(\sprintf('The "transport_sharing" option requires libcurl %s or higher for cURL share handles.',self::HANDLER_SHARING_VERSION
));
}
}
static function supportsSslSessionSharing():bool
{
$versionInfo=self::getVersionInfo();
return\defined('CURL_VERSION_SSL')&&null!==$versionInfo
&&version_compare($versionInfo['version'],self::SSL_SESSION_SHARING_VERSION,'>=')&&0!==(\CURL_VERSION_SSL&$versionInfo['features']);
}
static function ensureSslSessionSharingSupported():void
{
if(!self::supportsSslSessionSharing()){
throw new InvalidArgumentException(\sprintf('The "transport_sharing" option requires libcurl %s or higher with SSL support for SSL session sharing.',self::SSL_SESSION_SHARING_VERSION
));
}
}
static function supportsConnectionSharing():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::CONNECTION_SHARING_VERSION,'>=');
}
static function ensureConnectionSharingSupported():void
{
if(!self::supportsConnectionSharing()){
throw new InvalidArgumentException(\sprintf('The "transport_sharing" option requires libcurl %s or higher for persistent connection sharing.',self::CONNECTION_SHARING_VERSION
));
}
}
static function supportsSharedPoolConnectionCaps():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::SHARED_POOL_CONNECTION_CAP_VERSION,'>=');
}
static function supportsShareConnectionCaches():bool
{
$version=self::get();
return null===$version
||version_compare($version,self::SHARE_CONNECTION_CACHE_VERSION,'>=');
}
static function supportsProxyTlsCredentialAwareConnectionReuse():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::PROXY_TLS_CREDENTIAL_REUSE_VERSION,'>=');
}
static function supportsProxyCredentialAwareConnectionReuse():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::PROXY_CREDENTIAL_REUSE_VERSION,'>=');
}
static function supportsSocksProxyCredentialAwareConnectionReuse():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::SOCKS_PROXY_CREDENTIAL_REUSE_VERSION,'>=');
}
static function supportsProxyHeaderSeparation():bool
{
$version=self::get();
return null!==$version
&&version_compare($version,self::PROXY_HEADER_SEPARATION_VERSION,'>=')&&\defined('CURLOPT_PROXYHEADER')&&\defined('CURLOPT_HEADEROPT')&&\defined('CURLHEADER_SEPARATE');
}
static function supportsProtocolsStr():bool
{
$version=self::get();
return\defined('CURLOPT_PROTOCOLS_STR')&&null!==$version
&&version_compare($version,self::PROTOCOLS_STR_VERSION,'>=');
}
static function supportsProxyTunneling():bool
{
$version=self::get();
return\defined('CURLOPT_SUPPRESS_CONNECT_HEADERS')&&null!==$version
&&version_compare($version,self::PROXY_TUNNEL_VERSION,'>=');
}
static function ensureSupported(#[\SensitiveParameter]RequestInterface$request
):void{
if(self::supportsCurlHandler()){
return;
}
$version=self::get();
if(null===$version||version_compare($version,self::MIN_VERSION,'<')){
throw new ConnectException(\sprintf('cURL %s or higher is required by the cURL handler; %s is installed.',self::MIN_VERSION,$version??'an unknown version'),$request);
}
if(!\defined('CURL_SSLVERSION_TLSv1_2')){
throw new ConnectException(\sprintf('The PHP cURL extension must be built against cURL %s or higher to use the cURL handler.',self::MIN_VERSION
),$request);
}
if(!\defined('CURLMOPT_MAX_HOST_CONNECTIONS')||!\defined('CURLMOPT_MAX_TOTAL_CONNECTIONS')){
throw new ConnectException('The PHP cURL extension must expose CURLMOPT_MAX_HOST_CONNECTIONS and CURLMOPT_MAX_TOTAL_CONNECTIONS to use the cURL handler.',$request);
}
throw new ConnectException('The cURL handler requires libcurl SSL support.',$request);
}
private static function get():?string
{
$versionInfo=self::getVersionInfo();
return null===$versionInfo?null:$versionInfo['version'];
}
private static function getVersionInfo():?array
{
if(null===self::$versionInfo){
if(!\function_exists('curl_version')){
self::$versionInfo=false;
}else{
$versionInfo=\curl_version();
self::$versionInfo=\is_array($versionInfo)&&isset($versionInfo['version'],$versionInfo['features'])&&\is_string($versionInfo['version'])&&\is_int($versionInfo['features'])?['version'=>$versionInfo['version'],'features'=>$versionInfo['features'],]:false;
}
}
return false===self::$versionInfo?null:self::$versionInfo;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
final class DeadlineSourceStream implements StreamInterface
{
use NonSerializableTrait;
use StreamDecoratorTrait;
private const POLL_INTERVAL=0.05;
private StreamInterface$stream;
private float$deadline;
private?float$readTimeout;
function __construct(StreamInterface$stream,float$deadline,?float$readTimeout){
$this->stream=$stream;
$this->deadline=$deadline;
$this->readTimeout=$readTimeout;
}
function read(int$length):string
{
$idleStart=null;
while(true){
$remaining=$this->deadline-Clock::now();
if($remaining<=0){
throw new TimeoutException('Unable to read from stream: timed out');
}
$data=$this->stream->read($length);
if($data!==''){
return$data;
}
if($this->stream->eof()){
return'';
}
$now=Clock::now();
if($idleStart===null){
$idleStart=$now;
}
if($this->readTimeout!==null&&$now-$idleStart>=$this->readTimeout){
throw new TimeoutException('Unable to read from stream: timed out');
}
$wait=\min($remaining,self::POLL_INTERVAL);
if($this->readTimeout!==null){
$wait=\min($wait,$this->readTimeout-($now-$idleStart));
}
\usleep((int)\ceil($wait*1e6));
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
final class DeclaredLengthStream implements StreamInterface
{
use NonSerializableTrait;
use StreamDecoratorTrait;
private StreamInterface$stream;
private int$remaining;
private?\RuntimeException$failure=null;
function __construct(StreamInterface$stream,int$declaredLength){
$this->stream=$stream;
$this->remaining=$declaredLength;
}
function __clone(){
$this->stream=clone$this->stream;
}
function eof():bool
{
return$this->remaining===0;
}
function isSeekable():bool
{
return false;
}
function seek(int$offset,int$whence=\SEEK_SET):void
{
throw new\RuntimeException('Cannot seek a response body bounded by its declared Content-Length');
}
function getMetadata(?string$key=null){
if($this->failure!==null&&$key==='timed_out'){
return false;
}
$metadata=$this->stream->getMetadata($key);
if($this->failure!==null&&$key===null&&\is_array($metadata)){
$metadata['timed_out']=false;
}
return$metadata;
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
if($this->failure!==null){
throw$this->failure;
}
if($length===0||$this->remaining===0){
return'';
}
$data=$this->stream->read(\min($length,$this->remaining));
if($data===''&&$this->stream->eof()){
$this->failure=new\RuntimeException('Response body ended before the declared Content-Length was reached');
throw$this->failure;
}
$this->remaining-=\strlen($data);
return$data;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Exception\ResponseTransferException;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\DiagnosticValue;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Utils;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
final class EasyHandle
{
use NonSerializableTrait;
var$handle;
StreamInterface$sink;
RequestInterface$request;
array$headers=[];
array$trailers=[];
bool$usesPipewait=false;
bool$deferredSettled=false;
?ResponseInterface$response=null;
array$options=[];
int$errno=0;
?string$effectiveProxy=null;
?string$proxyTunnelSignature=null;
?\Throwable$onHeadersException=null;
?\Throwable$progressException=null;
bool$progressAborted=false;
?\Throwable$createResponseException=null;
?ResponseException$responseHeaderException=null;
?TimeoutException$bodyReadTimeoutException=null;
?TimeoutException$bodyRewindTimeoutException=null;
?\Throwable$bodyRewindException=null;
?\Throwable$bodyReadException=null;
?TimeoutException$sinkWriteTimeoutException=null;
?\Throwable$sinkWriteException=null;
bool$sinkWriteIncomplete=false;
int$responseBodyBytes=0;
?\OverflowException$responseBodySizeException=null;
function createResponse():void
{
$this->response=null;
$this->responseBodyBytes=0;
$this->responseBodySizeException=null;
$this->responseHeaderException=null;
[$ver,$status,$reason,$headers]=HeaderProcessor::parseHeaders($this->headers);
if($status<200&&$status!==101){
return;
}
$framingFailure=null;
try{
$declaredLength=HeaderProcessor::validateResponseFraming($this->request->getMethod(),$status,$headers);
HeaderProcessor::assertContentLengthWithinPlatformLimit($declaredLength);
}catch(\RuntimeException$e){
$framingFailure=$e;
}
$normalizedKeys=Utils::normalizeHeaderKeys($headers);
$decodeContent=$this->options['decode_content']??false;
if($framingFailure===null&&$decodeContent!==false&&isset($normalizedKeys['content-encoding'])){
$headers['x-encoded-content-encoding']=$headers[$normalizedKeys['content-encoding']];
unset($headers[$normalizedKeys['content-encoding']]);
$encodedContentLength=HeaderProcessor::removeHeader('Content-Length',$headers);
if($encodedContentLength!==[]){
$headers['x-encoded-content-length']=$encodedContentLength;
try{
$bodyLength=$this->sink->getSize();
}catch(\Exception$e){
$bodyLength=null;
}
if($bodyLength){
$headers['Content-Length']=[(string)$bodyLength];
}
}
}
$responseFactory=self::requireResponseFactory($this->options[RequestOptions::RESPONSE_FACTORY]??new HttpFactory);
$response=$responseFactory->createResponse($status,$reason??'')->withProtocolVersion($ver);
foreach($headers as$name=>$value){
$response=$response->withAddedHeader((string)$name,$value);
}
$this->response=$response->withBody($this->sink);
if($framingFailure instanceof\OverflowException){
$this->responseHeaderException=new ResponseException($framingFailure->getMessage(),$this->request,$this->response,$framingFailure
);
}elseif($framingFailure!==null){
$this->responseHeaderException=new ResponseTransferException($framingFailure->getMessage(),$this->request,$this->response,$framingFailure
);
}
}
private static function requireResponseFactory($factory):ResponseFactoryInterface
{
if(!$factory instanceof ResponseFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::RESPONSE_FACTORY,ResponseFactoryInterface::class
));
}
return$factory;
}
function __get(string$name):void
{
$msg=$name==='handle'?'The EasyHandle has been released':\sprintf('Invalid property: %s',DiagnosticValue::escape($name));
throw new\BadMethodCallException($msg);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
final class EncodedBodyStream implements StreamInterface
{
use NonSerializableTrait;
use StreamDecoratorTrait;
private StreamInterface$stream;
private?int$limit;
private int$bytesRead=0;
function __construct(StreamInterface$stream,string$declaredLength){
$this->stream=$stream;
$limit=HeaderProcessor::contentLengthToInt($declaredLength);
$this->limit=$limit!==null&&$limit>0?$limit:null;
}
function eof():bool
{
return($this->limit!==null&&$this->bytesRead>=$this->limit)||$this->stream->eof();
}
function isSeekable():bool
{
return false;
}
function seek(int$offset,int$whence=\SEEK_SET):void
{
throw new\RuntimeException('Cannot seek a stream while tracking encoded response bytes');
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
if($this->limit!==null){
$remaining=$this->limit-$this->bytesRead;
if($remaining===0){
return'';
}
$length=\min($length,$remaining);
}
$data=$this->stream->read($length);
$this->bytesRead=TransferByteCounter::add($this->bytesRead,\strlen($data),'Response body exceeds the maximum integer size supported on this platform');
return$data;
}
function getBytesRead():int
{
return$this->bytesRead;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Psr7;
use GuzzleHttp\Utils;
final class HeaderProcessor
{
private function __construct(){
}
static function parseHeaders(array$headers):array
{
if($headers===[]){
throw new\RuntimeException('Expected a non-empty array of header data');
}
$headers=self::getLastHeaderBlock(\array_values($headers));
$statusLine=\array_shift($headers);
if($statusLine===null){
throw new\RuntimeException('Expected a non-empty array of header data');
}
$parts=\explode(' ',$statusLine,3);
$protocol=$parts[0];
if(!Psr7\Utils::caselessEquals(\substr($protocol,0,5),'HTTP/')){
throw new\RuntimeException('HTTP version missing from header data');
}
$version=\substr($protocol,5);
if(!\preg_match('/^\d+(?:\.\d+)?$/D',$version)){
throw new\RuntimeException('HTTP version is invalid');
}
$status=$parts[1]??null;
if($status===null){
throw new\RuntimeException('HTTP status code missing from header data');
}
if(!\preg_match('/^[1-5]\d{2}$/D',$status)){
throw new\RuntimeException('HTTP status code is invalid');
}
$reason=$parts[2]??null;
if($reason!==null&&!\preg_match('/^[\x09\x20-\x7E\x80-\xFF]*$/D',$reason)){
throw new\RuntimeException('HTTP reason phrase is invalid');
}
foreach($headers as$header){
if(\strpos($header,':')===false){
throw new\RuntimeException('HTTP header line is invalid');
}
}
return[$version,(int)$status,$reason,Utils::headersFromLines($headers)];
}
static function isStatusLineCandidate(string$line):bool
{
return\preg_match('/^HTTP\/[0-9]+(?:\.[0-9]+)? [0-9]{3}(?: [^\r\n]*)?(?:\r\n|\r|\n)?$/iD',$line)===1;
}
static function isValidHeaderFieldLine(string$line):bool
{
$parts=\explode(':',$line,2);
if(!isset($parts[1])){
return false;
}
if(!\preg_match('/^[a-zA-Z0-9\'`#$%&*+.^_|~!-]+$/D',$parts[0])){
return false;
}
return\preg_match('/^[\x20\x09\x21-\x7E\x80-\xFF]*(?:\r\n|\r|\n)?$/D',\trim($parts[1]," \t"))===1;
}
static function parseContentLength(array$values):?string
{
$length=null;
foreach($values as$value){
foreach(\explode(',',$value)as$part){
$part=\trim($part," \t");
if(\preg_match('/^[0-9]+$/D',$part)!==1){
throw new\RuntimeException('value is not a non-negative decimal integer');
}
$part=\ltrim($part,'0');
$part=$part===''?'0':$part;
if($length!==null&&$part!==$length){
throw new\RuntimeException('values conflict');
}
$length=$part;
}
}
if($length===null){
return;
}
return$length;
}
static function contentLengthToInt(?string$length):?int
{
if($length===null){
return;
}
$max=(string)\PHP_INT_MAX;
if(\strlen($length)>\strlen($max)||(\strlen($length)===\strlen($max)&&\strcmp($length,$max)>0)){
return;
}
return(int)$length;
}
static function assertContentLengthWithinPlatformLimit(?string$length):void
{
if($length===null||self::contentLengthToInt($length)!==null){
return;
}
throw new\OverflowException('Content-Length exceeds the maximum integer size supported on this platform');
}
static function validateResponseFraming(string$method,int$status,array$headers
):?string{
if(!self::responseCanHaveBody($method,$status)){
return;
}
$normalizedKeys=Utils::normalizeHeaderKeys($headers);
$contentLength=self::removeHeader('Content-Length',$headers);
try{
$length=self::parseContentLength($contentLength);
}catch(\RuntimeException$e){
throw new\RuntimeException('Invalid Content-Length response header: '.$e->getMessage(),0,$e);
}
if($length!==null&&isset($normalizedKeys['transfer-encoding'])){
throw new\RuntimeException('A response must not contain both Content-Length and Transfer-Encoding');
}
self::parseTransferEncoding($headers);
return$length;
}
static function parseTransferEncoding(array$headers):bool
{
$chunked=false;
foreach($headers as$name=>$values){
if(!Psr7\Utils::caselessEquals((string)$name,'Transfer-Encoding')){
continue;
}
foreach($values as$value){
$afterChunked=false;
foreach(\explode(',',$value)as$coding){
$coding=\trim($coding," \t");
if($coding===''){
continue;
}
if(Psr7\Utils::caselessEquals($coding,'chunked')){
$chunked=true;
$afterChunked=true;
}elseif($afterChunked){
throw new\RuntimeException('Invalid Transfer-Encoding response header: chunked is not the final transfer coding');
}elseif(!Psr7\Utils::caselessEquals($coding,'identity')){
throw new\RuntimeException(\sprintf('Invalid Transfer-Encoding response header: unsupported transfer coding "%s"',Psr7\DiagnosticValue::escape($coding)));
}
}
}
}
return$chunked;
}
static function removeHeader(string$name,array&$headers):array
{
$values=[];
foreach($headers as$key=>$headerValues){
if(Psr7\Utils::caselessEquals((string)$key,$name)){
\array_push($values,...$headerValues);
unset($headers[$key]);
}
}
return$values;
}
static function responseCanHaveBody(string$method,int$status):bool
{
return$method!=='HEAD'&&!($method==='CONNECT'&&$status>=200&&$status<300)&&$status>=200
&&$status!==204
&&$status!==304;
}
private static function getLastHeaderBlock(array$headers):array
{
$lastStatusLine=0;
foreach($headers as$index=>$line){
if(self::isStatusLineCandidate($line)){
$lastStatusLine=$index;
}
}
return\array_slice($headers,$lastStatusLine);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
final class HostValidator
{
private function __construct(){
}
static function assertRequestHost(#[\SensitiveParameter]RequestInterface$request
):void{
self::assertUriHost($request->getUri()->getHost(),$request);
foreach($request->getHeader('Host')as$value){
self::assertPrintableAscii((string)$value,'The request Host header "%s" must contain only printable ASCII characters, because an intermediary or an origin server can otherwise read it as an authority that differs from the one the request names. An internationalized host name has an A-label form that this rule accepts.',$request);
}
}
private static function assertUriHost(string$host,#[\SensitiveParameter]RequestInterface$request
):void{
self::assertPrintableAscii($host,'The request URI host "%s" must contain only printable ASCII characters, because a handler can otherwise connect to a host that differs from the one the request names. An internationalized host name has an A-label form that this rule accepts.',$request);
if(\strpos($host,'%')!==false){
throw new RequestException(\sprintf('The request URI host "%s" must not contain a percent escape, because a handler decodes it and can then connect to a host that differs from the one the request names.',self::escape($host)),$request);
}
if(!Psr7\Rfc3986::isValidHost($host)){
throw new RequestException(\sprintf('The request URI host "%s" must be a valid RFC 3986 host, because a handler reparses the URI and can then connect to a host that differs from the one the request names.',self::escape($host)),$request);
}
if(\str_ends_with($host,'.')&&self::isNumericIpv4Host(\rtrim($host,'.'))){
throw new RequestException(\sprintf('The request URI host "%s" must not be written as one to four decimal, octal or hexadecimal parts followed by one or more trailing dots, because a handler can read that spelling as an IPv4 address and connect to that address while the rest of the process reads a name.',self::escape($host)),$request);
}
}
static function isNumericIpv4Host(string$host):bool
{
if($host===''){
return false;
}
$parts=\explode('.',$host);
if(\count($parts)>4){
return false;
}
foreach($parts as$part){
if(!self::isNumericIpv4Part($part)){
return false;
}
}
return true;
}
private static function isNumericIpv4Part(string$part):bool
{
if($part===''){
return false;
}
if($part[0]==='0'&&isset($part[1])&&($part[1]==='x'||$part[1]==='X')){
return\strlen($part)>2&&\strspn($part,'0123456789abcdefABCDEF',2)===\strlen($part)-2;
}
$digits=$part[0]==='0'?'01234567':'0123456789';
return\strspn($part,$digits)===\strlen($part);
}
private static function assertPrintableAscii(string$value,string$message,#[\SensitiveParameter]RequestInterface$request
):void{
if(\preg_match('/\A[\x21-\x7E]*\z/D',$value)!==1){
throw new RequestException(\sprintf($message,self::escape($value)),$request);
}
}
private static function escape(string$value):string
{
$escaped='';
for($offset=0,$length=\strlen($value);$offset<$length;++$offset){
$byte=\ord($value[$offset]);
if($byte>=32&&$byte<=126){
$escaped.=$value[$offset];
continue;
}
$escaped.=\sprintf('\\x%02X',$byte);
}
return$escaped;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\StreamWrapper;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
final class InflateBodyStream implements StreamInterface
{
use NonSerializableTrait;
private const CHUNK_SIZE=8192;
private const INVALID_DATA='Unable to decode the response body: invalid gzip or deflate data';
private const TRAILING_DATA='Unable to decode the response body: unexpected data after the compressed stream';
private?StreamInterface$stream;
private bool$deflate;
private$context;
private string$header='';
private string$buffer='';
private int$offset=0;
private int$position=0;
private bool$finished=false;
private int$trailingAllowance=0;
private bool$detachable=true;
private?\RuntimeException$error=null;
function __construct(StreamInterface$stream,bool$deflate=false){
$this->stream=$stream;
$this->deflate=$deflate;
}
function __toString():string
{
return$this->getContents();
}
function getContents():string
{
return Utils::copyToString($this);
}
function close():void
{
$stream=$this->stream;
$this->release();
if($stream!==null){
$stream->close();
}
}
function detach(){
if($this->stream===null||!$this->detachable){
return;
}
$stream=clone$this;
$stream->detachable=false;
$this->release();
return StreamWrapper::getResource($stream);
}
function getSize():?int
{
return;
}
function tell():int
{
$this->attached();
return$this->position;
}
function eof():bool
{
$stream=$this->attached();
return$this->error===null&&$this->offset===\strlen($this->buffer)&&$stream->eof();
}
function isSeekable():bool
{
return false;
}
function seek(int$offset,int$whence=\SEEK_SET):void
{
throw new\RuntimeException('Stream is not seekable');
}
function rewind():void
{
$this->seek(0);
}
function isWritable():bool
{
return false;
}
function write(string$string):int
{
throw new\RuntimeException('Cannot write to a non-writable stream');
}
function isReadable():bool
{
return$this->stream!==null&&$this->stream->isReadable();
}
function read(int$length):string
{
$stream=$this->attached();
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
if($length===0){
return'';
}
while($this->offset===\strlen($this->buffer)){
if($this->error!==null){
throw$this->error;
}
$encoded=$stream->read(self::CHUNK_SIZE);
if($encoded===''){
return'';
}
if($this->finished){
if($this->allowTrailing(\strlen($encoded))){
continue;
}
throw$this->fail(self::TRAILING_DATA);
}
$this->buffer=$this->inflate($encoded);
$this->offset=0;
}
$data=(string)\substr($this->buffer,$this->offset,$length);
$this->offset+=\strlen($data);
$this->position=TransferByteCounter::add($this->position,\strlen($data),'Response body exceeds the maximum integer size supported on this platform');
return$data;
}
function getMetadata(?string$key=null){
if($this->stream===null){
return$key===null?[]:null;
}
if($key==='timed_out'&&$this->error!==null){
return false;
}
$metadata=$this->stream->getMetadata($key);
if($key===null&&$this->error!==null&&\is_array($metadata)){
$metadata['timed_out']=false;
}
return$metadata;
}
private function inflate(string$encoded,?int$encoding=null):string
{
$retry=false;
if($this->context===null){
$this->header.=$encoded;
if(\strlen($this->header)<2){
return'';
}
$encoded=$this->header;
$this->header='';
if(!\function_exists('inflate_init')){
throw$this->fail('Unable to decode the response body: the zlib extension is not loaded');
}
$encoding=$encoding??(\strncmp($encoded,"\x1f\x8b",2)===0?\ZLIB_ENCODING_GZIP:\ZLIB_ENCODING_DEFLATE);
$retry=$this->deflate&&$encoding===\ZLIB_ENCODING_DEFLATE;
$context=\inflate_init($encoding);
if($context===false){
throw$this->fail(self::INVALID_DATA);
}
$this->context=$context;
}
$readBefore=\inflate_get_read_len($this->context);
\set_error_handler(static function():bool{
return true;
});
try{
$decoded=\inflate_add($this->context,$encoded);
}finally{
\restore_error_handler();
}
if($decoded===false){
if($retry){
$this->context=null;
$this->trailingAllowance=4;
return$this->inflate($encoded,\ZLIB_ENCODING_RAW);
}
throw$this->fail(self::INVALID_DATA);
}
$this->finished=\inflate_get_status($this->context)===\ZLIB_STREAM_END;
if($this->finished){
$consumed=\inflate_get_read_len($this->context)-$readBefore;
if($consumed<0){
$consumed+=4294967296;
}
if(!$this->allowTrailing(\strlen($encoded)-(int)$consumed)){
$this->fail(self::TRAILING_DATA);
}
}
return$decoded;
}
private function allowTrailing(int$length):bool
{
if($length>$this->trailingAllowance){
return false;
}
$this->trailingAllowance-=$length;
return true;
}
private function attached():StreamInterface
{
if($this->stream===null){
throw new\RuntimeException('Stream is detached');
}
return$this->stream;
}
private function release():void
{
$this->stream=null;
$this->context=null;
$this->buffer='';
$this->offset=0;
}
private function fail(string$message):\RuntimeException
{
return$this->error=new\RuntimeException($message);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\TransferStats;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
final class MockHandler implements\Countable
{
use NonSerializableTrait;
private array$queue=[];
private?RequestInterface$lastRequest=null;
private array$lastOptions=[];
private$onFulfilled;
private$onRejected;
static function createWithMiddleware(#[\SensitiveParameter]?array$queue=null,?callable$onFulfilled=null,?callable$onRejected=null
):HandlerStack{
return HandlerStack::create(new self($queue,$onFulfilled,$onRejected));
}
function __construct(#[\SensitiveParameter]?array$queue=null,?callable$onFulfilled=null,?callable$onRejected=null
){
$this->onFulfilled=$onFulfilled;
$this->onRejected=$onRejected;
if($queue){
$this->append(...array_values($queue));
}
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
if(!$this->queue){
throw new\OutOfBoundsException('Mock queue is empty');
}
if(isset($options['delay'])&&\is_numeric($options['delay'])){
Clock::sleep((int)($options['delay']*1000));
}
if(isset($options['on_stats'])&&!\is_callable($options['on_stats'])){
throw new InvalidArgumentException('on_stats must be callable');
}
$this->lastRequest=$request;
$this->lastOptions=$options;
$response=\array_shift($this->queue);
$onHeaders=null;
$onHeadersResponse=null;
if(isset($options['on_headers'])){
if(!\is_callable($options['on_headers'])){
throw new InvalidArgumentException('on_headers must be callable');
}
$onHeaders=$options['on_headers'];
}
if(\is_callable($response)){
$response=$response($request,$options);
}
$response=$response instanceof\Throwable
?P\Create::rejectionFor($response):P\Create::promiseFor($response);
if(\is_callable($onHeaders)){
$response=$response->then(static function(#[\SensitiveParameter]$value
)use($onHeaders,$request,&$onHeadersResponse){
if(!$value instanceof ResponseInterface){
return$value;
}
try{
$onHeaders($value,$request);
}catch(\Throwable$e){
$msg='An error was encountered during the on_headers event';
$onHeadersResponse=$value;
throw new ResponseException($msg,$request,$value,$e);
}
return$value;
}
);
}
$promise=$response->then(function(#[\SensitiveParameter]$value
)use($request,$options):?ResponseInterface{
$this->invokeStats($request,$options,$value);
if($this->onFulfilled){
($this->onFulfilled)($value);
}
if($value!==null&&isset($options['sink'])){
$contents=(string)$value->getBody();
$sink=$options['sink'];
if(\is_resource($sink)){
\fwrite($sink,$contents);
}elseif(\is_string($sink)){
\file_put_contents($sink,$contents);
}elseif($sink instanceof StreamInterface){
$sink->write($contents);
}
}
return$value;
},function(#[\SensitiveParameter]$reason
)use($request,$options,&$onHeadersResponse):PromiseInterface{
$this->invokeStats($request,$options,$onHeadersResponse,$reason);
if($this->onRejected){
($this->onRejected)($reason);
}
return P\Create::rejectionFor($reason);
}
);
return$promise;
}
function append(#[\SensitiveParameter]...$values
):void{
foreach($values as$value){
if($value instanceof ResponseInterface
||$value instanceof\Throwable
||$value instanceof PromiseInterface
||\is_callable($value)){
$this->queue[]=$value;
}else{
throw new\TypeError('Expected a Response, Promise, Throwable or callable. Found '.\get_debug_type($value));
}
}
}
function getLastRequest():?RequestInterface
{
return$this->lastRequest;
}
function getLastOptions():array
{
return$this->lastOptions;
}
function count():int
{
return\count($this->queue);
}
function reset():void
{
$this->queue=[];
}
private function invokeStats(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]?ResponseInterface$response=null,#[\SensitiveParameter]$reason=null
):void{
if(isset($options['on_stats'])){
$transferTime=$options['transfer_time']??0.0;
if(!\is_int($transferTime)&&!\is_float($transferTime)&&(!\is_string($transferTime)||!\is_numeric($transferTime))){
throw new InvalidArgumentException('transfer_time must be a number of seconds');
}
$stats=new TransferStats($request,$response,(float)$transferTime,$reason);
($options['on_stats'])($stats);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\RequestOptions;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class Proxy
{
private function __construct(){
}
static function wrapSync(callable$default,callable$sync):callable
{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($default,$sync):PromiseInterface{
return empty($options[RequestOptions::SYNCHRONOUS])?$default($request,$options):$sync($request,$options);
};
}
static function wrapStreaming(callable$default,callable$streaming):callable
{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($default,$streaming):PromiseInterface{
return empty($options['stream'])?$default($request,$options):$streaming($request,$options);
};
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\ProxyOptions;
use GuzzleHttp\ProxySelection;
use GuzzleHttp\Psr7;
use Psr\Http\Message\UriInterface;
final class ProxyEnv
{
private function __construct(){
}
static function resolveProxySelection(UriInterface$uri,#[\SensitiveParameter]$proxyOption
):ProxySelection{
$selection=ProxyOptions::resolve($uri,$proxyOption);
if($selection->hasProxy()||$selection->shouldDisableProxy()){
return$selection;
}
$envProxy=self::getProxyForScheme($uri->getScheme());
if($envProxy===null){
return$selection;
}
$noProxy=self::getNoProxy();
if($noProxy!==null&&ProxyOptions::isUriInNoProxy($uri,self::splitNoProxy($noProxy))){
return ProxySelection::bypassed();
}
return ProxySelection::proxy($envProxy);
}
static function getProxyForScheme(string$scheme):?string
{
$scheme=Psr7\Utils::asciiToLower($scheme);
$candidates=[$scheme.'_proxy'];
if($scheme!=='http'){
$candidates[]=Psr7\Utils::asciiToUpper($scheme).'_PROXY';
}
$candidates[]='all_proxy';
$candidates[]='ALL_PROXY';
foreach($candidates as$name){
$value=self::getenv($name);
if($value!==null){
return$value;
}
}
return;
}
static function getNoProxy():?string
{
foreach(['no_proxy','NO_PROXY']as$name){
$value=self::getenv($name);
if($value!==null){
return$value;
}
}
return;
}
static function splitNoProxy(string$noProxy):array
{
$entries=[];
$split=\preg_split('/[\s,]+/',$noProxy);
if($split===false){
throw new\RuntimeException('Unable to split the no_proxy value: '.\preg_last_error_msg());
}
foreach($split as$entry){
if($entry!==''){
$entries[]=$entry;
}
}
return$entries;
}
private static function getenv(string$name):?string
{
if(\PHP_OS_FAMILY==='Windows'&&\PHP_SAPI!=='cli'){
return;
}
$value=\getenv($name,true);
return$value===false||$value===''?null:$value;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use Psr\Http\Message\RequestInterface;
final class RequestFraming
{
use NonSerializableTrait;
RequestInterface$request;
?int$bodySize;
?int$contentLength;
private function __construct(RequestInterface$request,?int$bodySize,?int$contentLength){
$this->request=$request;
$this->bodySize=$bodySize;
$this->contentLength=$contentLength;
}
static function analyze(#[\SensitiveParameter]RequestInterface$request,bool$sendBody=true
):self{
try{
$length=HeaderProcessor::parseContentLength($request->getHeader('Content-Length'));
}catch(\RuntimeException$e){
throw new RequestException('Invalid Content-Length request header: '.$e->getMessage(),$request,0,$e);
}
try{
HeaderProcessor::assertContentLengthWithinPlatformLimit($length);
}catch(\OverflowException$e){
throw new RequestException($e->getMessage(),$request,0,$e);
}
$contentLength=HeaderProcessor::contentLengthToInt($length);
if($length!==null){
$request=$request->withHeader('Content-Length',$length);
}
if(!$sendBody){
return new self($request->withoutHeader('Transfer-Encoding'),null,$contentLength);
}
$transferEncoding=$request->getHeader('Transfer-Encoding');
if($length!==null&&$transferEncoding!==[]){
throw new RequestException('A request must not contain both Content-Length and Transfer-Encoding',$request
);
}
if($transferEncoding!==[]){
$tokens=[];
foreach($transferEncoding as$value){
foreach(\explode(',',$value)as$part){
$tokens[]=\trim($part," \t");
}
}
if(\count($tokens)!==1||!Psr7\Utils::caselessEquals($tokens[0],'chunked')||$request->getProtocolVersion()!=='1.1'){
throw new RequestException('Unsupported Transfer-Encoding request header',$request);
}
}
$bodySize=self::bodySize($request);
if($bodySize!==null&&$contentLength!==null&&$bodySize!==$contentLength){
throw new RequestException('Content-Length does not match the request body size',$request);
}
if($bodySize===null&&$contentLength===null&&$request->getProtocolVersion()==='1.0'){
throw new RequestException('An unknown-size HTTP/1.0 request body requires Content-Length',$request);
}
if($length===null&&$bodySize!==null&&($bodySize>0||\in_array($request->getMethod(),['PUT','POST'],true))){
$contentLength=$bodySize;
$request=$request->withHeader('Content-Length',(string)$bodySize);
}
return new self($request->withoutHeader('Transfer-Encoding'),$bodySize,$contentLength);
}
static function bodySize(#[\SensitiveParameter]RequestInterface$request
):?int{
$body=$request->getBody();
try{
$size=$body->getSize();
if($size===null){
return;
}
if($size<0){
throw new\RuntimeException('Request body size must not be negative');
}
$seekable=$body->isSeekable();
}catch(\Exception$e){
throw self::bodyException($request,$e,'Timed out while determining the request body size','Failed to determine the request body size');
}
if($seekable){
return$size;
}
try{
$position=$body->tell();
}catch(\RuntimeException$e){
return;
}
if($position<0||$position>$size){
throw new RequestException('The request body position is outside the stream size',$request);
}
return$size-$position;
}
function materialize():string
{
$body=$this->request->getBody();
if($this->contentLength===null){
try{
return(string)$body;
}catch(\Exception$e){
throw self::bodyException($this->request,$e,'Timed out while reading the request body','Failed to read the request body');
}
}
if($this->contentLength===0){
return'';
}
try{
if($body->isSeekable()){
$body->rewind();
}
}catch(\Exception$e){
throw self::bodyException($this->request,$e,'Timed out while rewinding the request body','Failed to rewind the request body');
}
$contents='';
$remaining=$this->contentLength;
while($remaining>0){
$limit=\min(8192,$remaining);
try{
$chunk=$body->read($limit);
}catch(\Exception$e){
throw self::bodyException($this->request,$e,'Timed out while reading the request body','Failed to read the request body');
}
if($chunk===''){
throw new RequestException('Request body ended before the declared Content-Length was reached',$this->request
);
}
if(\strlen($chunk)>$limit){
throw new RequestException('Request body stream returned more bytes than requested',$this->request);
}
$contents.=$chunk;
$remaining-=\strlen($chunk);
}
return$contents;
}
private static function bodyException(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]\Exception$exception,string$timeoutMessage,string$fallbackMessage
):RequestException{
$message=$exception instanceof TimeoutException
?$timeoutMessage
:($exception->getMessage()!==''?$exception->getMessage():$fallbackMessage);
return new RequestException($message,$request,0,$exception);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ConnectTimeoutException;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\NetworkException;
use GuzzleHttp\Exception\NetworkTimeoutException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Exception\ResponseTimeoutException;
use GuzzleHttp\Exception\ResponseTransferException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\HostIdentity;
use GuzzleHttp\Multiplexing;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\ProxyOptions;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\TransferStats;
use GuzzleHttp\TransportSharing;
use GuzzleHttp\Utils;
use Openssl\Session;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
final class StreamHandler
{
use NonSerializableTrait;
private const KNOWN_CONSTRUCTOR_OPTIONS=['max_host_connections'=>true,'max_total_connections'=>true,'transport_sharing'=>true,];
private const TLS_SESSION_CACHE_MAX_KEYS=25;
private const CONNECTION_ERRORS=['php_network_getaddresses:','getaddrinfo','gethostbyname failed','Unable to connect to','Connection refused','No connection could be made because the target machine actively refused it','connection attempt failed','connect() failed','Network is unreachable','No route to host','Host is unreachable','Host is down','Cannot connect to HTTPS server through proxy','Failed to enable crypto',];
private const CONNECT_TIMEOUT_ERRORS=['Connection timed out','Operation timed out','SSL: Handshake timed out','did not properly respond after a period of time',];
private const NETWORK_ERRORS=['SSL: Connection reset by peer','SSL: Broken pipe','unexpected eof while reading',];
private const STRUCTURED_NETWORK_ERROR_CODES=['NetworkSendFailed',];
private const STRUCTURED_CONNECTION_ERROR_CODES=['SslNotSupported',];
private const DEFAULT_IDLE_TIMEOUT_MS=60000;
private?\Throwable$onStatsException=null;
private string$transportSharingMode;
private bool$connectionCapsConfigured=false;
private?StreamTlsSessionCache$sessionCache=null;
function __construct(array$options=[]){
foreach($options as$name=>$_){
if(!isset(self::KNOWN_CONSTRUCTOR_OPTIONS[$name])){
throw new InvalidArgumentException(\sprintf('Invalid StreamHandler constructor option "%s".',Psr7\DiagnosticValue::escape((string)$name)));
}
}
$this->transportSharingMode=CurlShareHandleState::normalizeMode($options['transport_sharing']??null,'transport_sharing');
foreach(['max_host_connections','max_total_connections']as$capOption){
$value=$options[$capOption]??null;
if($value===null){
continue;
}
if(!\is_int($value)||$value<1){
throw new InvalidArgumentException(\sprintf('%s must be a positive integer.',$capOption));
}
$this->connectionCapsConfigured=true;
}
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$this->onStatsException=null;
if(isset($options['delay'])){
Clock::sleep((int)($options['delay']*1000));
}
$multiplex=$options['multiplex']??null;
if(null!==$multiplex&&!\in_array($multiplex,[Multiplexing::NONE,Multiplexing::EAGER,Multiplexing::WAIT,Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new InvalidArgumentException(\sprintf('The "multiplex" option must be null or a GuzzleHttp\\Multiplexing::* constant; received %s.',\get_debug_type($multiplex)));
}
if(\in_array($multiplex,[Multiplexing::REQUIRE_EAGER,Multiplexing::REQUIRE_WAIT],true)){
throw new RequestException('The stream handler cannot guarantee a multiplexed protocol; required multiplexing needs a cURL handler.',$request);
}
$protocolVersion=$request->getProtocolVersion();
if(''===$protocolVersion){
throw new RequestException('HTTP protocol version must not be empty.',$request);
}
if(1!==\preg_match('/^\d+(?:\.\d+)?$/D',$protocolVersion)){
throw new RequestException('HTTP protocol version must be a valid HTTP version number.',$request);
}
if('1.0'!==$protocolVersion&&'1.1'!==$protocolVersion){
throw new RequestException(sprintf('HTTP/%s is not supported by the stream handler.',$protocolVersion),$request);
}
if(isset($options['on_stats'])&&!\is_callable($options['on_stats'])){
throw new InvalidArgumentException('on_stats must be callable');
}
$startTime=isset($options['on_stats'])?Clock::now():null;
self::rejectUnsupportedRequestOptions($request,$options);
$this->rejectStreamingWithConnectionCaps($options);
$this->assertTransportSharingSupported();
$framing=RequestFraming::analyze($request->withoutHeader('Expect'));
$request=$framing->request;
try{
self::assertRequestUriSupported($request,$options);
$body=$framing->materialize();
if($framing->contentLength===null&&($body!==''||\in_array($request->getMethod(),['PUT','POST'],true))){
$request=$request->withHeader('Content-Length',(string)\strlen($body));
}
$deadline=null;
$stream=$this->createStream($request,$options,$body,$deadline);
$headers=\stream_get_meta_data($stream)['wrapper_data'];
return$this->createResponse($request,$options,$stream,\is_array($headers)?$headers:[],$startTime,$deadline
);
}catch(\InvalidArgumentException$e){
throw$e;
}catch(\Exception$e){
if($this->isOnStatsException($e)){
throw$e;
}
if(!$e instanceof TransferException){
$message=$e->getMessage();
$e=self::createStreamFailureException($message,$request,$e,[]);
}
$this->invokeStats($options,$request,$startTime,null,$e);
return P\Create::rejectionFor($e);
}
}
private function isOnStatsException(\Throwable$e):bool
{
if($this->onStatsException!==$e){
return false;
}
$this->onStatsException=null;
return true;
}
private static function isConnectTimeoutError(string$message):bool
{
foreach(self::CONNECT_TIMEOUT_ERRORS as$timeoutError){
if(Psr7\Utils::caselessContains($message,$timeoutError)){
return true;
}
}
return false;
}
private static function isConnectionError(string$message):bool
{
foreach(self::CONNECTION_ERRORS as$connectionError){
if(Psr7\Utils::caselessContains($message,$connectionError)){
return true;
}
}
return false;
}
private static function isSendError(string$message):bool
{
return Psr7\Utils::caselessContains($message,'bytes failed with errno=');
}
private static function isNetworkError(string$message):bool
{
foreach(self::NETWORK_ERRORS as$networkError){
if(Psr7\Utils::caselessContains($message,$networkError)){
return true;
}
}
return false;
}
private static function createStreamFailureException(#[\SensitiveParameter]string$message,#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]\Exception$previous,array$streamErrorCodes
):TransferException{
if(self::isSendError($message)||self::hasStreamErrorCode($streamErrorCodes,self::STRUCTURED_NETWORK_ERROR_CODES)){
return self::isConnectTimeoutError($message)?new NetworkTimeoutException($message,$request,$previous):new NetworkException($message,$request,$previous);
}
if(self::isConnectTimeoutError($message)){
return new ConnectTimeoutException($message,$request,$previous);
}
if(self::hasStreamErrorCode($streamErrorCodes,self::STRUCTURED_CONNECTION_ERROR_CODES)||self::isConnectionError($message)){
return new ConnectException($message,$request,$previous);
}
if(self::isNetworkError($message)){
return new NetworkException($message,$request,$previous);
}
return new RequestException($message,$request,0,$previous);
}
private static function hasStreamErrorCode(array$streamErrorCodes,array$codes):bool
{
foreach($streamErrorCodes as$streamErrorCode){
foreach($codes as$code){
if($streamErrorCode===$code){
return true;
}
}
}
return false;
}
private function invokeStats(#[\SensitiveParameter]array$options,#[\SensitiveParameter]RequestInterface$request,?float$startTime,#[\SensitiveParameter]?ResponseInterface$response=null,#[\SensitiveParameter]?\Throwable$error=null
):void{
if(isset($options['on_stats'])){
$stats=new TransferStats($request,$response,Clock::now()-$startTime,$error,[]);
try{
($options['on_stats'])($stats);
}catch(\Throwable$e){
$this->onStatsException=$e;
throw$e;
}
}
}
private function createResponse(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,$stream,#[\SensitiveParameter]array$hdrs,?float$startTime,?float$deadline
):PromiseInterface{
try{
[$ver,$status,$reason,$headers]=HeaderProcessor::parseHeaders($hdrs);
}catch(\Throwable$e){
return$this->rejectResponseCreation($options,$request,$startTime,$e);
}
$canHaveBody=HeaderProcessor::responseCanHaveBody($request->getMethod(),$status);
$framingFailure=null;
$declaredLength=null;
$chunked=false;
try{
$declaredLength=HeaderProcessor::validateResponseFraming($request->getMethod(),$status,$headers);
$chunked=$canHaveBody&&HeaderProcessor::parseTransferEncoding($headers);
if(empty($options['stream'])){
HeaderProcessor::assertContentLengthWithinPlatformLimit($declaredLength);
}
}catch(\RuntimeException$e){
$framingFailure=$e;
}
if($chunked){
HeaderProcessor::removeHeader('Transfer-Encoding',$headers);
}elseif(!$canHaveBody){
$headers=self::removeChunkedTransferCoding($headers);
}
$streamFactory=self::requireStreamFactory($options[RequestOptions::STREAM_FACTORY]??new Psr7\HttpFactory);
$responseFactory=self::requireResponseFactory($options[RequestOptions::RESPONSE_FACTORY]??new Psr7\HttpFactory);
$resource=$stream;
$stream=$streamFactory->createStreamFromResource($stream);
if($framingFailure===null&&$deadline!==null&&empty($options['stream'])){
$stream=self::createDeadlineSource($stream,$resource,$deadline,$options);
}
if($chunked||!empty($options['stream'])){
$stream=new TransportStream($stream);
}
if($chunked){
$stream=new ChunkedBodyStream($stream);
}elseif(!empty($options['stream'])){
$length=HeaderProcessor::contentLengthToInt($declaredLength);
if($length!==null){
$stream=new DeclaredLengthStream($stream,$length);
}
}
$encodedBody=null;
if($framingFailure===null){
[$stream,$headers,$encodedBody]=self::checkDecode($options,$headers,$stream,$declaredLength);
}
$sink=$framingFailure!==null||!$canHaveBody
?$streamFactory->createStream(''):$this->createSink($stream,$options);
try{
$response=$responseFactory->createResponse($status,$reason??'')->withProtocolVersion($ver);
foreach($headers as$name=>$value){
$response=$response->withAddedHeader((string)$name,$value);
}
$response=$response->withBody($sink);
}catch(\Throwable$e){
return$this->rejectResponseCreation($options,$request,$startTime,$e);
}
if($framingFailure!==null){
try{
$stream->close();
}catch(\Exception$e){
}
$reason=$framingFailure instanceof\OverflowException
?new ResponseException($framingFailure->getMessage(),$request,$response,$framingFailure):new ResponseTransferException($framingFailure->getMessage(),$request,$response,$framingFailure);
$this->invokeStats($options,$request,$startTime,$response,$reason);
return P\Create::rejectionFor($reason);
}
if($deadline!==null&&Clock::now()>=$deadline){
try{
$stream->close();
}catch(\Exception$e){
}
$reason=new ResponseTimeoutException('Timed out while receiving the response headers',$request,$response);
$this->invokeStats($options,$request,$startTime,$response,$reason);
return P\Create::rejectionFor($reason);
}
if(isset($options['on_headers'])){
try{
$options['on_headers']($response,$request);
}catch(\Throwable$e){
$reason=new ResponseException('An error was encountered during the on_headers event',$request,$response,$e);
$this->invokeStats($options,$request,$startTime,$response,$reason);
return P\Create::rejectionFor($reason);
}
}
if(!$canHaveBody){
try{
$stream->close();
}catch(\Exception$e){
}
}elseif($sink!==$stream){
try{
$this->drain($request,$response,$stream,$sink,$declaredLength,$encodedBody);
}catch(ResponseException$e){
$this->invokeStats($options,$request,$startTime,$response,$e);
return P\Create::rejectionFor($e);
}
}
$this->invokeStats($options,$request,$startTime,$response,null);
return P\Create::promiseFor($response);
}
private function rejectResponseCreation(#[\SensitiveParameter]array$options,#[\SensitiveParameter]RequestInterface$request,?float$startTime,#[\SensitiveParameter]\Throwable$previous
):PromiseInterface{
$reason=new RequestException('An error was encountered while creating the response',$request,0,$previous
);
$this->invokeStats($options,$request,$startTime,null,$reason);
return P\Create::rejectionFor($reason);
}
private function createSink(StreamInterface$stream,#[\SensitiveParameter]array$options
):StreamInterface{
if(!empty($options['stream'])){
return$stream;
}
$streamFactory=self::requireStreamFactory($options[RequestOptions::STREAM_FACTORY]??new Psr7\HttpFactory);
$hasSink=isset($options['sink']);
$sink=$hasSink?$options['sink']:Psr7\Utils::tryFopen('php://temp','r+');
if($hasSink&&\is_resource($sink)){
return self::streamForResourceSink(Psr7\Utils::streamFor($sink));
}
if(\is_string($sink)){
return new Psr7\LazyOpenStream($sink,'w+');
}
if(!\is_resource($sink)){
return Psr7\Utils::streamFor($sink);
}
return$streamFactory->createStreamFromResource($sink);
}
private static function streamForResourceSink(StreamInterface$stream):StreamInterface
{
return Psr7\FnStream::decorate($stream,['close'=>static function()use($stream):void{
$stream->detach();
},]);
}
private static function requireStreamFactory($factory):StreamFactoryInterface
{
if(!$factory instanceof StreamFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::STREAM_FACTORY,StreamFactoryInterface::class
));
}
return$factory;
}
private static function requireResponseFactory($factory):ResponseFactoryInterface
{
if(!$factory instanceof ResponseFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::RESPONSE_FACTORY,ResponseFactoryInterface::class
));
}
return$factory;
}
private static function removeChunkedTransferCoding(array$headers):array
{
foreach($headers as$name=>$values){
if(!Psr7\Utils::caselessEquals((string)$name,'Transfer-Encoding')){
continue;
}
$remaining=[];
foreach($values as$value){
if(!Psr7\Utils::caselessEquals(\substr($value,0,7),'chunked')){
$remaining[]=$value;
}
}
if($remaining===[]){
unset($headers[$name]);
}else{
$headers[$name]=$remaining;
}
}
return$headers;
}
private static function checkDecode(#[\SensitiveParameter]array$options,array$headers,StreamInterface$stream,?string$declaredLength
):array{
$encodedBody=null;
if(isset($options['decode_content'])&&$options['decode_content']!==false){
$normalizedKeys=Utils::normalizeHeaderKeys($headers);
if(isset($normalizedKeys['content-encoding'])){
$encoding=$headers[$normalizedKeys['content-encoding']];
if($encoding[0]==='gzip'||$encoding[0]==='deflate'){
if(empty($options['stream'])&&$declaredLength!==null&&$declaredLength!=='0'){
$encodedBody=new EncodedBodyStream($stream,$declaredLength);
$stream=$encodedBody;
}
$stream=new InflateBodyStream($stream,$encoding[0]==='deflate');
$headers['x-encoded-content-encoding']=$headers[$normalizedKeys['content-encoding']];
unset($headers[$normalizedKeys['content-encoding']]);
$encodedContentLength=HeaderProcessor::removeHeader('Content-Length',$headers);
if($encodedContentLength!==[]){
$headers['x-encoded-content-length']=$encodedContentLength;
}
}
}
}
return[$stream,$headers,$encodedBody];
}
private function drain(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response,StreamInterface$source,StreamInterface$sink,?string$declaredResponseBodyLength,?EncodedBodyStream$encodedBody=null
):StreamInterface{
try{
$declaredLength=HeaderProcessor::contentLengthToInt($declaredResponseBodyLength);
$copyLimit=$encodedBody===null?$declaredLength??-1:-1;
try{
$target=$this->createResponseSink($request,$response,$sink);
$copied=Psr7\Utils::copyToStream($source,$target,$copyLimit);
}catch(ResponseException$e){
throw$e;
}catch(TimeoutException$e){
throw new ResponseTimeoutException('Timed out while transferring the response body',$request,$response,$e
);
}catch(\OverflowException$e){
throw new ResponseException($e->getMessage(),$request,$response,$e);
}catch(\Exception$e){
throw new ResponseTransferException($e->getMessage()!==''?$e->getMessage():'Failed while transferring the response body',$request,$response,$e
);
}
$receivedLength=$encodedBody!==null?$encodedBody->getBytesRead():$copied;
if($declaredLength!==null&&$receivedLength<$declaredLength){
throw new ResponseTransferException('Response body ended before the declared Content-Length was reached',$request,$response
);
}
try{
if($sink->isSeekable()){
$sink->rewind();
}
}catch(\Exception$e){
throw new ResponseException($e->getMessage()!==''?$e->getMessage():'Failed to rewind the response body',$request,$response,$e
);
}
return$sink;
}finally{
try{
$source->close();
}catch(\Exception$e){
}
}
}
private function createResponseSink(RequestInterface$request,ResponseInterface$response,StreamInterface$sink
):StreamInterface{
return Psr7\FnStream::decorate($sink,['close'=>static function():void{
},'write'=>static function(string$data)use($request,$response,$sink):int{
try{
$written=$sink->write($data);
}catch(TimeoutException$e){
throw new ResponseException('Timed out while writing the response body',$request,$response,$e
);
}catch(\Exception$e){
throw new ResponseException($e->getMessage()!==''?$e->getMessage():'Failed to write the response body',$request,$response,$e
);
}
if($written<=0){
throw new ResponseException('Unable to write to stream',$request,$response);
}
return$written;
},'getMetadata'=>static function(?string$key=null)use($sink){
if($key==='timed_out'){
return false;
}
return$sink->getMetadata($key);
},]);
}
private static function createDeadlineSource(StreamInterface$stream,$resource,float$deadline,#[\SensitiveParameter]array$options
):StreamInterface{
$idleTimeout=isset($options['read_timeout'])?Timeout::toMilliseconds($options['read_timeout'],'read_timeout'):self::DEFAULT_IDLE_TIMEOUT_MS;
\stream_set_blocking($resource,false);
return new DeadlineSourceStream($stream,$deadline,$idleTimeout>0?$idleTimeout/1000:null);
}
private function createResource(callable$callback,#[\SensitiveParameter]?UriInterface$diagnosticUri=null
){
$errors=[];
\set_error_handler(static function(int$_,string$msg,string$file,int$line)use(&$errors):bool{
$errors[]=['message'=>$msg,'file'=>$file,'line'=>$line,];
return true;
});
try{
$resource=$callback();
}finally{
\restore_error_handler();
}
if(!$resource){
$details=[];
foreach($errors as$err){
foreach($err as$key=>$value){
$rendered=$key==='message'&&$diagnosticUri!==null
?UriDiagnostic::redactInMessage((string)$value,$diagnosticUri):Psr7\DiagnosticValue::escape((string)$value);
$details[]=\sprintf('[%s] %s',$key,$rendered);
}
}
$message='Error creating resource';
if($details!==[]){
$message.=': '.\implode('; ',$details);
}
throw new\RuntimeException($message);
}
return$resource;
}
private function createStream(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,string$body,?float&$deadline
){
$callerRequest=$request;
if($request->getProtocolVersion()==='1.1'&&!$request->hasHeader('Connection')){
$request=$request->withHeader('Connection','close');
}
if(!isset($options['verify'])){
$options['verify']=true;
}
$params=[];
$context=$this->getDefaultContext($request,$body);
$customSslContext=[];
if(isset($options['on_headers'])&&!\is_callable($options['on_headers'])){
throw new InvalidArgumentException('on_headers must be callable');
}
$idleTimeout=isset($options['read_timeout'])?Timeout::toMilliseconds($options['read_timeout'],'read_timeout'):self::DEFAULT_IDLE_TIMEOUT_MS;
$timeout=isset($options['timeout'])?Timeout::toMilliseconds($options['timeout'],'timeout'):0;
self::assertTlsVersionRangeForOptions($request,$options);
$this->applyHandlerOptions($request,$context,$options,$params);
$this->applyProxy($request,$context,$options['proxy']??null);
if(isset($options['stream_context'])){
$streamContext=$options['stream_context'];
if(!\is_array($streamContext)){
throw new InvalidArgumentException('stream_context must be an array');
}
self::rejectConflictingStreamContextOptions($streamContext);
self::rejectUnsupportedStreamContextOptions($streamContext);
$context=\array_replace_recursive($context,$streamContext);
$sslContext=$streamContext['ssl']??null;
if(\is_array($sslContext)){
$customSslContext=$sslContext;
}
}
$this->addDefaultTlsMinimum($request,$context);
$commitTlsSessions=$this->applyTlsSessionResumption($request,$context,$customSslContext);
if($timeout>0&&($idleTimeout<=0||$timeout<$idleTimeout)){
$context['http']['timeout']=$timeout/1000;
}elseif($idleTimeout>0){
$context['http']['timeout']=$idleTimeout/1000;
}else{
$context['http']['timeout']=-1;
}
$streamErrorCodes=[];
$captureStreamErrors=true;
$this->addStructuredStreamErrorHandler($context,$streamErrorCodes,$captureStreamErrors);
$uri=$this->resolveHost($request,$options);
$contextResource=$this->createResource(static function()use($context,$params){
return\stream_context_create($context,$params);
}
);
try{
$resource=$this->createResource(function()use($uri,$contextResource,$idleTimeout,$timeout,&$deadline){
$deadline=$timeout>0?Clock::now()+$timeout/1000:null;
$iniFrom=\function_exists('ini_set')?\ini_set('from',''):false;
try{
$resource=@\fopen((string)$uri,'r',false,$contextResource);
}finally{
if($iniFrom!==false){
\ini_set('from',$iniFrom);
}
}
if(false===$resource){
return false;
}
if($idleTimeout>0){
$sec=\intdiv($idleTimeout,1000);
$usec=($idleTimeout%1000)*1000;
\stream_set_timeout($resource,$sec,$usec);
}else{
\stream_set_timeout($resource,-1);
}
return$resource;
},$uri);
}catch(TransferException$e){
throw$e;
}catch(\RuntimeException$e){
throw self::createStreamFailureException($e->getMessage(),$callerRequest,$e,$streamErrorCodes);
}finally{
$captureStreamErrors=false;
}
if($commitTlsSessions!==null){
$commitTlsSessions();
}
return$resource;
}
private function addStructuredStreamErrorHandler(#[\SensitiveParameter]array&$context,array&$streamErrorCodes,bool&$captureStreamErrors
):void{
if(!self::supportsStructuredStreamErrors()){
return;
}
if(!isset($context['stream'])||!\is_array($context['stream'])){
$context['stream']=[];
}
$context['stream']['error_mode']=\StreamErrorMode::Error;
$context['stream']['error_store']=\StreamErrorStore::None;
$context['stream']['error_handler']=static function(#[\SensitiveParameter]array$errors
)use(&$streamErrorCodes,&$captureStreamErrors):void{
if(!$captureStreamErrors){
return;
}
foreach($errors as$error){
$name=$error->code->name;
if(!\in_array($name,$streamErrorCodes,true)){
$streamErrorCodes[]=$name;
}
}
};
}
private static function supportsStructuredStreamErrors():bool
{
return\PHP_VERSION_ID>=80600&&\class_exists(\StreamError::class,false);
}
private static function assertRequestUriSupported(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):void{
$uri=$request->getUri();
$scheme=$uri->getScheme();
if($scheme===''){
throw new RequestException('URI must include a scheme and host. Use an absolute URI, a network-path reference starting with //, or configure a base_uri.',$request
);
}
if(!\in_array($scheme,['http','https'],true)){
throw new RequestException(\sprintf("The scheme '%s' is not supported.",Psr7\DiagnosticValue::escape($scheme)),$request);
}
$protocols=Utils::normalizeProtocols($options['protocols']??['http','https']);
if(!\in_array($scheme,$protocols,true)){
throw new RequestException(\sprintf('The scheme "%s" is not allowed by the protocols request option.',Psr7\DiagnosticValue::escape($scheme)),$request);
}
if($uri->getHost()===''){
throw new RequestException('URI must include a scheme and host. Use an absolute URI, a network-path reference starting with //, or configure a base_uri.',$request
);
}
HostValidator::assertRequestHost($request);
}
private function applyHandlerOptions(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$context,#[\SensitiveParameter]array$options,array&$params
):void{
foreach($options as$key=>$value){
if($key==='crypto_method'){
$this->applyCryptoMethodOption($context,$value);
}elseif($key==='crypto_method_max'){
$this->applyCryptoMethodMaxOption($context,$value);
}elseif($key==='verify'){
$this->applyVerifyOption($context,$value);
}elseif($key==='cert'){
$this->applyCertOption($context,$value);
}elseif($key==='cert_type'){
$this->applyCertTypeOption($value);
}elseif($key==='ssl_key'){
$this->applySslKeyOption($context,$value);
}elseif($key==='ssl_key_type'){
$this->applySslKeyTypeOption($value);
}elseif($key==='progress'){
$this->applyProgressOption($value,$params);
}elseif($key==='debug'){
$this->applyDebugOption($request,$value,$params);
}
}
}
private function resolveHost(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):UriInterface{
$uri=$request->getUri();
$host=$uri->getHost();
$canonicalHost=self::canonicalConnectionHost($host);
if($canonicalHost!==$host){
$uri=$uri->withHost($canonicalHost);
$host=$canonicalHost;
}
$hostForIpCheck=\str_starts_with($host,'[')&&\str_ends_with($host,']')?\substr($host,1,-1):$host;
if(isset($options['force_ip_resolve'])&&!\filter_var($hostForIpCheck,\FILTER_VALIDATE_IP)){
if('v4'===$options['force_ip_resolve']){
$records=\dns_get_record($uri->getHost(),\DNS_A);
if(false===$records||!isset($records[0]['ip'])){
throw new ConnectException(\sprintf("Could not resolve IPv4 address for host '%s'",Psr7\DiagnosticValue::escape($uri->getHost())),$request);
}
return$uri->withHost($records[0]['ip']);
}
if('v6'===$options['force_ip_resolve']){
$records=\dns_get_record($uri->getHost(),\DNS_AAAA);
if(false===$records||!isset($records[0]['ipv6'])){
throw new ConnectException(\sprintf("Could not resolve IPv6 address for host '%s'",Psr7\DiagnosticValue::escape($uri->getHost())),$request);
}
return$uri->withHost('['.$records[0]['ipv6'].']');
}
}
return$uri;
}
private static function canonicalConnectionHost(string$host):string
{
$binary=HostIdentity::numericIpv4ToBinary($host);
if($binary===null){
return$host;
}
return(string)\inet_ntop($binary);
}
private function addDefaultTlsMinimum(RequestInterface$request,array&$context):void
{
if('https'!==$request->getUri()->getScheme()||!isset($context['ssl'])||!\is_array($context['ssl'])){
return;
}
if(\array_key_exists('crypto_method',$context['ssl'])||\array_key_exists('min_proto_version',$context['ssl'])){
return;
}
$context['ssl']['min_proto_version']=\STREAM_CRYPTO_PROTO_TLSv1_2;
}
private function applyTlsSessionResumption(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$context,#[\SensitiveParameter]array$customSslContext=[]):?\Closure{
if(!$this->transportSharingRequested()){
return;
}
$uri=$request->getUri();
if('https'!==$uri->getScheme()){
$this->failRequiredTlsSharingForRequest($request,'handler-lifetime TLS session sharing only applies to HTTPS requests.');
return;
}
$host=$uri->getHost();
$proxy=$context['http']['proxy']??null;
if(\is_string($proxy)&&ProxyOptions::proxyScheme($proxy)!=='tcp'){
$this->failRequiredTlsSharingForRequest($request,'the proxy uses a TLS stream transport, which would mix proxy and origin TLS session state.');
return;
}
if(!isset($context['ssl'])||!\is_array($context['ssl'])){
$this->failRequiredTlsSharingForConfiguration('the final stream SSL context is not an array.');
return;
}
$unsupported=StreamTlsSessionCache::unsupportedContextReason($context['ssl'],$customSslContext);
if($unsupported!==null){
$this->failRequiredTlsSharingForConfiguration($unsupported);
return;
}
$cache=$this->sessionCache();
if($cache===null){
$this->failRequiredTlsSharingForConfiguration('PHP 8.6+ with the OpenSSL session API is required.');
return;
}
$key=StreamTlsSessionCache::peerKey(self::canonicalConnectionHost($host),$uri->getPort()??443,$context['ssl']);
$credentials=StreamTlsSessionCache::credentialFingerprint($context['ssl']);
$session=$cache->find($key,$credentials);
if($session!==null){
$context['ssl']['session_data']=$session;
}
$accepted=false;
$staged=[];
$context['ssl']['session_new_cb']=static function(#[\SensitiveParameter]$stream,#[\SensitiveParameter]Session$session
)use($cache,$key,$credentials,&$accepted,&$staged):void{
if($accepted){
$cache->store($key,$credentials,$session);
return;
}
if(\count($staged)>=StreamTlsSessionCache::MAX_SESSIONS_PER_KEY){
\array_shift($staged);
}
$staged[]=$session;
};
return static function()use($cache,$key,$credentials,&$accepted,&$staged):void{
$accepted=true;
foreach($staged as$session){
$cache->store($key,$credentials,$session);
}
$staged=[];
};
}
private function transportSharingRequested():bool
{
return$this->transportSharingMode!==TransportSharing::NONE
&&$this->transportSharingMode!==TransportSharing::PERSISTENT_REQUIRE;
}
private function transportSharingRequired():bool
{
return$this->transportSharingMode===TransportSharing::HANDLER_REQUIRE;
}
private function failRequiredTlsSharingForRequest(#[\SensitiveParameter]RequestInterface$request,string$reason
):void{
if($this->transportSharingRequired()){
throw new RequestException('The "transport_sharing" option requires stream handler TLS session sharing, but '.$reason,$request);
}
}
private function failRequiredTlsSharingForConfiguration(string$reason):void
{
if($this->transportSharingRequired()){
throw new InvalidArgumentException('The "transport_sharing" option requires stream handler TLS session sharing, but '.$reason);
}
}
private function sessionCache():?StreamTlsSessionCache
{
if(!$this->transportSharingRequested()||!StreamTlsSessionCache::isSupported()){
return;
}
return$this->sessionCache??($this->sessionCache=new StreamTlsSessionCache(self::TLS_SESSION_CACHE_MAX_KEYS));
}
private function getDefaultContext(#[\SensitiveParameter]RequestInterface$request,string$body
):array{
$headers='';
foreach($request->getHeaders()as$name=>$value){
if(Psr7\Utils::caselessEquals((string)$name,'Proxy-Authorization')){
continue;
}
foreach($value as$val){
$headers.="$name: $val\r\n";
}
}
$context=['http'=>['auto_decode'=>false,'method'=>$request->getMethod(),'header'=>$headers,'protocol_version'=>$request->getProtocolVersion(),'ignore_errors'=>true,'follow_location'=>0,],'ssl'=>['peer_name'=>self::canonicalConnectionHost($request->getUri()->getHost()),],];
if(!$request->hasHeader('User-Agent')){
$context['http']['user_agent']='';
}
if(''!==$body){
$context['http']['content']=$body;
if(!$request->hasHeader('Content-Type')){
$context['http']['header'].="Content-Type:\r\n";
}
}
$context['http']['header']=\rtrim($context['http']['header'],"\r\n");
return$context;
}
private function assertTransportSharingSupported():void
{
if($this->transportSharingMode===TransportSharing::PERSISTENT_REQUIRE){
throw new InvalidArgumentException('The "transport_sharing" option requires persistent transport sharing, which is only available through cURL share handles. The stream handler can only share handler-lifetime TLS sessions.');
}
if($this->transportSharingMode===TransportSharing::HANDLER_REQUIRE&&!StreamTlsSessionCache::isSupported()){
throw new InvalidArgumentException('The "transport_sharing" option requires handler-lifetime transport sharing, but the stream handler only supports it through TLS session resumption on PHP 8.6+ with the OpenSSL session API.');
}
}
private static function rejectUnsupportedRequestOptions(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):void{
if(\array_key_exists('curl',$options)&&$options['curl']!==null
&&$options['curl']!==[]){
throw new InvalidArgumentException('Passing the "curl" request option to the stream handler is not supported because the stream handler ignores cURL options.');
}
if(\array_key_exists('expect',$options)&&$options['expect']!==false&&$request->hasHeader('Expect')){
throw new InvalidArgumentException('Passing the "expect" request option to the stream handler is not supported when it adds an Expect header because the stream handler does not support Expect: 100-Continue.');
}
if(isset($options['on_trailers'])){
throw new InvalidArgumentException('Passing the "on_trailers" request option to the stream handler is not supported because the stream handler cannot observe trailers.');
}
}
private function rejectStreamingWithConnectionCaps(#[\SensitiveParameter]array$options
):void{
if($this->connectionCapsConfigured&&!empty($options['stream'])){
throw new InvalidArgumentException('Enabling the "stream" request option on a stream handler configured with the "max_host_connections" or "max_total_connections" option is not supported because streamed connections cannot be capped.');
}
}
private static function rejectConflictingStreamContextOptions(#[\SensitiveParameter]array$streamContext
):void{
$conflictingOptions=self::conflictingStreamContextOptions();
foreach($streamContext as$wrapper=>$contextOptions){
if(!\is_string($wrapper)||!isset($conflictingOptions[$wrapper])||!\is_array($contextOptions)){
continue;
}
foreach($contextOptions as$option=>$_){
if(!\is_string($option)||!\array_key_exists($option,$conflictingOptions[$wrapper])){
continue;
}
$replacement=$conflictingOptions[$wrapper][$option];
throw new InvalidArgumentException(\sprintf('Passing stream_context.%s.%s in the "stream_context" request option is not supported because it conflicts with Guzzle-managed request handling. Use %s instead.',Psr7\DiagnosticValue::escape($wrapper),Psr7\DiagnosticValue::escape($option),$replacement
));
}
}
}
private static function rejectUnsupportedStreamContextOptions(#[\SensitiveParameter]array$streamContext
):void{
$unsupportedOptions=self::unsupportedStreamContextOptions($streamContext);
if($unsupportedOptions===[]){
return;
}
throw new InvalidArgumentException(\sprintf('Passing PHP stream context options outside the built-in stream handler allow-list to the "stream_context" request option is not supported. Unsupported option%s: %s.',\count($unsupportedOptions)===1?'':'s',\implode(', ',$unsupportedOptions)));
}
private static function unsupportedStreamContextOptions(array$streamContext):array
{
$supportedOptions=self::supportedStreamContextOptions();
$conflictingOptions=self::conflictingStreamContextOptions();
$unsupportedOptions=[];
foreach($streamContext as$wrapper=>$contextOptions){
if(!\is_string($wrapper)||!isset($supportedOptions[$wrapper])){
if(\is_array($contextOptions)){
foreach($contextOptions as$option=>$_){
if(\is_string($wrapper)&&\is_string($option)&&isset($conflictingOptions[$wrapper])&&\array_key_exists($option,$conflictingOptions[$wrapper])){
continue;
}
$unsupportedOptions[]=\sprintf('stream_context.%s.%s',Psr7\DiagnosticValue::escape((string)$wrapper),Psr7\DiagnosticValue::escape((string)$option));
}
}else{
$unsupportedOptions[]=\sprintf('stream_context.%s',Psr7\DiagnosticValue::escape((string)$wrapper));
}
continue;
}
if(!\is_array($contextOptions)){
$unsupportedOptions[]=\sprintf('stream_context.%s',Psr7\DiagnosticValue::escape($wrapper));
continue;
}
foreach($contextOptions as$option=>$_){
if(\is_string($option)&&isset($conflictingOptions[$wrapper])&&\array_key_exists($option,$conflictingOptions[$wrapper])){
continue;
}
if(!\is_string($option)||!\array_key_exists($option,$supportedOptions[$wrapper])){
$unsupportedOptions[]=\sprintf('stream_context.%s.%s',Psr7\DiagnosticValue::escape($wrapper),Psr7\DiagnosticValue::escape((string)$option));
}
}
}
return$unsupportedOptions;
}
private static function supportedStreamContextOptions():array
{
return['http'=>['request_fulluri'=>true,],'socket'=>['bindto'=>true,'tcp_nodelay'=>true,],'ssl'=>['SNI_enabled'=>true,'capture_peer_cert'=>true,'capture_peer_cert_chain'=>true,'ciphers'=>true,'disable_compression'=>true,'no_ticket'=>true,'peer_fingerprint'=>true,'security_level'=>true,'verify_depth'=>true,],];
}
private static function conflictingStreamContextOptions():array
{
return['http'=>['auto_decode'=>'Guzzle response framing and decoding','content'=>'the request body','follow_location'=>'the "allow_redirects" request option','header'=>'the request headers','max_redirects'=>'the "allow_redirects" request option','method'=>'the request method','protocol_version'=>'the request protocol version','proxy'=>'the "proxy" request option','timeout'=>'the "timeout" and "read_timeout" request options',],'ssl'=>['allow_self_signed'=>'the "verify" request option','cafile'=>'the "verify" request option','capath'=>'the "verify" request option','crypto_method'=>'the "crypto_method" request option','local_cert'=>'the "cert" request option','local_pk'=>'the "ssl_key" request option','max_proto_version'=>'the "crypto_method_max" request option','min_proto_version'=>'the "crypto_method" request option','passphrase'=>'the "cert" or "ssl_key" request option','peer_name'=>'the request URI','verify_peer'=>'the "verify" request option','verify_peer_name'=>'the "verify" request option',],'stream'=>['error_handler'=>'Guzzle stream error handling','error_mode'=>'Guzzle stream error handling','error_store'=>'Guzzle stream error handling',],];
}
private static function normalizeTlsFileOption(string$option,#[\SensitiveParameter]$value
):array{
$passphrase=null;
if(\is_array($value)){
if(!isset($value[0])||!\is_string($value[0])){
throw new InvalidArgumentException(\sprintf('Invalid %s request option',$option));
}
if(isset($value[1])){
if(!\is_string($value[1])){
throw new InvalidArgumentException(\sprintf('Invalid %s request option',$option));
}
$passphrase=$value[1];
}
$value=$value[0];
}
if(!\is_string($value)){
throw new InvalidArgumentException(\sprintf('Invalid %s request option',$option));
}
return[$value,$passphrase];
}
private static function setTlsPassphrase(#[\SensitiveParameter]array&$options,#[\SensitiveParameter]?string$passphrase,string$option
):void{
if($passphrase===null){
return;
}
if(isset($options['ssl']['passphrase'])&&$options['ssl']['passphrase']!==$passphrase){
throw new InvalidArgumentException(\sprintf('Cannot use different passphrases for cert and ssl_key with the stream handler; %s conflicts with an existing TLS passphrase.',$option));
}
$options['ssl']['passphrase']=$passphrase;
}
private static function assertStreamTlsType(string$option,$value):void
{
if(!\is_string($value)||$value===''){
throw new InvalidArgumentException(\sprintf('%s must be a non-empty string',$option));
}
if(Psr7\Utils::asciiToUpper($value)!=='PEM'){
throw new InvalidArgumentException(\sprintf('The stream handler only supports "PEM" for the %s request option.',$option));
}
}
private function applyProxy(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array&$context,#[\SensitiveParameter]$value
):void{
$proxy=ProxyEnv::resolveProxySelection($request->getUri(),$value);
$proxyUri=$proxy->getProxy();
if($proxyUri===null){
return;
}
$scheme=ProxyOptions::proxyScheme($proxyUri);
if($scheme==='https'){
throw new InvalidArgumentException('HTTPS proxies are not supported by the stream handler.');
}
if(\in_array($scheme,['socks4','socks4a','socks5','socks5h'],true)){
throw new InvalidArgumentException('SOCKS proxies are not supported by the stream handler.');
}
if($scheme!=='http'&&!self::isRawTransportName($scheme)){
throw new InvalidArgumentException(\sprintf('The "%s" proxy scheme is not supported by the stream handler.',Psr7\DiagnosticValue::escape($scheme)));
}
if(!\in_array($scheme,['http','tcp'],true)&&!\in_array($scheme,\stream_get_transports(),true)){
throw new RequestException(\sprintf('The "%s" proxy transport is not available in this PHP build.',Psr7\DiagnosticValue::escape($scheme)),$request);
}
$parsed=$this->parseProxy($proxyUri,$scheme);
if($request->hasHeader('Proxy-Authorization')){
throw new InvalidArgumentException('Proxy-Authorization request headers are not supported through the stream handler; configure credentials in the proxy URI or use a cURL handler.');
}
$context['http']['proxy']=$parsed['proxy'];
if($parsed['auth']){
if(!isset($context['http']['header'])){
$context['http']['header']='';
}
$context['http']['header'].="\r\nProxy-Authorization: {$parsed['auth']}";
}
}
private static function isRawTransportName(string$scheme):bool
{
return\in_array($scheme,['tcp','ssl','tls'],true)||\preg_match('/^tlsv\d+(?:\.\d+)?$/D',$scheme)===1;
}
private function parseProxy(string$url,string$scheme):array
{
if($scheme!=='http'){
return['proxy'=>$url,'auth'=>null,];
}
$parsed=\parse_url(\strpos($url,'://')===false?'http://'.$url:$url);
if(\is_array($parsed)&&isset($parsed['host'])){
$port=$parsed['port']??1080;
$user=$parsed['user']??'';
$pass=$parsed['pass']??'';
$auth=($user!==''||$pass!=='')?'Basic '.\base64_encode("{$user}:{$pass}"):null;
return['proxy'=>"tcp://{$parsed['host']}:{$port}",'auth'=>$auth,];
}
return['proxy'=>$url,'auth'=>null,];
}
private function applyCryptoMethodOption(#[\SensitiveParameter]array&$context,$value
):void{
$context['ssl']['min_proto_version']=TlsVersion::streamProtocolVersion('crypto_method',$value);
}
private function applyCryptoMethodMaxOption(#[\SensitiveParameter]array&$context,$value
):void{
$context['ssl']['max_proto_version']=TlsVersion::streamProtocolVersion('crypto_method_max',$value);
}
private static function assertTlsVersionRangeForOptions(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):void{
if(!isset($options['crypto_method_max'])){
return;
}
$cryptoMethod=$options['crypto_method']??null;
if($cryptoMethod===null&&'https'===$request->getUri()->getScheme()){
$cryptoMethod=\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
}
TlsVersion::assertRange($cryptoMethod,$options['crypto_method_max']);
}
private function applyVerifyOption(#[\SensitiveParameter]array&$context,$value
):void{
if($value===false){
$context['ssl']['verify_peer']=false;
$context['ssl']['verify_peer_name']=false;
return;
}
if(\is_string($value)){
$context['ssl']['cafile']=$value;
if(!\file_exists($value)){
throw new\RuntimeException(\sprintf('SSL CA bundle not found: %s',Psr7\DiagnosticValue::escape($value)));
}
}elseif($value!==true){
throw new InvalidArgumentException('Invalid verify request option');
}
$context['ssl']['verify_peer']=true;
$context['ssl']['verify_peer_name']=true;
$context['ssl']['allow_self_signed']=false;
}
private function applyCertOption(#[\SensitiveParameter]array&$context,#[\SensitiveParameter]$value
):void{
[$value,$passphrase]=self::normalizeTlsFileOption('cert',$value);
if(!\file_exists($value)){
throw new\RuntimeException(\sprintf('SSL certificate not found: %s',Psr7\DiagnosticValue::escape($value)));
}
self::setTlsPassphrase($context,$passphrase,'cert');
$context['ssl']['local_cert']=$value;
}
private function applyCertTypeOption($value):void
{
self::assertStreamTlsType('cert_type',$value);
}
private function applySslKeyOption(#[\SensitiveParameter]array&$context,#[\SensitiveParameter]$value
):void{
[$value,$passphrase]=self::normalizeTlsFileOption('ssl_key',$value);
if(!\file_exists($value)){
throw new\RuntimeException(\sprintf('SSL private key not found: %s',Psr7\DiagnosticValue::escape($value)));
}
self::setTlsPassphrase($context,$passphrase,'ssl_key');
$context['ssl']['local_pk']=$value;
}
private function applySslKeyTypeOption($value):void
{
self::assertStreamTlsType('ssl_key_type',$value);
}
private function applyProgressOption($value,array&$params):void
{
if(!\is_callable($value)){
throw new InvalidArgumentException('progress client option must be callable');
}
self::addNotification($params,static function($code,$a,$b,$c,$transferred,$total)use($value):void{
if($code==\STREAM_NOTIFY_PROGRESS){
$value(TransferByteCounter::progressValueToInt($total),TransferByteCounter::progressValueToInt($transferred),0,0
);
}
}
);
}
private function applyDebugOption(#[\SensitiveParameter]RequestInterface$request,$value,array&$params
):void{
if($value===false){
return;
}
static$map=[\STREAM_NOTIFY_CONNECT=>'CONNECT',\STREAM_NOTIFY_AUTH_REQUIRED=>'AUTH_REQUIRED',\STREAM_NOTIFY_AUTH_RESULT=>'AUTH_RESULT',\STREAM_NOTIFY_MIME_TYPE_IS=>'MIME_TYPE_IS',\STREAM_NOTIFY_FILE_SIZE_IS=>'FILE_SIZE_IS',\STREAM_NOTIFY_REDIRECTED=>'REDIRECTED',\STREAM_NOTIFY_PROGRESS=>'PROGRESS',\STREAM_NOTIFY_FAILURE=>'FAILURE',\STREAM_NOTIFY_COMPLETED=>'COMPLETED',\STREAM_NOTIFY_RESOLVE=>'RESOLVE',];
static$args=['severity','message','message_code','bytes_transferred','bytes_max'];
$value=Utils::debugResource($value);
$ident=$request->getMethod().' '.$request->getUri()->withFragment('');
self::addNotification($params,static function(int$code,...$passed)use($ident,$value,$map,$args):void{
\fprintf($value,'<%s> [%s] ',$ident,$map[$code]);
foreach(\array_filter($passed)as$i=>$v){
\fwrite($value,$args[$i].': "'.$v.'" ');
}
\fwrite($value,"\n");
}
);
}
private static function addNotification(array&$params,callable$notify):void
{
if(!isset($params['notification'])){
$params['notification']=$notify;
}else{
$params['notification']=self::callArray([$params['notification'],$notify,]);
}
}
private static function callArray(array$functions):callable
{
return static function(...$args)use($functions):void{
foreach($functions as$fn){
$fn(...$args);
}
};
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\HostIdentity;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7;
use Openssl\Session;
final class StreamTlsSessionCache
{
use NonSerializableTrait;
const MAX_SESSIONS_PER_KEY=2;
private const MAX_TLS13_LIFETIME=604800;
private const MAX_PRE_TLS13_LIFETIME=86400;
private const USER_MANAGED_SESSION_OPTIONS=['session_cache'=>true,'session_cache_size'=>true,'session_data'=>true,'session_get_cb'=>true,'session_id_context'=>true,'session_new_cb'=>true,'session_remove_cb'=>true,'session_stream'=>true,'session_timeout'=>true,];
private const USER_MANAGED_PSK_OPTIONS=['psk_client_cb'=>true,'psk_server_cb'=>true,];
private const USER_MANAGED_EARLY_DATA_OPTIONS=['early_data'=>true,'early_data_cb'=>true,'max_early_data'=>true,];
private const PATH_OPTIONS=['SNI_server_certs'=>true,'cafile'=>true,'capath'=>true,'dh_param'=>true,'local_cert'=>true,'local_pk'=>true,];
private const CERT_CAPTURE_OPTIONS=['capture_peer_cert'=>true,'capture_peer_cert_chain'=>true,];
private const CUSTOM_SCALAR_KEYABLE_OPTIONS=['SNI_enabled'=>true,'allow_self_signed'=>true,'alpn_protocols'=>true,'ciphers'=>true,'crypto_method'=>true,'disable_compression'=>true,'max_proto_version'=>true,'min_proto_version'=>true,'peer_name'=>true,'security_level'=>true,'verify_depth'=>true,'verify_peer'=>true,'verify_peer_name'=>true,];
private const INVALID_PEER_FINGERPRINT_REASON='the SSL context option "peer_fingerprint" must be a string or a non-empty, flat array with string algorithm names and string fingerprints.';
private int$maxKeys;
private array$sessions=[];
function __construct(int$maxKeys){
if($maxKeys<1){
throw new InvalidArgumentException('maxKeys must be a positive integer.');
}
$this->maxKeys=$maxKeys;
}
static function isSupported():bool
{
return\PHP_VERSION_ID>=80600&&\class_exists(Session::class,false);
}
static function unsupportedContextReason(array$ssl,array$customSsl=[]):?string
{
foreach($customSsl as$key=>$value){
if(!isset(self::CUSTOM_SCALAR_KEYABLE_OPTIONS[$key])&&!isset(self::PATH_OPTIONS[$key])&&!isset(self::USER_MANAGED_SESSION_OPTIONS[$key])&&!isset(self::USER_MANAGED_PSK_OPTIONS[$key])&&!isset(self::USER_MANAGED_EARLY_DATA_OPTIONS[$key])&&!isset(self::CERT_CAPTURE_OPTIONS[$key])&&$key!=='no_ticket'&&$key!=='peer_fingerprint'){
return\sprintf('the custom SSL context option "%s" is not known to be safe for TLS session sharing.',Psr7\DiagnosticValue::escape((string)$key));
}
}
foreach($ssl as$key=>$value){
if(isset(self::PATH_OPTIONS[$key])){
return\sprintf('the SSL context option "%s" uses file or path state that cannot be safely shared.',Psr7\DiagnosticValue::escape((string)$key));
}
if(isset(self::USER_MANAGED_SESSION_OPTIONS[$key])){
return\sprintf('the SSL context option "%s" is user-managed TLS session state.',Psr7\DiagnosticValue::escape((string)$key));
}
if(isset(self::USER_MANAGED_PSK_OPTIONS[$key])){
return\sprintf('the SSL context option "%s" is user-managed TLS PSK state.',Psr7\DiagnosticValue::escape((string)$key));
}
if(isset(self::USER_MANAGED_EARLY_DATA_OPTIONS[$key])){
return\sprintf('the SSL context option "%s" is user-managed TLS early data state.',Psr7\DiagnosticValue::escape((string)$key));
}
if(isset(self::CERT_CAPTURE_OPTIONS[$key])&&$value){
return\sprintf('the SSL context option "%s" requires a fresh peer certificate handshake.',Psr7\DiagnosticValue::escape((string)$key));
}
if($key==='no_ticket'&&$value){
return'the SSL context option "no_ticket" disables TLS ticket sharing.';
}
if($key==='peer_fingerprint'){
if(!self::isPeerFingerprint($value)){
return self::INVALID_PEER_FINGERPRINT_REASON;
}
continue;
}
if(!self::isCanonicalScalar($value)){
return\sprintf('the SSL context option "%s" cannot be safely included in the TLS session cache identity.',Psr7\DiagnosticValue::escape((string)$key));
}
}
return;
}
static function peerKey(string$host,?int$port,#[\SensitiveParameter]array$ssl
):string{
$identity=['schema'=>'guzzle-stream-tls-session-v1','runtime'=>self::runtimeIdentity(),'peer'=>['host'=>self::canonicalHost($host),'port'=>$port,],'ssl'=>self::canonicalPeerSslContext($ssl),];
return\hash('sha256',\serialize($identity));
}
static function credentialFingerprint(array$ssl):string
{
$material=['local_cert'=>isset($ssl['local_cert'])&&\is_string($ssl['local_cert'])?self::pathIdentity($ssl['local_cert']):null,'local_pk'=>isset($ssl['local_pk'])&&\is_string($ssl['local_pk'])?self::pathIdentity($ssl['local_pk']):null,'passphrase'=>isset($ssl['passphrase'])&&\is_string($ssl['passphrase'])?$ssl['passphrase']:null,];
return\hash('sha256',\serialize($material));
}
function find(string$key,string$credentials):?Session
{
if(!isset($this->sessions[$key])){
return;
}
$now=\time();
$entries=$this->sessions[$key];
$found=null;
foreach($entries as$i=>$entry){
if($entry['expiresAt']<=$now){
unset($entries[$i]);
continue;
}
if(!\hash_equals($entry['credentials'],$credentials)){
continue;
}
if(!$entry['session']->isResumable()){
unset($entries[$i]);
continue;
}
$found=$entry['session'];
if($entry['singleUse']){
unset($entries[$i]);
}
break;
}
if($entries===[]){
unset($this->sessions[$key]);
}else{
$this->sessions[$key]=\array_values($entries);
if($found!==null){
$this->touch($key);
}
}
return$found;
}
function store(string$key,string$credentials,#[\SensitiveParameter]Session$session
):void{
if(!$session->isResumable()){
return;
}
$expiresAt=self::expiry($session);
if($expiresAt===null){
return;
}
$list=$this->sessions[$key]??[];
$list[]=['session'=>$session,'credentials'=>$credentials,'expiresAt'=>$expiresAt,'singleUse'=>self::isTls13($session),];
if(\count($list)>self::MAX_SESSIONS_PER_KEY){
$list=\array_slice($list,-self::MAX_SESSIONS_PER_KEY);
}
$this->sessions[$key]=$list;
$this->touch($key);
$this->evictExcessKeys();
}
private function touch(string$key):void
{
if(!isset($this->sessions[$key])){
return;
}
$value=$this->sessions[$key];
unset($this->sessions[$key]);
$this->sessions[$key]=$value;
}
private function evictExcessKeys():void
{
while(\count($this->sessions)>$this->maxKeys){
\array_shift($this->sessions);
}
}
private static function isTls13(#[\SensitiveParameter]Session$session
):bool{
$protocol=$session->getProtocol();
return$protocol!==null&&Psr7\Utils::caselessContains($protocol,'1.3');
}
private static function expiry(#[\SensitiveParameter]Session$session
):?int{
return self::expiryFromLifetimes(self::isTls13($session),$session->hasTicket(),$session->getTicketLifetimeHint(),$session->getTimeout(),$session->getCreatedAt(),\time());
}
private static function expiryFromLifetimes(bool$isTls13,bool$hasTicket,?int$ticketLifetimeHint,int$timeout,int$createdAt,int$now):?int
{
if($timeout<=0){
return;
}
$lifetime=\min($timeout,$isTls13?self::MAX_TLS13_LIFETIME:self::MAX_PRE_TLS13_LIFETIME);
if($isTls13){
if(!$hasTicket||$ticketLifetimeHint===null||$ticketLifetimeHint<=0){
return;
}
$lifetime=\min($lifetime,$ticketLifetimeHint);
}elseif($hasTicket&&$ticketLifetimeHint!==null&&$ticketLifetimeHint>0){
$lifetime=\min($lifetime,$ticketLifetimeHint);
}
$expiresAt=$createdAt+$lifetime;
return$expiresAt>$now?$expiresAt:null;
}
private static function runtimeIdentity():array
{
return['php'=>\PHP_VERSION_ID,'openssl'=>\defined('OPENSSL_VERSION_NUMBER')?\OPENSSL_VERSION_NUMBER:null,'trust'=>['openssl.cafile'=>(string)\ini_get('openssl.cafile'),'openssl.capath'=>(string)\ini_get('openssl.capath'),'SSL_CERT_FILE'=>(string)\getenv('SSL_CERT_FILE'),'SSL_CERT_DIR'=>(string)\getenv('SSL_CERT_DIR'),'cwd'=>\getcwd(),],];
}
private static function canonicalHost(string$host):string
{
if(!Psr7\Rfc3986::isValidHost($host)){
throw new InvalidArgumentException('Hosts used in the TLS session cache identity must be valid RFC 3986 hosts.');
}
return HostIdentity::canonicalHost($host);
}
private static function canonicalPeerSslContext(#[\SensitiveParameter]array$ssl
):array{
$context=[];
foreach($ssl as$key=>$value){
if(isset(self::USER_MANAGED_SESSION_OPTIONS[$key])||isset(self::USER_MANAGED_PSK_OPTIONS[$key])||isset(self::USER_MANAGED_EARLY_DATA_OPTIONS[$key])||$key==='passphrase'){
continue;
}
if($key==='peer_name'&&\is_string($value)){
$context[$key]=['string',self::canonicalHost($value)];
continue;
}
if($key==='peer_fingerprint'){
$context[$key]=self::canonicalPeerFingerprint($value);
continue;
}
if(\in_array($key,['cafile','capath','local_cert','local_pk'],true)&&\is_string($value)){
$context[$key]=self::pathIdentity($value);
continue;
}
$context[$key]=self::canonicalScalar($value);
}
\ksort($context);
return$context;
}
private static function pathIdentity(string$path):array
{
$realPath=\realpath($path);
return['path',$realPath!==false?$realPath:$path,];
}
private static function isCanonicalScalar($value):bool
{
return$value===null
||\is_bool($value)||\is_int($value)||\is_float($value)||\is_string($value);
}
private static function isPeerFingerprint($value):bool
{
if(\is_string($value)){
return true;
}
if(!\is_array($value)||$value===[]){
return false;
}
foreach($value as$algorithm=>$fingerprint){
if(!\is_string($algorithm)||!\is_string($fingerprint)){
return false;
}
}
return true;
}
private static function canonicalScalar($value):array
{
if($value===null){
return['null',null];
}
if(\is_bool($value)){
return['bool',$value];
}
if(\is_int($value)){
return['int',$value];
}
if(\is_float($value)){
return['float',\bin2hex(\pack('E',$value))];
}
if(\is_string($value)){
return['string',$value];
}
throw new InvalidArgumentException('SSL context values used in the TLS session cache identity must be scalar or null.');
}
private static function canonicalPeerFingerprint($value):array
{
if(!self::isPeerFingerprint($value)){
throw new InvalidArgumentException(self::INVALID_PEER_FINGERPRINT_REASON);
}
if(\is_string($value)){
return['string',$value];
}
if(!\is_array($value)){
throw new InvalidArgumentException(self::INVALID_PEER_FINGERPRINT_REASON);
}
$items=[];
foreach($value as$algorithm=>$fingerprint){
$items[$algorithm]=['string',$fingerprint];
}
\ksort($items,\SORT_STRING);
return['map',$items];
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
final class Timeout
{
private function __construct(){
}
static function toMilliseconds($value,string$option):int
{
if(!\is_int($value)&&!\is_float($value)&&(!\is_string($value)||!\is_numeric($value))){
throw new InvalidArgumentException($option.' must be a number of seconds');
}
$seconds=(float)$value;
if(!\is_finite($seconds)||$seconds<0){
throw new InvalidArgumentException($option.' must be 0 or greater than or equal to 0.001 seconds');
}
$milliseconds=(int)($seconds*1000);
if($seconds>0&&$milliseconds===0){
throw new InvalidArgumentException($option.' must be 0 or greater than or equal to 0.001 seconds');
}
return$milliseconds;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Exception\InvalidArgumentException;
final class TlsVersion
{
static function ordinal(string$option,$value):int
{
if($value===\STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT){
return 10;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT){
return 11;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT){
return 12;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT){
return 13;
}
throw new InvalidArgumentException(\sprintf('Invalid %s request option: unknown version provided',$option));
}
static function assertRange($min,$max):void
{
if($min===null||$max===null){
return;
}
if(self::ordinal('crypto_method_max',$max)<self::ordinal('crypto_method',$min)){
throw new InvalidArgumentException('Invalid crypto_method_max request option: maximum TLS version must be greater than or equal to crypto_method');
}
}
static function streamProtocolVersion(string$option,$value):int
{
if($value===\STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT){
return\STREAM_CRYPTO_PROTO_TLSv1_0;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT){
return\STREAM_CRYPTO_PROTO_TLSv1_1;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT){
return\STREAM_CRYPTO_PROTO_TLSv1_2;
}
if($value===\STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT){
return\STREAM_CRYPTO_PROTO_TLSv1_3;
}
throw new InvalidArgumentException(\sprintf('Invalid %s request option: unknown version provided',$option));
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
final class TransferByteCounter
{
private function __construct(){
}
static function progressValueToInt($value):int
{
if(\is_int($value)){
if($value<0){
throw new\OverflowException('Progress byte count exceeds the maximum integer size supported on this platform');
}
return$value;
}
if(!\is_float($value)){
throw new\UnexpectedValueException('Progress byte count must be an integer or float');
}
if(!\is_finite($value)||$value<0
||$value>\PHP_INT_MAX
||(\PHP_INT_SIZE===8&&$value>=(float)\PHP_INT_MAX)){
throw new\OverflowException('Progress byte count exceeds the maximum integer size supported on this platform');
}
$intValue=(int)$value;
if($intValue<0){
throw new\OverflowException('Progress byte count exceeds the maximum integer size supported on this platform');
}
return$intValue;
}
static function add(int$current,int$delta,string$message):int
{
if($current<0||$delta<0){
throw new\OverflowException($message);
}
if($delta>\PHP_INT_MAX-$current){
throw new\OverflowException($message);
}
return$current+$delta;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\NonSerializableTrait;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
final class TransportStream implements StreamInterface
{
use NonSerializableTrait;
use StreamDecoratorTrait;
private StreamInterface$stream;
function __construct(StreamInterface$stream){
$this->stream=$stream;
}
function __clone(){
$this->stream=clone$this->stream;
}
function read(int$length):string
{
$buffered=$this->stream->getMetadata('unread_bytes');
return$this->stream->read(\is_int($buffered)&&$buffered>0?\min($length,$buffered):$length);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Handler;
use GuzzleHttp\Psr7;
use Psr\Http\Message\UriInterface;
final class UriDiagnostic
{
private function __construct(){
}
static function redactInMessage(#[\SensitiveParameter]string$message,#[\SensitiveParameter]UriInterface$uri
):string{
$message=Psr7\Utils::redactUserInfoInString($message,(string)$uri);
$query=$uri->getQuery();
if($query!==''){
$message=\str_replace('?'.$query,'',$message);
}
$fragment=$uri->getFragment();
if($fragment!==''){
$message=\str_replace('#'.$fragment,'',$message);
}
return Psr7\DiagnosticValue::escape($message);
}
}
declare(strict_types=1);
namespace GuzzleHttp;
final class HostIdentity
{
static function canonicalHost(string$host):string
{
if(\str_starts_with($host,'[')&&\str_ends_with($host,']')){
try{
return'['.Psr7\Rfc3986::canonicalizeIpv6(\substr($host,1,-1)).']';
}catch(\InvalidArgumentException$e){
}
}
return Psr7\Utils::asciiToLower($host);
}
static function canonicalCookieDomain(string$domain):string
{
if(!\str_starts_with($domain,'[')&&\strpos($domain,':')!==false){
try{
return Psr7\Rfc3986::canonicalizeIpv6($domain);
}catch(\InvalidArgumentException$e){
return Psr7\Utils::asciiToLower($domain);
}
}
return self::canonicalHost($domain);
}
static function cookieDomainMatches(string$domain,string$cookieDomain):bool
{
$domain=self::canonicalCookieDomain($domain);
$cookieDomain=self::canonicalCookieDomain($cookieDomain);
if($domain===$cookieDomain){
return true;
}
if(\strpos($cookieDomain,'%')!==false){
return false;
}
if(!self::isDnsSuffixEligible($domain)||!self::isDnsSuffixEligible($cookieDomain)){
return false;
}
return\preg_match('/\.'.\preg_quote($cookieDomain,'/').'$/D',$domain)===1;
}
static function canonicalHostHeader(string$header):string
{
if(\str_starts_with($header,'[')){
$end=\strpos($header,']');
if($end!==false){
$rest=\substr($header,$end+1);
if($rest===''||(\str_starts_with($rest,':')&&Psr7\Rfc3986::isValidPort(\substr($rest,1)))){
return self::canonicalHost(\substr($header,0,$end+1)).$rest;
}
}
}
return Psr7\Utils::asciiToLower($header);
}
private static function isDnsSuffixEligible(string$host):bool
{
if(\strpbrk($host,'[]:')!==false){
return false;
}
if(!Psr7\Rfc3986::isValidHost($host)){
return false;
}
return!self::isIpAddressOrNumericHost($host);
}
private static function isIpAddressOrNumericHost(string$host):bool
{
if($host!==''&&\str_ends_with($host,'.')){
$host=\substr($host,0,-1);
}
if(\str_starts_with($host,'[')&&\str_ends_with($host,']')){
$host=\substr($host,1,-1);
}
if(\filter_var($host,\FILTER_VALIDATE_IP)!==false){
return true;
}
$labels=\explode('.',$host);
$last=(string)\end($labels);
if($last!==''&&\ctype_digit($last)){
return true;
}
return\str_starts_with($last,'0x')&&\strlen($last)>2&&\ctype_xdigit(\substr($last,2));
}
static function numericIpv4ToBinary(string$host):?string
{
if(!Handler\HostValidator::isNumericIpv4Host($host)){
return;
}
$values=[];
foreach(\explode('.',$host)as$part){
$values[]=self::numericIpv4PartValue($part);
}
$address=(float)\array_pop($values);
$packed='';
foreach($values as$value){
if($value>255.0){
return;
}
$packed.=\chr((int)$value);
}
$width=4-\count($values);
if($address>=256.0**$width){
return;
}
for($shift=$width-1;$shift>=0;--$shift){
$packed.=\chr((int)\fmod(\floor($address/256.0**$shift),256.0));
}
return$packed;
}
private static function numericIpv4PartValue(string$part):float
{
if($part[0]==='0'&&isset($part[1])&&($part[1]==='x'||$part[1]==='X')){
return self::digitsValue((string)\substr($part,2),16);
}
if($part[0]==='0'){
return self::digitsValue($part,8);
}
return(float)$part;
}
private static function digitsValue(string$digits,int$base):float
{
$value=0.0;
foreach(\str_split($digits)as$digit){
$value=$value*$base+\hexdec($digit);
if($value>4294967295){
break;
}
}
return$value;
}
private function __construct(){
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Exception\InvalidArgumentException;
use Psr\Http\Message\UriInterface;
final class Idn
{
private function __construct(){
}
static function normalizeConversionOption($value):?int
{
if($value===null||$value===false){
return;
}
if($value===true){
return\IDNA_DEFAULT;
}
if(\is_int($value)){
return$value;
}
throw new InvalidArgumentException('idn_conversion must be true, false, null, or an integer IDNA_* bitmask');
}
static function convertUri(UriInterface$uri,int$options=0):UriInterface
{
if($uri->getHost()){
$asciiHost=self::idnToAsci($uri->getHost(),$options,$info);
if($asciiHost===false){
$errorBitSet=$info['errors']??0;
$errorConstants=array_filter(array_keys(get_defined_constants()),static function(string$name):bool{
return substr($name,0,11)==='IDNA_ERROR_';
});
$errors=[];
foreach($errorConstants as$errorConstant){
if($errorBitSet&constant($errorConstant)){
$errors[]=$errorConstant;
}
}
$errorMessage='IDN conversion failed';
if($errors){
$errorMessage.=' (errors: '.join(', ',$errors).')';
}
throw new InvalidArgumentException($errorMessage);
}
if($uri->getHost()!==$asciiHost){
$uri=$uri->withHost($asciiHost);
}
}
return$uri;
}
private static function idnToAsci(string$domain,int$options,?array&$info=[]){
if(\function_exists('idn_to_ascii')&&\defined('INTL_IDNA_VARIANT_UTS46')){
return\idn_to_ascii($domain,$options,\INTL_IDNA_VARIANT_UTS46,$info);
}
throw new\Error('ext-idn or symfony/polyfill-intl-idn not loaded or too old');
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
interface MessageFormatterInterface
{
function format(RequestInterface$request,?ResponseInterface$response=null,?\Throwable$error=null):string;
}
declare(strict_types=1);
namespace GuzzleHttp;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class MessageFormatter implements MessageFormatterInterface
{
const CLF='{hostname} {req_header_User-Agent} - [{date_common_log}] "{method} {target} HTTP/{version}" {code} {res_header_Content-Length}';
const DEBUG=">>>>>>>>\n{request}\n<<<<<<<<\n{response}\n--------\n{error}";
const SHORT='[{ts}] "{method} {target} HTTP/{version}" {code}';
private string$template;
function __construct(?string$template=self::CLF){
$this->template=$template?:self::CLF;
}
function format(RequestInterface$request,?ResponseInterface$response=null,?\Throwable$error=null):string
{
$cache=[];
$result=\preg_replace_callback('/{\s*([A-Za-z_\-\.0-9]+)\s*}/',function(array$matches)use($request,$response,$error,&$cache):string{
if(isset($cache[$matches[1]])){
return$cache[$matches[1]];
}
$result='';
switch($matches[1]){
case'request':$result=Psr7\Message::toString($request);
break;
case'response':$result=$response?Psr7\Message::toString($response):'';
break;
case'req_headers':$result=\trim($request->getMethod().' '.$request->getRequestTarget()," \n\r\t\0\x0B").' HTTP/'.$request->getProtocolVersion()."\r\n".$this->headers($request);
break;
case'res_headers':$result=$response?\sprintf('HTTP/%s %d %s',$response->getProtocolVersion(),$response->getStatusCode(),$response->getReasonPhrase())."\r\n".$this->headers($response):'NULL';
break;
case'req_body':$result=$request->getBody()->__toString();
break;
case'res_body':if(!$response instanceof ResponseInterface){
$result='NULL';
break;
}
$body=$response->getBody();
if(!$body->isSeekable()){
$result='RESPONSE_NOT_LOGGEABLE';
break;
}
$result=$response->getBody()->__toString();
break;
case'ts':case'date_iso_8601':$result=\gmdate('c');
break;
case'date_common_log':$result=\date('d/M/Y:H:i:s O');
break;
case'method':$result=$request->getMethod();
break;
case'version':$result=$request->getProtocolVersion();
break;
case'uri':case'url':$result=$request->getUri()->__toString();
break;
case'target':$result=$request->getRequestTarget();
break;
case'req_version':$result=$request->getProtocolVersion();
break;
case'res_version':$result=$response
?$response->getProtocolVersion():'NULL';
break;
case'host':$result=$request->getHeaderLine('Host');
break;
case'hostname':$result=\gethostname();
break;
case'code':$result=$response?$response->getStatusCode():'NULL';
break;
case'phrase':$result=$response?$response->getReasonPhrase():'NULL';
break;
case'error':$result=$error?$error->getMessage():'NULL';
break;
default:if(\strpos($matches[1],'req_header_')===0){
$result=$request->getHeaderLine(\substr($matches[1],11));
}elseif(\strpos($matches[1],'res_header_')===0){
$result=$response
?$response->getHeaderLine(\substr($matches[1],11)):'NULL';
}
}
$result=(string)$result;
$cache[$matches[1]]=$result;
return$result;
},$this->template
);
if($result===null){
throw new\RuntimeException('Unable to format message: '.\preg_last_error_msg());
}
return$result;
}
private function headers(MessageInterface$message):string
{
$result='';
foreach($message->getHeaders()as$name=>$values){
$result.=$name.': '.\implode(', ',$values)."\r\n";
}
return\trim($result," \n\r\t\0\x0B");
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Cookie\CookieJarInterface;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
final class Middleware
{
private function __construct(){
}
static function auth(bool$reuseChallenges=true):callable
{
return static function(callable$handler)use($reuseChallenges):AuthMiddleware{
return new AuthMiddleware($handler,null,$reuseChallenges);
};
}
static function cookies():callable
{
return static function(callable$handler):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($handler):PromiseInterface{
if(empty($options['cookies'])){
return$handler($request,$options);
}elseif(!$options['cookies']instanceof CookieJarInterface){
throw new\InvalidArgumentException('cookies must be an instance of GuzzleHttp\Cookie\CookieJarInterface');
}
$cookieJar=$options['cookies'];
$request=$cookieJar->withCookieHeader($request);
return$handler($request,$options)->then(static function(#[\SensitiveParameter]ResponseInterface$response
)use($cookieJar,$request):ResponseInterface{
$cookieJar->extractCookies($request,$response);
return$response;
}
);
};
};
}
static function httpErrors(?BodySummarizerInterface$bodySummarizer=null):callable
{
return static function(callable$handler)use($bodySummarizer):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($handler,$bodySummarizer):PromiseInterface{
if(empty($options['http_errors'])){
return$handler($request,$options);
}
return$handler($request,$options)->then(static function(#[\SensitiveParameter]ResponseInterface$response
)use($request,$bodySummarizer):ResponseInterface{
$code=$response->getStatusCode();
if($code<400){
return$response;
}
throw RequestException::create($request,$response,null,$bodySummarizer);
}
);
};
};
}
static function history(&$container):callable
{
if(!\is_array($container)&&!$container instanceof\ArrayAccess){
throw new\InvalidArgumentException('history container must be an array or object implementing ArrayAccess');
}
return static function(callable$handler)use(&$container):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($handler,&$container):PromiseInterface{
return$handler($request,$options)->then(static function(#[\SensitiveParameter]ResponseInterface$value
)use($request,&$container,$options):ResponseInterface{
$container[]=['request'=>$request,'response'=>$value,'error'=>null,'options'=>$options,];
return$value;
},static function(#[\SensitiveParameter]$reason
)use($request,&$container,$options):PromiseInterface{
$container[]=['request'=>$request,'response'=>null,'error'=>$reason,'options'=>$options,];
return P\Create::rejectionFor($reason);
}
);
};
};
}
static function tap(?callable$before=null,?callable$after=null):callable
{
return static function(callable$handler)use($before,$after):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($handler,$before,$after):PromiseInterface{
if($before){
$before($request,$options);
}
$response=$handler($request,$options);
if($after){
$after($request,$options,$response);
}
return$response;
};
};
}
static function redirect():callable
{
return static function(callable$handler):RedirectMiddleware{
return new RedirectMiddleware($handler);
};
}
static function retry(callable$decider,?callable$delay=null):callable
{
return static function(callable$handler)use($decider,$delay):RetryMiddleware{
return new RetryMiddleware($decider,$handler,$delay);
};
}
static function log(LoggerInterface$logger,MessageFormatterInterface$formatter,string$logLevel='info'):callable
{
return static function(callable$handler)use($logger,$formatter,$logLevel):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options=[])use($handler,$logger,$formatter,$logLevel):PromiseInterface{
return$handler($request,$options)->then(static function(#[\SensitiveParameter]ResponseInterface$response
)use($logger,$request,$formatter,$logLevel):ResponseInterface{
$message=$formatter->format($request,$response);
$logger->log($logLevel,$message);
return$response;
},static function(#[\SensitiveParameter]$reason
)use($logger,$request,$formatter):PromiseInterface{
$response=$reason instanceof ResponseException?$reason->getResponse():null;
$message=$formatter->format($request,$response,P\Create::exceptionFor($reason));
$logger->error($message);
return P\Create::rejectionFor($reason);
}
);
};
};
}
static function prepareBody():callable
{
return static function(callable$handler):PrepareBodyMiddleware{
return new PrepareBodyMiddleware($handler);
};
}
static function mapRequest(callable$fn):callable
{
return static function(callable$handler)use($fn):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($handler,$fn):PromiseInterface{
return$handler($fn($request),$options);
};
};
}
static function mapResponse(callable$fn):callable
{
return static function(callable$handler)use($fn):callable{
return static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
)use($handler,$fn):PromiseInterface{
return$handler($request,$options)->then($fn);
};
};
}
}
declare(strict_types=1);
namespace GuzzleHttp;
final class Multiplexing
{
const NONE='none';
const EAGER='eager';
const WAIT='wait';
const REQUIRE_EAGER='require_eager';
const REQUIRE_WAIT='require_wait';
private function __construct(){
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
interface PromisorInterface
{
function promise():PromiseInterface;
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Cookie\CookieJarInterface;
use GuzzleHttp\Promise\EachPromise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\PromisorInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
class Pool implements PromisorInterface
{
use NonSerializableTrait;
private EachPromise$each;
function __construct(ClientInterface$client,iterable$requests,#[\SensitiveParameter]array$config=[]){
if(!isset($config['concurrency'])){
$config['concurrency']=25;
}
if(isset($config['options'])){
$opts=$config['options'];
unset($config['options']);
}else{
$opts=[];
}
$requestGenerator=static function()use($requests,$client,$opts):\Generator{
foreach($requests as$key=>$rfn){
$keyedOpts=self::keyedRequestOptions($opts,$key);
if($rfn instanceof RequestInterface){
yield$key=>$client->sendAsync($rfn,$keyedOpts);
}elseif(\is_callable($rfn)){
yield$key=>$rfn($keyedOpts);
}else{
throw new\InvalidArgumentException('Each value yielded by the iterator must be a Psr\Http\Message\RequestInterface or a callable that returns a promise that fulfills with a Psr\Http\Message\ResponseInterface object.');
}
}
};
$this->each=new EachPromise($requestGenerator(),$config);
}
function promise():PromiseInterface
{
return$this->each->promise();
}
static function batch(ClientInterface$client,iterable$requests,#[\SensitiveParameter]array$options=[]):array{
$res=[];
self::cmpCallback($options,'fulfilled',$res);
self::cmpCallback($options,'rejected',$res);
$pool=new static($client,$requests,$options);
$pool->promise()->wait();
\ksort($res);
return$res;
}
private static function cmpCallback(array&$options,string$name,array&$results):void
{
if(!isset($options[$name])){
$options[$name]=static function(#[\SensitiveParameter]$v,$k
)use(&$results):void{
$results[$k]=$v;
};
}else{
$currentFn=$options[$name];
$options[$name]=static function(#[\SensitiveParameter]$v,$k
)use(&$results,$currentFn):void{
$currentFn($v,$k);
$results[$k]=$v;
};
}
}
private static function keyedRequestOptions(array$options,$key):array
{
if(\is_array($options['allow_redirects']??null)&&\is_callable($options['allow_redirects']['on_redirect']??null)){
$onRedirect=$options['allow_redirects']['on_redirect'];
$options['allow_redirects']['on_redirect']=static function(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]UriInterface$uri
)use($onRedirect,$key):void{
$onRedirect($request,$response,$uri,$key);
};
}
if(\is_callable($options['on_headers']??null)){
$onHeaders=$options['on_headers'];
$options['on_headers']=static function(#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]RequestInterface$request
)use($onHeaders,$key):void{
$onHeaders($response,$request,$key);
};
}
if(\is_callable($options['on_stats']??null)){
$onStats=$options['on_stats'];
$options['on_stats']=static function(TransferStats$stats)use($onStats,$key):void{
$onStats($stats,$key);
};
}
if(\is_callable($options['on_trailers']??null)){
$onTrailers=$options['on_trailers'];
$options['on_trailers']=static function(array$trailers,#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]RequestInterface$request
)use($onTrailers,$key):void{
$onTrailers($trailers,$response,$request,$key);
};
}
if(\is_callable($options['progress']??null)){
$progress=$options['progress'];
$options['progress']=static function(int$downloadTotal,int$downloadedBytes,int$uploadTotal,int$uploadedBytes)use($progress,$key){
return$progress($downloadTotal,$downloadedBytes,$uploadTotal,$uploadedBytes,$key);
};
}
return$options;
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Handler\RequestFraming;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
class PrepareBodyMiddleware
{
use NonSerializableTrait;
private$nextHandler;
function __construct(callable$nextHandler){
$this->nextHandler=$nextHandler;
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$fn=$this->nextHandler;
$bodySize=RequestFraming::bodySize($request);
if($bodySize===0){
return$fn($request,$options);
}
$modify=[];
if(!$request->hasHeader('Content-Type')){
if($uri=$request->getBody()->getMetadata('uri')){
if(is_string($uri)&&$type=Psr7\MimeType::fromFilename($uri)){
$modify['set_headers']['Content-Type']=$type;
}
}
}
if(!$request->hasHeader('Content-Length')&&!$request->hasHeader('Transfer-Encoding')){
if($bodySize!==null){
$modify['set_headers']['Content-Length']=(string)$bodySize;
}elseif($request->getProtocolVersion()==='1.1'){
$modify['set_headers']['Transfer-Encoding']='chunked';
}
}
$this->addExpectHeader($request,$options,$modify,$bodySize);
return$fn(Psr7\Utils::modifyRequest($request,$modify),$options);
}
private function addExpectHeader(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,array&$modify,?int$bodySize
):void{
if($request->hasHeader('Expect')){
return;
}
$expect=$options['expect']??null;
if($expect===false||'1.1'!==$request->getProtocolVersion()){
return;
}
if($expect===true){
$modify['set_headers']['Expect']='100-Continue';
return;
}
if($expect===null){
$expect=1048576;
}
$body=$request->getBody();
if($bodySize===null||$bodySize>=(int)$expect||!$body->isSeekable()){
$modify['set_headers']['Expect']='100-Continue';
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class RejectionException extends\RuntimeException
{
private$reason;
function __construct($reason,?string$description=null){
$this->reason=$reason;
$message='The promise was rejected';
if($description){
$message.=' with reason: '.$description;
}elseif(is_string($reason)||(is_object($reason)&&method_exists($reason,'__toString'))){
$message.=' with reason: '.$this->reason;
}elseif($reason instanceof\JsonSerializable){
$message.=' with reason: '.json_encode($this->reason,JSON_PRETTY_PRINT);
}
parent::__construct($message);
}
function getReason(){
return$this->reason;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class AggregateException extends RejectionException
{
function __construct(string$msg,array$reasons){
parent::__construct($reasons,sprintf('%s; %d rejected promises',$msg,count($reasons)));
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class CancellationException extends RejectionException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
trait NonSerializableTrait
{
function __serialize():array
{
throw new\LogicException(static::class.' should never be serialized');
}
function __unserialize(array$data):void
{
throw new\LogicException(static::class.' should never be unserialized');
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
interface PromiseInterface
{
const PENDING='pending';
const FULFILLED='fulfilled';
const REJECTED='rejected';
function then(?callable$onFulfilled=null,?callable$onRejected=null
):PromiseInterface;
function otherwise(callable$onRejected):PromiseInterface;
function getState():string;
function resolve($value=null):void;
function reject($reason):void;
function cancel():void;
function wait(bool$unwrap=true);
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
use Generator;
final class Coroutine implements PromiseInterface
{
use NonSerializableTrait;
private?PromiseInterface$currentPromise=null;
private Generator$generator;
private PromiseInterface$result;
function __construct(callable$generatorFn){
$this->generator=$generatorFn();
$this->result=new Promise(function():void{
while(isset($this->currentPromise)){
$this->currentPromise->wait();
}
});
try{
$this->nextCoroutine($this->generator->current());
}catch(\Throwable$throwable){
$this->result->reject($throwable);
}
}
static function of(callable$generatorFn):self
{
return new self($generatorFn);
}
function then(?callable$onFulfilled=null,?callable$onRejected=null
):PromiseInterface{
return$this->result->then($onFulfilled,$onRejected);
}
function otherwise(callable$onRejected):PromiseInterface
{
return$this->result->otherwise($onRejected);
}
function wait(bool$unwrap=true){
return$this->result->wait($unwrap);
}
function getState():string
{
return$this->result->getState();
}
function resolve($value=null):void
{
$this->result->resolve($value);
}
function reject($reason):void
{
$this->result->reject($reason);
}
function cancel():void
{
if(isset($this->currentPromise)){
$this->currentPromise->cancel();
}
$this->result->cancel();
}
private function nextCoroutine($yielded):void
{
$this->currentPromise=Create::promiseFor($yielded)->then([$this,'_handleSuccess'],[$this,'_handleFailure']);
}
function _handleSuccess($value):void
{
$this->currentPromise=null;
try{
$next=$this->generator->send($value);
if($this->generator->valid()){
$this->nextCoroutine($next);
}else{
$this->result->resolve($value);
}
}catch(\Throwable$throwable){
$this->result->reject($throwable);
}
}
function _handleFailure($reason):void
{
$this->currentPromise=null;
try{
$nextYield=$this->generator->throw(Create::exceptionFor($reason));
$this->nextCoroutine($nextYield);
}catch(\Throwable$throwable){
$this->result->reject($throwable);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
final class Create
{
private function __construct(){
}
static function promiseFor($value):PromiseInterface
{
if($value instanceof PromiseInterface){
return$value;
}
if(is_object($value)&&method_exists($value,'then')){
$wfn=method_exists($value,'wait')?[$value,'wait']:null;
$cfn=method_exists($value,'cancel')?[$value,'cancel']:null;
$promise=new Promise($wfn,$cfn);
$value->then([$promise,'resolve'],[$promise,'reject']);
return$promise;
}
return new FulfilledPromise($value);
}
static function rejectionFor($reason):PromiseInterface
{
if($reason instanceof PromiseInterface){
return$reason;
}
return new RejectedPromise($reason);
}
static function exceptionFor($reason):\Throwable
{
if($reason instanceof\Throwable){
return$reason;
}
return new RejectionException($reason);
}
static function iterFor(iterable$value):\Iterator
{
if($value instanceof\Iterator){
return$value;
}
if(is_array($value)){
return new\ArrayIterator($value);
}
if($value instanceof\IteratorAggregate){
return self::iterFor($value->getIterator());
}
return new\IteratorIterator($value);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
final class Each
{
private function __construct(){
}
static function of(iterable$iterable,?callable$onFulfilled=null,?callable$onRejected=null,array$config=[]):PromiseInterface{
$eachConfig=[];
if(null!==$onFulfilled){
$eachConfig['fulfilled']=$onFulfilled;
}
if(null!==$onRejected){
$eachConfig['rejected']=$onRejected;
}
if(isset($config['concurrency'])){
$eachConfig['concurrency']=$config['concurrency'];
}
return(new EachPromise($iterable,$eachConfig))->promise();
}
static function ofLimit(iterable$iterable,$concurrency,?callable$onFulfilled=null,?callable$onRejected=null
):PromiseInterface{
return self::of($iterable,$onFulfilled,$onRejected,['concurrency'=>$concurrency]);
}
static function ofLimitAll(iterable$iterable,$concurrency,?callable$onFulfilled=null
):PromiseInterface{
return self::ofLimit($iterable,$concurrency,$onFulfilled,function($reason,$idx,PromiseInterface$aggregate):void{
$aggregate->reject($reason);
}
);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class EachPromise implements PromisorInterface
{
use NonSerializableTrait;
private?array$pending=[];
private int$nextPendingIndex=0;
private?\Iterator$iterable;
private$concurrency;
private$onFulfilled;
private$onRejected;
private?Promise$aggregate=null;
private?bool$mutex=null;
private bool$stepWhileLocked=false;
function __construct(iterable$iterable,array$config=[]){
$this->iterable=Create::iterFor($iterable);
if(isset($config['concurrency'])){
$this->concurrency=$config['concurrency'];
}
if(isset($config['fulfilled'])){
$this->onFulfilled=$config['fulfilled'];
}
if(isset($config['rejected'])){
$this->onRejected=$config['rejected'];
}
}
function promise():PromiseInterface
{
if($this->aggregate){
return$this->aggregate;
}
try{
$this->createPromise();
$this->iterable->rewind();
$this->refillPending();
if(!$this->pending){
Utils::queue()->add(function():void{
if(!$this->aggregate||State::isSettled($this->aggregate)){
return;
}
try{
$this->checkIfFinished();
}catch(\Throwable$e){
$this->aggregate->reject($e);
}
});
}
}catch(\Throwable$e){
$this->aggregate->reject($e);
}
return$this->aggregate;
}
private function createPromise():void
{
$this->mutex=false;
$this->aggregate=new Promise(function():void{
while(true){
if($this->checkIfFinished()){
return;
}
reset($this->pending);
while($promise=pos($this->pending)){
next($this->pending);
$promise->wait();
if(State::isSettled($this->aggregate)){
return;
}
}
$this->refillPending();
if(State::isSettled($this->aggregate)||!$this->pending){
return;
}
}
});
$clearFn=function():void{
$this->iterable=$this->concurrency=$this->pending=null;
$this->onFulfilled=$this->onRejected=null;
$this->nextPendingIndex=0;
};
$this->aggregate->then($clearFn,$clearFn);
}
private function refillPending():void
{
if(!$this->concurrency){
while($this->addPending()&&$this->advanceIterator()){
}
return;
}
$concurrency=is_callable($this->concurrency)?($this->concurrency)(count($this->pending)):$this->concurrency;
if(State::isSettled($this->aggregate)){
return;
}
$concurrency=max($concurrency-count($this->pending),0);
if(!$concurrency){
return;
}
$this->addPending();
while(--$concurrency
&&$this->advanceIterator()&&$this->addPending()){
}
}
private function addPending():bool
{
if(!$this->iterable||!$this->iterable->valid()){
return false;
}
$promise=Create::promiseFor($this->iterable->current());
$key=$this->iterable->key();
$idx=$this->nextPendingIndex++;
$this->pending[$idx]=$promise->then(function($value)use($idx,$key):void{
if($this->onFulfilled){
($this->onFulfilled)($value,$key,$this->aggregate
);
}
$this->step($idx);
},function($reason)use($idx,$key):void{
if($this->onRejected){
($this->onRejected)($reason,$key,$this->aggregate
);
}
$this->step($idx);
}
);
return true;
}
private function advanceIterator():bool
{
if($this->mutex){
$this->stepWhileLocked=true;
return false;
}
$this->mutex=true;
try{
$this->iterable->next();
$this->mutex=false;
}catch(\Throwable$e){
$this->aggregate->reject($e);
$this->mutex=false;
return false;
}
if($this->stepWhileLocked){
$this->stepWhileLocked=false;
if(!State::isSettled($this->aggregate)){
$this->checkIfFinished();
}
}
return true;
}
private function step(int$idx):void
{
if(State::isSettled($this->aggregate)){
return;
}
unset($this->pending[$idx]);
if($this->advanceIterator()&&!$this->checkIfFinished()){
$this->refillPending();
}
}
private function checkIfFinished():bool
{
if(!$this->pending&&!$this->iterable->valid()){
$this->aggregate->resolve(null);
return true;
}
return false;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class FulfilledPromise implements PromiseInterface
{
private$value;
function __construct($value){
if(is_object($value)&&method_exists($value,'then')){
throw new\InvalidArgumentException('You cannot create a FulfilledPromise with a promise.');
}
$this->value=$value;
}
function then(?callable$onFulfilled=null,?callable$onRejected=null
):PromiseInterface{
if(!$onFulfilled){
return$this;
}
$queue=Utils::queue();
$p=new Promise([$queue,'run']);
$value=$this->value;
$queue->add(static function()use($p,$value,$onFulfilled):void{
if(State::isPending($p)){
try{
$p->resolve($onFulfilled($value));
}catch(\Throwable$e){
$p->reject($e);
}
}
});
return$p;
}
function otherwise(callable$onRejected):PromiseInterface
{
return$this->then(null,$onRejected);
}
function wait(bool$unwrap=true){
return$unwrap?$this->value:null;
}
function getState():string
{
return self::FULFILLED;
}
function resolve($value=null):void
{
if($value!==$this->value){
throw new\LogicException('Cannot resolve a fulfilled promise');
}
}
function reject($reason):void
{
throw new\LogicException('Cannot reject a fulfilled promise');
}
function cancel():void
{
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
final class Is
{
private function __construct(){
}
static function pending(PromiseInterface$promise):bool
{
\trigger_deprecation('guzzlehttp/promises','3.1','%s() is deprecated and will be removed in 4.0. Use %s::isPending() instead.',__METHOD__,State::class
);
return State::isPending($promise);
}
static function settled(PromiseInterface$promise):bool
{
\trigger_deprecation('guzzlehttp/promises','3.1','%s() is deprecated and will be removed in 4.0. Use %s::isSettled() instead.',__METHOD__,State::class
);
return State::isSettled($promise);
}
static function fulfilled(PromiseInterface$promise):bool
{
\trigger_deprecation('guzzlehttp/promises','3.1','%s() is deprecated and will be removed in 4.0. Use %s::isFulfilled() instead.',__METHOD__,State::class
);
return State::isFulfilled($promise);
}
static function rejected(PromiseInterface$promise):bool
{
\trigger_deprecation('guzzlehttp/promises','3.1','%s() is deprecated and will be removed in 4.0. Use %s::isRejected() instead.',__METHOD__,State::class
);
return State::isRejected($promise);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class Promise implements PromiseInterface
{
use NonSerializableTrait;
private string$state=self::PENDING;
private$result;
private$cancelFn;
private$waitFn;
private?array$waitList=null;
private?array$handlers=[];
function __construct(?callable$waitFn=null,?callable$cancelFn=null
){
$this->waitFn=$waitFn;
$this->cancelFn=$cancelFn;
}
function then(?callable$onFulfilled=null,?callable$onRejected=null
):PromiseInterface{
if($this->state===self::PENDING){
$p=new Promise(null,[$this,'cancel']);
$this->handlers[]=[$p,$onFulfilled,$onRejected];
$p->waitList=$this->waitList;
$p->waitList[]=$this;
return$p;
}
if($this->state===self::FULFILLED){
$promise=Create::promiseFor($this->result);
return$promise->then($onFulfilled,$onRejected);
}
$rejection=Create::rejectionFor($this->result);
$promise=$onRejected?$rejection->then(null,$onRejected):$rejection;
return$promise;
}
function otherwise(callable$onRejected):PromiseInterface
{
return$this->then(null,$onRejected);
}
function wait(bool$unwrap=true){
$this->waitIfPending();
if($this->result instanceof PromiseInterface){
return$this->result->wait($unwrap);
}
if($unwrap){
if($this->state===self::FULFILLED){
return$this->result;
}
throw Create::exceptionFor($this->result);
}
return;
}
function getState():string
{
return$this->state;
}
function cancel():void
{
if($this->state!==self::PENDING){
return;
}
$this->waitFn=$this->waitList=null;
if($this->cancelFn){
$fn=$this->cancelFn;
$this->cancelFn=null;
try{
$fn();
}catch(\Throwable$e){
$this->reject($e);
}
}
if($this->state===self::PENDING){
$this->reject(new CancellationException('Promise has been cancelled'));
}
}
function resolve($value=null):void
{
$this->settle(self::FULFILLED,$value);
}
function reject($reason):void
{
$this->settle(self::REJECTED,$reason);
}
private function settle(string$state,$value):void
{
if($this->state!==self::PENDING){
if($state===$this->state&&$value===$this->result){
return;
}
throw$this->state===$state
?new\LogicException("The promise is already {$state}."):new\LogicException("Cannot change a {$this->state} promise to {$state}");
}
if($value===$this){
throw new\LogicException('Cannot fulfill or reject a promise with itself');
}
$this->state=$state;
$this->result=$value;
$handlers=$this->handlers;
$this->handlers=null;
$this->waitList=$this->waitFn=null;
$this->cancelFn=null;
if(!$handlers){
return;
}
if(!is_object($value)||!method_exists($value,'then')){
$id=$state===self::FULFILLED?1:2;
Utils::queue()->add(static function()use($id,$value,$handlers):void{
foreach($handlers as$handler){
self::callHandler($id,$value,$handler);
}
});
}elseif($value instanceof Promise&&State::isPending($value)){
$value->handlers=array_merge($value->handlers,$handlers);
}else{
$value->then(static function($value)use($handlers):void{
foreach($handlers as$handler){
self::callHandler(1,$value,$handler);
}
},static function($reason)use($handlers):void{
foreach($handlers as$handler){
self::callHandler(2,$reason,$handler);
}
}
);
}
}
private static function callHandler(int$index,$value,array$handler):void
{
$promise=$handler[0];
if(State::isSettled($promise)){
return;
}
try{
if(isset($handler[$index])){
$f=$handler[$index];
unset($handler);
$promise->resolve($f($value));
}elseif($index===1){
$promise->resolve($value);
}else{
$promise->reject($value);
}
}catch(\Throwable$reason){
$promise->reject($reason);
}
}
private function waitIfPending():void
{
if($this->state!==self::PENDING){
return;
}elseif($this->waitFn){
$this->invokeWaitFn();
}elseif($this->waitList){
$this->invokeWaitList();
}else{
$this->reject('Cannot wait on a promise that has '.'no internal wait function. You must provide a wait '.'function when constructing the promise to be able to '.'wait on a promise.');
}
Utils::queue()->run();
if($this->state===self::PENDING){
$this->reject('Invoking the wait callback did not resolve the promise');
}
}
private function invokeWaitFn():void
{
try{
$wfn=$this->waitFn;
$this->waitFn=null;
$wfn(true);
}catch(\Throwable$reason){
if($this->state===self::PENDING){
$this->reject($reason);
}else{
throw$reason;
}
}
}
private function invokeWaitList():void
{
$waitList=$this->waitList;
$this->waitList=null;
foreach($waitList as$result){
do{
$result->waitIfPending();
$result=$result->result;
}while($result instanceof Promise);
if($result instanceof PromiseInterface){
$result->wait(false);
}
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class RejectedPromise implements PromiseInterface
{
private$reason;
function __construct($reason){
if(is_object($reason)&&method_exists($reason,'then')){
throw new\InvalidArgumentException('You cannot create a RejectedPromise with a promise.');
}
$this->reason=$reason;
}
function then(?callable$onFulfilled=null,?callable$onRejected=null
):PromiseInterface{
if(!$onRejected){
return$this;
}
$queue=Utils::queue();
$reason=$this->reason;
$p=new Promise([$queue,'run']);
$queue->add(static function()use($p,$reason,$onRejected):void{
if(State::isPending($p)){
try{
$p->resolve($onRejected($reason));
}catch(\Throwable$e){
$p->reject($e);
}
}
});
return$p;
}
function otherwise(callable$onRejected):PromiseInterface
{
return$this->then(null,$onRejected);
}
function wait(bool$unwrap=true){
if($unwrap){
throw Create::exceptionFor($this->reason);
}
return;
}
function getState():string
{
return self::REJECTED;
}
function resolve($value=null):void
{
throw new\LogicException('Cannot resolve a rejected promise');
}
function reject($reason):void
{
if($reason!==$this->reason){
throw new\LogicException('Cannot reject a rejected promise');
}
}
function cancel():void
{
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
final class State
{
private function __construct(){
}
static function isPending(PromiseInterface$promise):bool
{
return$promise->getState()===PromiseInterface::PENDING;
}
static function isSettled(PromiseInterface$promise):bool
{
return$promise->getState()!==PromiseInterface::PENDING;
}
static function isFulfilled(PromiseInterface$promise):bool
{
return$promise->getState()===PromiseInterface::FULFILLED;
}
static function isRejected(PromiseInterface$promise):bool
{
return$promise->getState()===PromiseInterface::REJECTED;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
interface TaskQueueInterface
{
function isEmpty():bool;
function add(callable$task):void;
function run():void;
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
class TaskQueue implements TaskQueueInterface
{
use NonSerializableTrait;
private bool$enableShutdown=true;
private array$queue=[];
function __construct(bool$withShutdown=true){
if($withShutdown){
register_shutdown_function(function():void{
if($this->enableShutdown){
$err=error_get_last();
if(!$err||($err['type']^ E_ERROR)){
$this->run();
}
}
});
}
}
function isEmpty():bool
{
return!$this->queue;
}
function add(callable$task):void
{
$this->queue[]=$task;
}
function run():void
{
while($task=array_shift($this->queue)){
$task();
}
}
function disableShutdown():void
{
$this->enableShutdown=false;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Promise;
final class Utils
{
private function __construct(){
}
static function queue(?TaskQueueInterface$assign=null):TaskQueueInterface
{
static$queue;
if($assign){
$queue=$assign;
}elseif(!$queue){
$queue=new TaskQueue;
}
return$queue;
}
static function task(callable$task):PromiseInterface
{
$queue=self::queue();
$promise=new Promise([$queue,'run']);
$queue->add(function()use($task,$promise):void{
try{
if(State::isPending($promise)){
$promise->resolve($task());
}
}catch(\Throwable$e){
$promise->reject($e);
}
});
return$promise;
}
static function inspect(PromiseInterface$promise):array
{
$result=null;
$getResult=static function()use(&$result):?array{
return$result;
};
$inspection=$promise->then(static function($value)use(&$result):void{
$result=['state'=>PromiseInterface::FULFILLED,'value'=>$value];
},static function($reason)use(&$result):void{
$result=['state'=>PromiseInterface::REJECTED,'reason'=>$reason];
}
);
try{
$inspection->wait(false);
}catch(\Throwable$e){
$settled=$getResult();
if(null!==$settled){
return$settled;
}
if(State::isSettled($promise)){
try{
self::queue()->run();
}catch(\Throwable$queueError){
return['state'=>PromiseInterface::REJECTED,'reason'=>$queueError];
}
$settled=$getResult();
if(null!==$settled){
return$settled;
}
}
return['state'=>PromiseInterface::REJECTED,'reason'=>$e];
}
return$getResult()??['state'=>$promise->getState()];
}
static function inspectAll(iterable$promises):array
{
$results=[];
foreach($promises as$key=>$promise){
$results[$key]=self::inspect($promise);
}
return$results;
}
static function unwrap(iterable$promises):array
{
$results=[];
foreach($promises as$key=>$promise){
$results[$key]=$promise->wait();
}
return$results;
}
static function all(iterable$promises,bool$recursive=false,array$config=[]):PromiseInterface
{
$results=[];
$promise=Each::of($promises,function($value,$idx)use(&$results):void{
$results[$idx]=$value;
},function($reason,$idx,PromiseInterface$aggregate):void{
if(State::isPending($aggregate)){
$aggregate->reject($reason);
}
},$config
)->then(function()use(&$results){
ksort($results);
return$results;
});
if(true===$recursive){
$promise=$promise->then(function($results)use(&$promises,$config){
if(self::shouldRecurse($promises,$results)){
return self::all($promises,true,$config);
}
return$results;
});
}
return$promise;
}
static function some(int$count,iterable$promises):PromiseInterface
{
$results=[];
$rejections=[];
$promise=Each::of($promises,function($value,$idx,PromiseInterface$p)use(&$results,$count):void{
if(State::isSettled($p)){
return;
}
$results[$idx]=$value;
if(count($results)>=$count){
$p->resolve(null);
}
},function($reason)use(&$rejections):void{
$rejections[]=$reason;
}
)->then(function()use(&$results,&$rejections,$count){
if(count($results)!==$count){
throw new AggregateException('Not enough promises to fulfill count',$rejections
);
}
ksort($results);
return array_values($results);
}
);
return$promise;
}
static function any(iterable$promises):PromiseInterface
{
return self::some(1,$promises)->then(function(array$values){
return$values[0];
});
}
static function settle(iterable$promises,bool$recursive=false,array$config=[]):PromiseInterface
{
$results=[];
$promise=Each::of($promises,function($value,$idx)use(&$results):void{
$results[$idx]=['state'=>PromiseInterface::FULFILLED,'value'=>$value];
},function($reason,$idx)use(&$results):void{
$results[$idx]=['state'=>PromiseInterface::REJECTED,'reason'=>$reason];
},$config
)->then(function()use(&$results){
ksort($results);
return$results;
});
if(true===$recursive){
$promise=$promise->then(function($results)use(&$promises,$config){
if(self::shouldRecurse($promises,$results)){
return self::settle($promises,true,$config);
}
return$results;
});
}
return$promise;
}
private static function shouldRecurse(iterable$promises,array$results):bool
{
if($promises instanceof\Generator){
return false;
}
foreach($promises as$key=>$promise){
if(!key_exists($key,$results)){
return true;
}
if($promise instanceof PromiseInterface&&State::isPending($promise)){
return true;
}
}
return false;
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Psr7\Rfc3986;
use Psr\Http\Message\UriInterface;
final class ProxyOptions
{
private function __construct(){
}
static function resolve(UriInterface$uri,#[\SensitiveParameter]$proxy
):ProxySelection{
if($proxy===null){
return ProxySelection::none();
}
if(!\is_array($proxy)){
if(!\is_string($proxy)){
throw new InvalidArgumentException('proxy must be a string or array');
}
return ProxySelection::proxy($proxy);
}
$schemeProxy=$proxy[$uri->getScheme()]??null;
if($schemeProxy!==null&&!\is_string($schemeProxy)){
throw new InvalidArgumentException('proxy values must be strings');
}
$noProxy=isset($proxy['no'])?self::normalizeNoProxy($proxy['no']):[];
if($noProxy!==[]&&self::isUriInNoProxy($uri,$noProxy)){
return ProxySelection::bypassed();
}
if($schemeProxy===null){
return ProxySelection::none();
}
return ProxySelection::proxy($schemeProxy);
}
static function proxyScheme(#[\SensitiveParameter]string$proxy
):string{
$parts=\explode('://',$proxy,2);
if(\count($parts)===1){
$scheme='http';
$authority=$proxy;
}else{
[$scheme,$authority]=$parts;
$scheme=Psr7\Utils::asciiToLower($scheme);
if($scheme===''||!Rfc3986::isValidScheme($scheme)){
throw new InvalidArgumentException('Invalid proxy URL.');
}
}
if(!self::isValidProxyAuthority($authority)){
throw new InvalidArgumentException('Invalid proxy URL.');
}
return$scheme;
}
private static function isValidProxyAuthority(string$authority):bool
{
if(\str_ends_with($authority,'/')){
$authority=\substr($authority,0,\strlen($authority)-1);
}
if($authority===''||\strpbrk($authority,'/?#')!==false){
return false;
}
$segments=\explode('@',$authority);
$authority=$segments[\count($segments)-1];
if($authority===''){
return false;
}
$port=null;
if(\str_starts_with($authority,'[')){
$parts=\explode(']',$authority,2);
if(\count($parts)!==2){
return false;
}
$host=$parts[0].']';
$remainder=$parts[1];
if($remainder!==''){
if(!\str_starts_with($remainder,':')){
return false;
}
[,$port]=\explode(':',$remainder,2);
}
}elseif(\strpos($authority,':')!==false){
[$host,$port]=\explode(':',$authority,2);
}else{
$host=$authority;
}
if($port===''){
$port=null;
}
if($host===''||!Rfc3986::isValidHost($host)){
return false;
}
return$port===null||Rfc3986::isValidPort($port);
}
static function normalizeNoProxy($noProxy):array
{
if($noProxy===null){
return[];
}
if(\is_string($noProxy)){
$noProxy=\preg_split('/[\s,]+/',$noProxy);
if($noProxy===false){
throw new\RuntimeException('Unable to split the proxy no list: '.\preg_last_error_msg());
}
}elseif(!\is_array($noProxy)){
throw new InvalidArgumentException('proxy no list must be null, a string, or an array of strings');
}
$result=[];
foreach($noProxy as$area){
if(!\is_string($area)){
throw new InvalidArgumentException('proxy no list must be null, a string, or an array of strings');
}
$area=\trim($area," \n\r\t\0\x0B");
if($area!==''){
$result[]=$area;
}
}
return$result;
}
static function isUriInNoProxy(UriInterface$uri,array$noProxy):bool
{
self::assertNoProxyList($noProxy);
$target=self::parseNoProxyTarget($uri);
if($target===null){
return false;
}
foreach($noProxy as$area){
$area=\trim($area," \n\r\t\0\x0B");
if($area==='*'){
return true;
}
$rule=self::parseNoProxyRule($area);
if($rule!==null&&self::noProxyRuleMatches($target,$rule)){
return true;
}
}
return false;
}
static function isHostInNoProxy(string$host,array$noProxy):bool
{
if($host===''){
throw new InvalidArgumentException('Empty host provided');
}
self::assertNoProxyList($noProxy);
$target=self::parseNoProxyHostString($host);
if($target===null){
return false;
}
foreach($noProxy as$area){
$area=\trim($area," \n\r\t\0\x0B");
if($area==='*'){
return true;
}
$rule=self::parseNoProxyRule($area);
if($rule!==null&&self::noProxyRuleMatches($target,$rule)){
return true;
}
}
return false;
}
private static function assertNoProxyList(array$noProxy):void
{
foreach($noProxy as$area){
if(!\is_string($area)){
throw new InvalidArgumentException('proxy no list must be null, a string, or an array of strings');
}
}
}
private static function parseNoProxyTarget(UriInterface$uri):?array
{
$host=$uri->getHost();
if($host===''){
return;
}
return self::parseNoProxyHost($host,$uri->getPort()??self::getDefaultPort($uri->getScheme()));
}
private static function parseNoProxyHostString(string$host):?array
{
$hostAndPort=self::splitNoProxyHostAndPort($host);
if($hostAndPort===null){
return;
}
[$host]=$hostAndPort;
return self::parseNoProxyHost($host,null);
}
private static function parseNoProxyRule(string$area):?array
{
$area=\trim($area," \n\r\t\0\x0B");
if($area===''||$area==='*'){
return;
}
if($area[0]==='.'){
$area=\substr($area,1);
if($area===''){
return;
}
}
if(\strpos($area,'/')!==false){
return self::parseNoProxyCidrRule($area);
}
$hostAndPort=self::splitNoProxyHostAndPort($area);
if($hostAndPort===null){
return;
}
[$host,$port]=$hostAndPort;
if($host==='*'){
return['type'=>'wildcard','value'=>'*','port'=>$port,];
}
return self::parseNoProxyHost($host,$port);
}
private static function parseNoProxyHost(string$host,?int$port):?array
{
if($host!==''&&$host[0]==='['){
if(\substr($host,-1)!==']'){
return;
}
$address=\substr($host,1,-1);
if(!\filter_var($address,\FILTER_VALIDATE_IP,\FILTER_FLAG_IPV6)){
return;
}
$host=$address;
}
$packedIp=self::packHostAddress($host);
if($packedIp!==false){
return['type'=>'ip','value'=>$packedIp,'port'=>$port,];
}
if($host===''||\strpos($host,':')!==false){
return;
}
if(\substr($host,-1)==='.'){
$host=\substr($host,0,-1);
if($host===''){
return;
}
}
return['type'=>'domain','value'=>Psr7\Utils::asciiToLower($host),'port'=>$port,];
}
private static function splitNoProxyHostAndPort(string$area):?array
{
if($area!==''&&$area[0]==='['){
$closingBracket=\strpos($area,']');
if($closingBracket===false){
return;
}
$host=\substr($area,0,$closingBracket+1);
$tail=\substr($area,$closingBracket+1);
if($tail===''){
return[$host,null];
}
if($tail[0]!==':'){
return;
}
$port=self::parseNoProxyPort(\substr($tail,1));
return$port===null?null:[$host,$port];
}
if(self::packHostAddress($area)!==false){
return[$area,null];
}
$colon=\strrpos($area,':');
if($colon===false){
return[$area,null];
}
$port=self::parseNoProxyPort(\substr($area,$colon+1));
if($port===null){
return;
}
return[\substr($area,0,$colon),$port];
}
private static function parseNoProxyPort(string$port):?int
{
return self::parseBoundedUnsignedInteger($port,65535);
}
private static function getDefaultPort(string$scheme):?int
{
if($scheme==='http'){
return 80;
}
if($scheme==='https'){
return 443;
}
return;
}
private static function parseNoProxyCidrRule(string$area):?array
{
$slash=\strpos($area,'/');
if($slash===false){
return;
}
$prefix=\substr($area,$slash+1);
$network=\substr($area,0,$slash);
if($network!==''&&$network[0]==='['&&\substr($network,-1)===']'){
$network=\substr($network,1,-1);
}
$network=self::packIpAddress($network);
if($network===false){
return;
}
$prefix=self::parseBoundedUnsignedInteger($prefix,\strlen($network)*8);
if($prefix===null){
return;
}
return['type'=>'cidr','value'=>$network,'prefix'=>$prefix,];
}
private static function parseBoundedUnsignedInteger(string$value,int$max):?int
{
if($value===''||!\ctype_digit($value)){
return;
}
$normalized=\ltrim($value,'0');
$normalized=$normalized===''?'0':$normalized;
$limit=(string)$max;
if(\strlen($normalized)>\strlen($limit)||(\strlen($normalized)===\strlen($limit)&&\strcmp($normalized,$limit)>0)){
return;
}
return(int)$normalized;
}
private static function noProxyRuleMatches(array$target,array$rule):bool
{
if($rule['type']==='wildcard'){
return($rule['port']??null)===null||$rule['port']===$target['port'];
}
if($rule['type']==='cidr'){
if($target['type']!=='ip'||!isset($rule['prefix'])){
return false;
}
if(\strlen($target['value'])!==\strlen($rule['value'])){
return false;
}
return self::ipMatchesPrefix($target['value'],$rule['value'],$rule['prefix']);
}
if(($rule['port']??null)!==null&&$rule['port']!==$target['port']){
return false;
}
if($rule['type']!==$target['type']){
return false;
}
if($rule['type']==='ip'){
return$rule['value']===$target['value'];
}
if($target['value']===$rule['value']){
return true;
}
$suffix='.'.$rule['value'];
return\substr($target['value'],-\strlen($suffix))===$suffix;
}
private static function packIpAddress(string$ip){
if(\filter_var($ip,\FILTER_VALIDATE_IP)){
return\inet_pton($ip);
}
return false;
}
private static function packHostAddress(string$host){
$packed=self::packIpAddress($host);
if($packed!==false){
return$packed;
}
return HostIdentity::numericIpv4ToBinary($host)??false;
}
private static function ipMatchesPrefix(string$address,string$network,int$prefix):bool
{
$fullBytes=\intdiv($prefix,8);
$remainingBits=$prefix%8;
if($fullBytes>0&&\substr($address,0,$fullBytes)!==\substr($network,0,$fullBytes)){
return false;
}
if($remainingBits===0){
return true;
}
$mask=(255<<(8-$remainingBits))&255;
return(\ord($address[$fullBytes])&$mask)===(\ord($network[$fullBytes])&$mask);
}
}
declare(strict_types=1);
namespace GuzzleHttp;
final class ProxySelection
{
private?string$proxy;
private bool$bypassed;
private bool$disabled;
private function __construct(?string$proxy,bool$bypassed,bool$disabled){
$this->proxy=$proxy;
$this->bypassed=$bypassed;
$this->disabled=$disabled;
}
static function none():self
{
return new self(null,false,false);
}
static function proxy(string$proxy):self
{
return$proxy===''?self::disabled():new self($proxy,false,false);
}
static function bypassed():self
{
return new self(null,true,false);
}
static function disabled():self
{
return new self(null,false,true);
}
function getProxy():?string
{
return$this->proxy;
}
function hasProxy():bool
{
return$this->proxy!==null;
}
function isBypassed():bool
{
return$this->bypassed;
}
function isDisabled():bool
{
return$this->disabled;
}
function shouldDisableProxy():bool
{
return$this->bypassed||$this->disabled;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
trait NonSerializableStreamTrait
{
function __serialize():array
{
throw new\LogicException(static::class.' should never be serialized');
}
function __unserialize(array$data):void
{
throw new\LogicException(static::class.' should never be unserialized');
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use Psr\Http\Message\StreamInterface;
final class AppendStream implements StreamInterface
{
use NonSerializableStreamTrait;
private array$streams=[];
private bool$seekable=true;
private int$current=0;
private int$pos=0;
function __construct(array$streams=[]){
foreach($streams as$stream){
$this->addStream($stream);
}
}
function __toString():string
{
$this->rewind();
return$this->getContents();
}
function addStream(StreamInterface$stream):void
{
if(!$stream->isReadable()){
throw new\InvalidArgumentException('Each stream must be readable');
}
if(!$stream->isSeekable()){
$this->seekable=false;
}
$this->streams[]=$stream;
}
function getContents():string
{
return Utils::copyToString($this);
}
function close():void
{
$this->pos=$this->current=0;
$this->seekable=true;
foreach($this->streams as$stream){
$stream->close();
}
$this->streams=[];
}
function detach(){
$this->pos=$this->current=0;
$this->seekable=true;
foreach($this->streams as$stream){
$stream->detach();
}
$this->streams=[];
return;
}
function tell():int
{
return$this->pos;
}
function getSize():?int
{
$size=0;
foreach($this->streams as$stream){
$s=$stream->getSize();
if($s===null){
return;
}
$size=Integers::add($size,$s);
}
return$size;
}
function eof():bool
{
return!$this->streams
||($this->current>=count($this->streams)-1
&&$this->streams[$this->current]->eof());
}
function rewind():void
{
$this->seek(0);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
if(!$this->seekable){
throw new\RuntimeException('This AppendStream is not seekable');
}elseif($whence!==SEEK_SET){
throw new\RuntimeException('The AppendStream can only seek with SEEK_SET');
}
$this->pos=$this->current=0;
foreach($this->streams as$i=>$stream){
try{
$stream->rewind();
}catch(\Exception$e){
throw new\RuntimeException('Unable to seek stream '.$i.' of the AppendStream',0,$e);
}
}
while($this->pos<$offset&&!$this->eof()){
$result=$this->read(min(8096,$offset-$this->pos));
if($result===''){
break;
}
}
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
if($this->streams===[]){
return'';
}
$buffer='';
$total=count($this->streams)-1;
$remaining=$length;
$progressToNext=false;
while($remaining>0){
if($progressToNext||$this->streams[$this->current]->eof()){
$progressToNext=false;
if($this->current===$total){
break;
}
++$this->current;
}
try{
$result=StreamTimeout::read($this->streams[$this->current],$remaining,'Unable to read from stream: timed out');
}catch(TimeoutException$e){
if($buffer===''){
throw$e;
}
break;
}
if($result===''){
$progressToNext=true;
continue;
}
$buffer.=$result;
$remaining=$length-strlen($buffer);
}
$this->pos=Integers::add($this->pos,strlen($buffer));
return$buffer;
}
function isReadable():bool
{
return true;
}
function isWritable():bool
{
return false;
}
function isSeekable():bool
{
return$this->seekable;
}
function write(string$string):int
{
throw new\RuntimeException('Cannot write to an AppendStream');
}
function getMetadata(?string$key=null):?array
{
return$key===null?[]:null;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class BufferStream implements StreamInterface
{
use NonSerializableStreamTrait;
private int$hwm;
private string$buffer='';
function __construct(int$hwm=16384){
$this->hwm=Integers::assertNonNegativeInteger($hwm,'High water mark');
}
function __toString():string
{
return$this->getContents();
}
function getContents():string
{
$buffer=$this->buffer;
$this->buffer='';
return$buffer;
}
function close():void
{
$this->buffer='';
}
function detach(){
$this->close();
return;
}
function getSize():?int
{
return strlen($this->buffer);
}
function isReadable():bool
{
return true;
}
function isWritable():bool
{
return true;
}
function isSeekable():bool
{
return false;
}
function rewind():void
{
$this->seek(0);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
throw new\RuntimeException('Cannot seek a BufferStream');
}
function eof():bool
{
return strlen($this->buffer)===0;
}
function tell():int
{
throw new\RuntimeException('Cannot determine the position of a BufferStream');
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
$currentLength=strlen($this->buffer);
if($length>=$currentLength){
$result=$this->buffer;
$this->buffer='';
}else{
$result=substr($this->buffer,0,$length);
$this->buffer=substr($this->buffer,$length);
}
return$result;
}
function write(string$string):int
{
$this->buffer.=$string;
if(strlen($this->buffer)>=$this->hwm){
return 0;
}
return strlen($string);
}
function getMetadata(?string$key=null){
if($key==='hwm'){
return$this->hwm;
}
return$key===null?[]:null;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class CachingStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private StreamInterface$remoteStream;
private int$skipReadBytes=0;
private StreamInterface$stream;
private bool$detached=false;
private bool$closed=false;
function __construct(StreamInterface$stream,?StreamInterface$target=null
){
$this->remoteStream=$stream;
$this->stream=$target?:new Stream(Utils::tryFopen('php://temp','r+'));
}
function getSize():?int
{
if($this->detached){
return;
}
$remoteSize=$this->remoteStream->getSize();
if(null===$remoteSize){
return;
}
return max($this->stream->getSize(),$remoteSize);
}
function rewind():void
{
$this->seek(0);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
if($whence===SEEK_SET){
$byte=$offset;
}elseif($whence===SEEK_CUR){
$byte=Integers::addSigned($this->tell(),$offset);
}elseif($whence===SEEK_END){
$size=$this->remoteStream->getSize();
if($size===null){
$position=$this->tell();
$size=$this->cacheEntireStream();
try{
$byte=Integers::addSigned($size,$offset);
}catch(\Throwable$e){
$this->stream->seek($position);
throw$e;
}
}else{
$byte=Integers::addSigned($size,$offset);
}
}else{
throw new\InvalidArgumentException('Invalid whence');
}
$diff=$byte-$this->stream->getSize();
if($diff>0){
while($diff>0&&!$this->remoteStream->eof()){
$previousSize=$this->stream->getSize();
$previousSkipReadBytes=$this->skipReadBytes;
$data=$this->read($diff);
$currentSize=$this->stream->getSize();
if($data===''&&$currentSize===$previousSize&&$this->skipReadBytes===$previousSkipReadBytes){
break;
}
$diff=$byte-$currentSize;
}
}else{
$this->stream->seek($byte);
}
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
$data=$this->stream->read($length);
$remaining=$length-strlen($data);
if($remaining){
$remoteData=StreamTimeout::read($this->remoteStream,Integers::add($remaining,$this->skipReadBytes),'Unable to read from stream: timed out');
if($this->skipReadBytes){
$len=strlen($remoteData);
$remoteData=substr($remoteData,$this->skipReadBytes);
$this->skipReadBytes=max(0,$this->skipReadBytes-$len);
}
$data.=$remoteData;
if($this->stream->write($remoteData)!==strlen($remoteData)){
throw new\RuntimeException('Unable to cache the entire read from the remote stream');
}
}
return$data;
}
function write(string$string):int
{
$overflow=Integers::add(strlen($string),$this->tell())-$this->remoteStream->tell();
if($overflow>0){
$this->skipReadBytes=max($this->skipReadBytes,$overflow);
}
return$this->stream->write($string);
}
function eof():bool
{
return$this->stream->eof()&&$this->remoteStream->eof();
}
function detach(){
if($this->detached){
return;
}
$position=$this->tell();
$this->cacheEntireStream();
$this->stream->seek($position);
$resource=$this->stream->detach();
$this->detached=true;
return$resource;
}
function close():void
{
if($this->closed){
return;
}
$closeCache=!$this->detached;
$this->closed=true;
$this->detached=true;
$exception=null;
try{
$this->remoteStream->close();
}catch(\Throwable$e){
$exception=$e;
}
if($closeCache){
try{
$this->stream->close();
}catch(\Throwable$e){
if($exception===null){
$exception=$e;
}
}
}
if($exception!==null){
throw$exception;
}
}
private function cacheEntireStream():int
{
$target=new FnStream(['write'=>'strlen']);
Utils::copyToStream($this,$target);
return$this->tell();
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class DiagnosticValue
{
private function __construct(){
}
static function escape(string$value):string
{
$escaped=\preg_replace_callback('/[\x{0000}-\x{001F}\x{007F}-\x{009F}]/u',static function(array$matches):string{
$character=$matches[0];
$codePoint=\strlen($character)===1?\ord($character):\ord($character[1]);
return\sprintf('\\x%02X',$codePoint);
},$value
);
return$escaped??self::escapeBytes($value);
}
private static function escapeBytes(string$value):string
{
$escaped='';
for($offset=0,$length=\strlen($value);$offset<$length;++$offset){
$byte=\ord($value[$offset]);
if($byte>=32&&$byte<=126){
$escaped.=$value[$offset];
continue;
}
$escaped.=\sprintf('\\x%02X',$byte);
}
return$escaped;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class DroppingStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private int$maxLength;
private StreamInterface$stream;
function __construct(StreamInterface$stream,int$maxLength){
$this->stream=$stream;
$this->maxLength=Integers::assertNonNegativeInteger($maxLength,'Maximum length');
}
function write(string$string):int
{
$diff=$this->maxLength-$this->stream->getSize();
if($diff<=0){
return 0;
}
if(strlen($string)<$diff){
return$this->stream->write($string);
}
return$this->stream->write(substr($string,0,$diff));
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7\Exception;
use InvalidArgumentException;
class MalformedUriException extends InvalidArgumentException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7\Exception;
use RuntimeException;
class TimeoutException extends RuntimeException
{
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
#[\AllowDynamicProperties]final class FnStream implements StreamInterface
{
use NonSerializableStreamTrait;
private const SLOTS=['__toString','close','detach','rewind','getSize','tell','eof','isSeekable','seek','isWritable','write','isReadable','read','getContents','getMetadata',];
private array$methods;
private bool$detached=false;
function __construct(array$methods){
$this->methods=$methods;
foreach($methods as$name=>$fn){
$this->{'_fn_'.$name}=$fn;
}
}
function __get(string$name):void
{
throw new\BadMethodCallException(\sprintf('%s() is not implemented in the FnStream',DiagnosticValue::escape(str_replace('_fn_','',$name))));
}
function __destruct(){
if($this->detached||!isset($this->_fn_close)){
return;
}
try{
$this->close();
}catch(\Throwable$e){
}
}
function __wakeup():void
{
$this->methods=[];
$this->detached=true;
throw new\LogicException(static::class.' should never be unserialized');
}
function __unserialize(array$data):void
{
$this->methods=[];
$this->detached=true;
throw new\LogicException(static::class.' should never be unserialized');
}
static function decorate(StreamInterface$stream,array$methods):self
{
foreach(array_diff(self::SLOTS,array_keys($methods))as$diff){
$callable=[$stream,$diff];
$methods[$diff]=$callable;
}
return new self($methods);
}
function __toString():string
{
$this->assertAttached();
return($this->_fn___toString)();
}
function close():void
{
if($this->detached){
return;
}
$close=$this->_fn_close;
$this->detached=true;
$close();
}
function detach(){
if($this->detached){
return;
}
$detach=$this->_fn_detach;
$result=$detach();
$this->detached=true;
return$result;
}
function getSize():?int
{
if($this->detached){
return;
}
return($this->_fn_getSize)();
}
function tell():int
{
$this->assertAttached();
return($this->_fn_tell)();
}
function eof():bool
{
$this->assertAttached();
return($this->_fn_eof)();
}
function isSeekable():bool
{
if($this->detached){
return false;
}
return($this->_fn_isSeekable)();
}
function rewind():void
{
$this->assertAttached();
($this->_fn_rewind)();
}
function seek(int$offset,int$whence=SEEK_SET):void
{
$this->assertAttached();
($this->_fn_seek)($offset,$whence);
}
function isWritable():bool
{
if($this->detached){
return false;
}
return($this->_fn_isWritable)();
}
function write(string$string):int
{
$this->assertAttached();
return($this->_fn_write)($string);
}
function isReadable():bool
{
if($this->detached){
return false;
}
return($this->_fn_isReadable)();
}
function read(int$length):string
{
$this->assertAttached();
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
return($this->_fn_read)($length);
}
function getContents():string
{
$this->assertAttached();
return($this->_fn_getContents)();
}
function getMetadata(?string$key=null){
if($this->detached){
return$key===null?[]:null;
}
return($this->_fn_getMetadata)($key);
}
private function assertAttached():void
{
if($this->detached){
throw new\RuntimeException('Stream is detached');
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class Header
{
private function __construct(){
}
static function parse($header):array
{
static$trimmed="\"'  \n\t\r";
$params=$matches=[];
foreach((array)$header as$value){
foreach(self::splitList($value)as$val){
$part=[];
foreach(self::splitParameters($val)as$kvp){
$count=preg_match_all('/<[^>]+>|[^=]+/',$kvp,$matches);
if($count===false){
throw new\RuntimeException('Unable to parse header parameters: '.preg_last_error_msg());
}
if($count!==0){
$m=$matches[0];
if(isset($m[1])){
$part[trim($m[0],$trimmed)]=trim($m[1],$trimmed);
}else{
$part[]=trim($m[0],$trimmed);
}
}
}
if($part){
$params[]=$part;
}
}
}
return$params;
}
private static function splitParameters(string$value):array
{
$values=[];
$start=0;
$isQuoted=false;
$isEscaped=false;
for($i=0,$max=\strlen($value);$i<$max;++$i){
$char=$value[$i];
if($isEscaped){
$isEscaped=false;
continue;
}
if($isQuoted&&$char==='\\'){
$isEscaped=true;
continue;
}
if($char==='"'){
$isQuoted=!$isQuoted;
continue;
}
if(!$isQuoted&&$char===';'){
$values[]=\substr($value,$start,$i-$start);
$start=$i+1;
}
}
$values[]=\substr($value,$start);
return$values;
}
static function splitList($values):array
{
if(!\is_array($values)){
$values=[$values];
}
$result=[];
foreach($values as$value){
if(!\is_string($value)){
throw new\TypeError('$header must either be a string or an array containing strings.');
}
$v='';
$isQuoted=false;
$isEscaped=false;
for($i=0,$max=\strlen($value);$i<$max;++$i){
if($isEscaped){
$v.=$value[$i];
$isEscaped=false;
continue;
}
if(!$isQuoted&&$value[$i]===','){
$v=\trim($v," \t\n\r");
if($v!==''){
$result[]=$v;
}
$v='';
continue;
}
if($isQuoted&&$value[$i]==='\\'){
$isEscaped=true;
$v.=$value[$i];
continue;
}
if($value[$i]==='"'){
$isQuoted=!$isQuoted;
$v.=$value[$i];
continue;
}
$v.=$value[$i];
}
$v=\trim($v," \t\n\r");
if($v!==''){
$result[]=$v;
}
}
return$result;
}
}
namespace Psr\Http\Message;
interface RequestFactoryInterface
{
function createRequest(string$method,$uri):RequestInterface;
}
namespace Psr\Http\Message;
interface ResponseFactoryInterface
{
function createResponse(int$code=200,string$reasonPhrase=''):ResponseInterface;
}
namespace Psr\Http\Message;
interface ServerRequestFactoryInterface
{
function createServerRequest(string$method,$uri,array$serverParams=[]):ServerRequestInterface;
}
namespace Psr\Http\Message;
interface StreamFactoryInterface
{
function createStream(string$content=''):StreamInterface;
function createStreamFromFile(string$filename,string$mode='r'):StreamInterface;
function createStreamFromResource($resource):StreamInterface;
}
namespace Psr\Http\Message;
interface UploadedFileFactoryInterface
{
function createUploadedFile(StreamInterface$stream,?int$size=null,int$error=\UPLOAD_ERR_OK,?string$clientFilename=null,?string$clientMediaType=null
):UploadedFileInterface;
}
namespace Psr\Http\Message;
interface UriFactoryInterface
{
function createUri(string$uri=''):UriInterface;
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Http\Message\UploadedFileInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
final class HttpFactory implements RequestFactoryInterface,ResponseFactoryInterface,ServerRequestFactoryInterface,StreamFactoryInterface,UploadedFileFactoryInterface,UriFactoryInterface
{
function createUploadedFile(StreamInterface$stream,?int$size=null,int$error=\UPLOAD_ERR_OK,?string$clientFilename=null,?string$clientMediaType=null
):UploadedFileInterface{
if($size===null){
$size=$stream->getSize();
}
return new UploadedFile($stream,Integers::assertOptionalNonNegativeSize($size,'Uploaded file size'),$error,$clientFilename,$clientMediaType
);
}
function createStream(string$content=''):StreamInterface
{
return Utils::streamFor($content);
}
function createStreamFromFile(string$file,string$mode='r'):StreamInterface
{
try{
$resource=Utils::tryFopen($file,$mode);
}catch(\RuntimeException$e){
if(''===$mode||false===\in_array($mode[0],['r','w','a','x','c'],true)){
throw new\InvalidArgumentException(sprintf('Invalid file opening mode: %s',DiagnosticValue::escape($mode)),0,$e);
}
throw$e;
}
return Utils::streamFor($resource);
}
function createStreamFromResource($resource):StreamInterface
{
return Utils::streamFor($resource);
}
function createServerRequest(string$method,$uri,#[\SensitiveParameter]array$serverParams=[]):ServerRequestInterface{
if(empty($method)){
if(!empty($serverParams['REQUEST_METHOD'])){
$method=$serverParams['REQUEST_METHOD'];
}else{
throw new\InvalidArgumentException('Cannot determine HTTP method');
}
}
return new ServerRequest($method,$uri,[],null,'1.1',$serverParams);
}
function createResponse(int$code=200,string$reasonPhrase=''):ResponseInterface
{
return new Response($code,[],null,'1.1',$reasonPhrase);
}
function createRequest(string$method,$uri):RequestInterface
{
return new Request($method,$uri);
}
function createUri(string$uri=''):UriInterface
{
return new Uri($uri);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use Psr\Http\Message\StreamInterface;
final class InflateStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private StreamInterface$stream;
private?StreamInterface$source;
private?ReadFailureCapturingStream$capturingSource;
function __construct(StreamInterface$stream){
$this->source=$stream;
$this->capturingSource=new ReadFailureCapturingStream($stream);
$resource=StreamWrapper::getResource($this->capturingSource);
stream_filter_append($resource,'zlib.inflate',STREAM_FILTER_READ,['window'=>15+32]);
$this->stream=$stream->isSeekable()?new Stream($resource):new NoSeekStream(new Stream($resource));
}
function eof():bool
{
return($this->capturingSource===null||!$this->capturingSource->hasReadFailure())&&$this->stream->eof();
}
function read(int$length):string
{
if($length<=0||$this->source===null||$this->capturingSource===null){
return$this->stream->read($length);
}
$failure=$this->capturingSource->takeReadFailure();
if($failure===null){
try{
$data=$this->stream->read($length);
}catch(TimeoutException$e){
throw$e;
}catch(\RuntimeException$e){
if(StreamTimeout::isReadTimedOut($this->source)){
throw new TimeoutException('Unable to read from stream: timed out',0,$e);
}
throw$e;
}
if($data!==''){
return$data;
}
$failure=$this->capturingSource->takeReadFailure();
}
if($failure instanceof TimeoutException||StreamTimeout::isReadTimedOut($this->source)){
throw new TimeoutException('Unable to read from stream: timed out',0,$failure);
}
if($failure!==null){
throw new\RuntimeException('Unable to read from stream',0,$failure);
}
return'';
}
function close():void
{
$source=$this->source;
$this->source=null;
$this->capturingSource=null;
$exception=null;
try{
$this->stream->close();
}catch(\Throwable$e){
$exception=$e;
}
if($source!==null){
try{
$source->close();
}catch(\Throwable$e){
if($exception===null){
$exception=$e;
}
}
}
if($exception!==null){
throw$exception;
}
}
function detach(){
$this->source=null;
if($this->capturingSource!==null){
$this->capturingSource->stopCapturing();
$this->capturingSource=null;
}
return$this->stream->detach();
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class Integers
{
private function __construct(){
}
static function add(int$a,int$b):int
{
if($a<0||$b<0){
throw new\InvalidArgumentException('Integer operands must be non-negative');
}
if($b>\PHP_INT_MAX-$a){
throw new\OverflowException('Stream byte count exceeds the maximum integer size supported on this platform');
}
return$a+$b;
}
static function addSigned(int$base,int$delta):int
{
if($base<0){
throw new\InvalidArgumentException('Stream offset must be non-negative');
}
if($delta>0&&$delta>\PHP_INT_MAX-$base){
throw new\OverflowException('Stream offset exceeds the maximum integer size supported on this platform');
}
$value=$base+$delta;
if($value<0){
throw new\RuntimeException('Stream offset must be non-negative');
}
return$value;
}
static function assertEngineInteger($value,string$what):?int
{
if($value===false||$value===null){
return;
}
if(!\is_int($value)||$value<0){
throw new\OverflowException($what.' exceeds the maximum integer size supported on this platform');
}
return$value;
}
static function assertOptionalNonNegativeSize($value,string$name):?int
{
if($value===null){
return;
}
if(!\is_int($value)||$value<0){
throw new\InvalidArgumentException($name.' must be a non-negative integer or null');
}
return$value;
}
static function assertNonNegativeInteger($value,string$name):int
{
if(!\is_int($value)||$value<0){
throw new\InvalidArgumentException($name.' must be a non-negative integer');
}
return$value;
}
static function assertLimitInteger($value,string$name):int
{
if(!\is_int($value)||$value<-1){
throw new\InvalidArgumentException($name.' must be -1 or a non-negative integer');
}
return$value;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class LazyOpenStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private string$filename;
private string$mode;
private StreamInterface$stream;
function __construct(string$filename,string$mode){
$this->filename=$filename;
$this->mode=$mode;
unset($this->stream);
}
function __unserialize(array$data):void
{
$this->stream=new BufferStream;
throw new\LogicException(static::class.' should never be unserialized');
}
protected function createStream():StreamInterface
{
return Utils::streamFor(Utils::tryFopen($this->filename,$this->mode));
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class LimitStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private int$offset;
private int$limit;
private StreamInterface$stream;
function __construct(StreamInterface$stream,int$limit=-1,int$offset=0
){
$this->stream=$stream;
$this->setLimit($limit);
$this->setOffset($offset);
}
function eof():bool
{
if($this->stream->eof()){
return true;
}
if($this->limit===-1){
return false;
}
return$this->stream->tell()>=Integers::add($this->offset,$this->limit);
}
function getSize():?int
{
if(null===($length=$this->stream->getSize())){
return;
}
$size=$length-$this->offset;
if($this->limit!==-1){
$size=min($this->limit,$size);
}
return max(0,$size);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
if($whence!==SEEK_SET||$offset<0){
throw new\RuntimeException(sprintf('Cannot seek to offset %s with whence %s',$offset,$whence
));
}
$offset=Integers::add($this->offset,$offset);
if($this->limit!==-1){
$upperBound=Integers::add($this->offset,$this->limit);
if($offset>$upperBound){
$offset=$upperBound;
}
}
$this->stream->seek($offset);
}
function tell():int
{
return$this->stream->tell()-$this->offset;
}
function setOffset(int$offset):void
{
$offset=Integers::assertNonNegativeInteger($offset,'Offset');
$current=$this->stream->tell();
if($current===$offset){
$this->offset=$offset;
return;
}
if($this->stream->isSeekable()){
$this->stream->seek($offset);
$this->offset=$offset;
return;
}
if($current>$offset){
throw new\RuntimeException("Could not seek to stream offset $offset");
}
while($current<$offset){
if($this->stream->eof()){
$this->offset=$current;
return;
}
$result=$this->stream->read($offset-$current);
if($result===''){
if($this->stream->eof()){
$this->offset=$current;
return;
}
throw new\RuntimeException("Could not seek to stream offset $offset");
}
$current=Integers::add($current,strlen($result));
}
$this->offset=$offset;
}
function setLimit(int$limit):void
{
$this->limit=Integers::assertLimitInteger($limit,'Limit');
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
if($this->limit===-1){
return$this->stream->read($length);
}
$remaining=Integers::add($this->offset,$this->limit)-$this->stream->tell();
if($remaining>0){
return$this->stream->read(min($remaining,$length));
}
return'';
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
final class Message
{
private const DEFAULT_BODY_SUMMARY_TRUNCATE_AT=120;
private function __construct(){
}
static function toString(MessageInterface$message):string
{
if($message instanceof RequestInterface){
$msg=trim($message->getMethod().' '.$message->getRequestTarget()," \n\r\t\0\x0B").' HTTP/'.$message->getProtocolVersion();
if(!$message->hasHeader('host')){
$msg.="\r\nHost: ".self::hostHeaderFromUri($message->getUri());
}
}elseif($message instanceof ResponseInterface){
$msg='HTTP/'.$message->getProtocolVersion().' '.$message->getStatusCode().' '.$message->getReasonPhrase();
}else{
throw new\InvalidArgumentException('Unknown message type');
}
foreach($message->getHeaders()as$name=>$values){
if(is_string($name)&&Utils::asciiToLower($name)==='set-cookie'){
foreach($values as$value){
$msg.="\r\n{$name}: ".$value;
}
}else{
$msg.="\r\n{$name}: ".join(', ',$values);
}
}
return"{$msg}\r\n\r\n".$message->getBody();
}
private static function hostHeaderFromUri(UriInterface$uri):string
{
$host=$uri->getHost();
if($host===''){
return'';
}
Uri::assertValidHost($host);
if(($port=$uri->getPort())!==null){
$host.=':'.$port;
}
return$host;
}
static function bodySummary(MessageInterface$message,?int$truncateAt=null):?string
{
$truncateAt??=self::DEFAULT_BODY_SUMMARY_TRUNCATE_AT;
$body=$message->getBody();
if(!$body->isSeekable()||!$body->isReadable()){
return;
}
$size=$body->getSize();
if($size===0){
return;
}
$position=$body->tell();
try{
$body->rewind();
$summary=$body->read($truncateAt);
if($size>$truncateAt){
if(preg_match('//u',$summary)!==1){
$summary=self::trimTrailingIncompleteUtf8Character($summary,$body->read(3));
}
$summary.=' (truncated...)';
}
}finally{
$body->seek($position);
}
if(preg_match('/[^\pL\pM\pN\pP\pS\pZ\n\r\t]/u',$summary)!==0){
return;
}
return$summary;
}
private static function trimTrailingIncompleteUtf8Character(string$summary,string$lookahead):string
{
$length=strlen($summary);
if($length===0){
return$summary;
}
$start=$length-1;
while($start>=0){
$byte=ord($summary[$start]);
if($byte<128||$byte>191){
break;
}
--$start;
}
if($start<0){
return$summary;
}
$lead=ord($summary[$start]);
if($lead>=194&&$lead<=223){
$expectedLength=2;
}elseif($lead>=224&&$lead<=239){
$expectedLength=3;
}elseif($lead>=240&&$lead<=244){
$expectedLength=4;
}else{
return$summary;
}
$availableLength=$length-$start;
if($availableLength>=$expectedLength){
return$summary;
}
$sequence=substr($summary,$start).substr($lookahead,0,$expectedLength-$availableLength);
if(strlen($sequence)!==$expectedLength||preg_match('//u',$sequence)!==1){
return$summary;
}
return substr($summary,0,$start);
}
static function rewindBody(MessageInterface$message):void
{
$body=$message->getBody();
if($body->tell()){
$body->rewind();
}
}
static function parseMessage(string$message):array
{
return MessageParser::parseMessage($message);
}
static function parseRequestUri(string$path,array$headers):string
{
return MessageParser::parseRequestUri($path,$headers);
}
static function parseRequest(string$message):RequestInterface
{
return MessageParser::parseRequest($message);
}
static function parseResponse(string$message):ResponseInterface
{
return MessageParser::parseResponse($message);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class MessageParser
{
private function __construct(){
}
static function parseMessage(string$message):array
{
if(!$message){
throw new\InvalidArgumentException('Invalid message');
}
$message=ltrim($message,"\r\n");
$messageParts=preg_split("/\r?\n\r?\n/",$message,2);
if($messageParts===false){
throw new\RuntimeException('Unable to split HTTP message: '.preg_last_error_msg());
}
if(count($messageParts)!==2){
throw new\InvalidArgumentException('Invalid message: Missing header delimiter');
}
[$rawHeaders,$body]=$messageParts;
$rawHeaders.="\r\n";
$headerParts=preg_split("/\r?\n/",$rawHeaders,2);
if($headerParts===false){
throw new\RuntimeException('Unable to split HTTP message headers: '.preg_last_error_msg());
}
if(count($headerParts)!==2){
throw new\InvalidArgumentException('Invalid message: Missing status line');
}
[$startLine,$rawHeaders]=$headerParts;
$versionMatch=preg_match('/(?:^HTTP\/|^'.Rfc9110::TOKEN_PATTERN.' '.Rfc9112::REQUEST_TARGET_PATTERN.' HTTP\/)('.Rfc9112::PROTOCOL_VERSION_PATTERN.')/i',$startLine,$matches
);
if($versionMatch===false){
throw new\RuntimeException('Unable to parse HTTP start line: '.preg_last_error_msg());
}
if($versionMatch===1&&$matches[1]==='1.0'){
$rawHeaders=preg_replace(Rfc9112::HEADER_FOLD_REGEX,' ',$rawHeaders);
if($rawHeaders===null){
throw new\RuntimeException('Unable to unfold HTTP headers: '.preg_last_error_msg());
}
}
$count=preg_match_all(Rfc9112::HEADER_REGEX,$rawHeaders,$headerLines,PREG_SET_ORDER);
if($count===false){
throw new\RuntimeException('Unable to parse HTTP headers: '.preg_last_error_msg());
}
if($count!==substr_count($rawHeaders,"\n")){
$hasFoldedHeader=preg_match(Rfc9112::HEADER_FOLD_REGEX,$rawHeaders);
if($hasFoldedHeader===false){
throw new\RuntimeException('Unable to inspect HTTP header folding: '.preg_last_error_msg());
}
if($hasFoldedHeader===1){
throw new\InvalidArgumentException('Invalid header syntax: Obsolete line folding');
}
throw new\InvalidArgumentException('Invalid header syntax');
}
$headers=[];
foreach($headerLines as$headerLine){
$headers[$headerLine[1]][]=$headerLine[2];
}
return['start-line'=>$startLine,'headers'=>$headers,'body'=>$body,];
}
static function parseRequestUri(string$path,array$headers):string
{
$host=self::getHostFromHeaders($headers);
if($host===null){
return self::normalizePathForOriginForm($path);
}
[$authorityHost,$port]=self::parseHostHeaderAuthority($host);
$scheme=$port===443?'https':'http';
return$scheme.'://'.self::composeAuthority($authorityHost,$port).'/'.ltrim($path,'/');
}
private static function normalizePathForOriginForm(string$path):string
{
if(str_starts_with($path,'//')){
return'/'.ltrim($path,'/');
}
return$path;
}
private static function parseHostHeaderAuthority(string$authority):array
{
$parsed=Rfc9112::parseHostHeader($authority);
if($parsed===null){
throw new\InvalidArgumentException('Invalid request string');
}
return$parsed;
}
private static function composeAuthority(string$host,?int$port):string
{
return$host.($port!==null?':'.$port:'');
}
private static function getHostFromHeaders(array$headers):?string
{
$host=self::getSingleHostHeader($headers);
if($host===null){
return;
}
self::parseHostHeaderAuthority($host);
return$host;
}
private static function getSingleHostHeader(array$headers):?string
{
$host=null;
$found=false;
foreach($headers as$name=>$values){
if(Utils::asciiToLower((string)$name)!=='host'){
continue;
}
if($found||!is_array($values)||count($values)!==1){
throw new\InvalidArgumentException('Invalid request string');
}
$found=true;
$host=reset($values);
}
if(!$found){
return;
}
if(!is_string($host)){
throw new\InvalidArgumentException('Invalid request string');
}
return$host;
}
private static function parseRequestAuthorityUri(array$headers):string
{
$host=self::getHostFromHeaders($headers);
if($host===null){
return'';
}
[$authorityHost,$port]=self::parseHostHeaderAuthority($host);
$scheme=$port===443?'https':'http';
return$scheme.'://'.self::composeAuthority($authorityHost,$port);
}
static function parseRequest(string$message):RequestInterface
{
$data=self::parseMessage($message);
$matches=[];
$matched=preg_match('/^(?P<method>'.Rfc9110::TOKEN_PATTERN.') (?P<target>'.Rfc9112::REQUEST_TARGET_PATTERN.') HTTP\/(?P<version>'.Rfc9112::PROTOCOL_VERSION_PATTERN.')$/D',$data['start-line'],$matches
);
if($matched===false){
throw new\RuntimeException('Unable to parse request start line: '.preg_last_error_msg());
}
if($matched===0){
throw new\InvalidArgumentException('Invalid request string');
}
self::getHostFromHeaders($data['headers']);
if(str_starts_with($matches['target'],'/')){
return new Request($matches['method'],self::parseRequestUri($matches['target'],$data['headers']),$data['headers'],$data['body'],$matches['version']);
}
$absoluteFormUri=self::parseAbsoluteFormRequestTarget($matches['target']);
if($absoluteFormUri!==null){
return(new Request($matches['method'],$absoluteFormUri,$data['headers'],$data['body'],$matches['version']))->withRequestTarget($matches['target']);
}
if(Rfc9112::isAsteriskFormRequestTarget($matches['method'],$matches['target'])){
return(new Request($matches['method'],self::parseRequestAuthorityUri($data['headers']),$data['headers'],$data['body'],$matches['version']))->withRequestTarget($matches['target']);
}
$connectUri=self::parseConnectAuthorityFormRequestTarget($matches['method'],$matches['target']);
if($connectUri!==null){
return(new Request($matches['method'],$connectUri,$data['headers'],$data['body'],$matches['version']))->withRequestTarget($matches['target']);
}
throw new\InvalidArgumentException('Invalid request string');
}
private static function parseAbsoluteFormRequestTarget(string$target):?Uri
{
if(!Rfc9112::isAbsoluteFormRequestTarget($target)){
return;
}
$authority=substr($target,strpos($target,'//')+2);
$authority=substr($authority,0,strcspn($authority,'/?#'));
if(str_contains($authority,'@')){
return;
}
try{
$uri=new Uri($target);
}catch(\InvalidArgumentException$e){
return;
}
if($uri->getHost()===''){
return;
}
try{
self::parseHostHeaderAuthority(self::composeAuthority($uri->getHost(),$uri->getPort()));
}catch(\InvalidArgumentException$e){
return;
}
return$uri;
}
private static function parseConnectAuthorityFormRequestTarget(string$method,string$target):?Uri
{
if(!Rfc9112::isConnectAuthorityFormRequestTarget($method,$target)){
return;
}
$parsed=Rfc9112::parseHostHeader($target);
if($parsed===null){
return;
}
[$host,$port]=$parsed;
if($port===null){
return;
}
try{
return new Uri('//'.self::composeAuthority($host,$port));
}catch(\InvalidArgumentException$e){
return;
}
}
static function parseResponse(string$message):ResponseInterface
{
$data=self::parseMessage($message);
$matched=preg_match('/^HTTP\/(?P<version>'.Rfc9112::PROTOCOL_VERSION_PATTERN.') (?P<status>[1-5][0-9]{2})(?: (?P<reason>'.Rfc9110::FIELD_VALUE_PATTERN.'))?$/D',$data['start-line'],$matches
);
if($matched===false){
throw new\RuntimeException('Unable to parse response start line: '.preg_last_error_msg());
}
if($matched===0){
throw new\InvalidArgumentException(\sprintf('Invalid response string: %s',DiagnosticValue::escape($data['start-line'])));
}
return new Response((int)$matches['status'],$data['headers'],$data['body'],$matches['version'],$matches['reason']??null
);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\StreamInterface;
trait MessageTrait
{
private array$headers=[];
private array$headerNames=[];
private string$protocol='1.1';
private?StreamInterface$stream=null;
function getProtocolVersion():string
{
return$this->protocol;
}
function withProtocolVersion(string$version):MessageInterface
{
$this->assertProtocolVersion($version);
if($this->protocol===$version){
return$this;
}
$new=clone$this;
$new->protocol=$version;
return$new;
}
function getHeaders():array
{
return$this->headers;
}
function hasHeader(string$name):bool
{
return isset($this->headerNames[Utils::asciiToLower($name)]);
}
function getHeader(string$name):array
{
$header=Utils::asciiToLower($name);
if(!isset($this->headerNames[$header])){
return[];
}
$header=$this->headerNames[$header];
return$this->headers[$header];
}
function getHeaderLine(string$name):string
{
return join(', ',$this->getHeader($name));
}
function withHeader(string$name,$value):MessageInterface
{
$this->assertHeader($name);
$value=$this->normalizeHeaderValue($name,$value);
$normalized=Utils::asciiToLower($name);
$new=clone$this;
if(isset($new->headerNames[$normalized])){
unset($new->headers[$new->headerNames[$normalized]]);
}
$new->headerNames[$normalized]=$name;
$new->headers[$name]=$value;
return$new;
}
function withAddedHeader(string$name,$value):MessageInterface
{
$this->assertHeader($name);
$value=$this->normalizeHeaderValue($name,$value);
$normalized=Utils::asciiToLower($name);
$new=clone$this;
if(isset($new->headerNames[$normalized])){
$name=$this->headerNames[$normalized];
$new->headers[$name]=array_merge($this->headers[$name],$value);
}else{
$new->headerNames[$normalized]=$name;
$new->headers[$name]=$value;
}
return$new;
}
function withoutHeader(string$name):MessageInterface
{
$normalized=Utils::asciiToLower($name);
if(!isset($this->headerNames[$normalized])){
return$this;
}
$name=$this->headerNames[$normalized];
$new=clone$this;
unset($new->headers[$name],$new->headerNames[$normalized]);
return$new;
}
function getBody():StreamInterface
{
if(!$this->stream){
$this->stream=Utils::streamFor('');
}
return$this->stream;
}
function withBody(StreamInterface$body):MessageInterface
{
if($body===$this->stream){
return$this;
}
$new=clone$this;
$new->stream=$body;
return$new;
}
private function setHeaders(array$headers):void
{
$this->headerNames=$this->headers=[];
foreach($headers as$header=>$value){
$header=(string)$header;
$this->assertHeader($header);
$value=$this->normalizeHeaderValue($header,$value);
$normalized=Utils::asciiToLower($header);
if(isset($this->headerNames[$normalized])){
$header=$this->headerNames[$normalized];
$this->headers[$header]=array_merge($this->headers[$header],$value);
}else{
$this->headerNames[$normalized]=$header;
$this->headers[$header]=$value;
}
}
}
private function normalizeHeaderValue(string$header,$value):array
{
if(is_array($value)&&$value===[]){
throw new\InvalidArgumentException('Header value must be a non-empty array or string.');
}
if(!is_array($value)){
return$this->trimAndValidateHeaderValues($header,[$value]);
}
return$this->trimAndValidateHeaderValues($header,$value);
}
private function trimAndValidateHeaderValues(string$header,array$values):array
{
return array_map(function($value)use($header):string{
if(!is_string($value)){
throw new\InvalidArgumentException(sprintf('Header value must be a string or array of strings but %s provided.',\get_debug_type($value)));
}
$trimmed=trim($value," \t");
$this->assertValue($header,$trimmed);
return$trimmed;
},array_values($values));
}
private function assertHeader(string$header):void
{
if(!Rfc9110::isToken($header)){
throw new\InvalidArgumentException(sprintf('Invalid header name: %s',DiagnosticValue::escape($header)));
}
}
private function assertProtocolVersion(string$version):void
{
if(!Rfc9112::isValidProtocolVersion($version)){
throw new\InvalidArgumentException('Protocol version must be a valid HTTP version number.');
}
}
private function assertValue(string$header,string$value):void
{
if(!Rfc9110::isFieldValue($value)){
$reason=strpbrk($value,"\r\n")!==false
?'must not contain CR or LF characters':'contains an invalid control character';
throw new\InvalidArgumentException(sprintf('Header "%s" %s.',DiagnosticValue::escape($header),$reason));
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class MimeType
{
private function __construct(){
}
private const MIME_TYPES=['123'=>'application/vnd.lotus-1-2-3','1km'=>'application/vnd.1000minds.decision-model+xml','210'=>'model/step','3dml'=>'text/vnd.in3d.3dml','3ds'=>'image/x-3ds','3g2'=>'video/3gpp2','3gp'=>'video/3gpp','3gpp'=>'video/3gpp','3mf'=>'model/3mf','7z'=>'application/x-7z-compressed','7zip'=>'application/x-7z-compressed','aab'=>'application/x-authorware-bin','aac'=>'audio/aac','aam'=>'application/x-authorware-map','aas'=>'application/x-authorware-seg','abw'=>'application/x-abiword','ac'=>'application/pkix-attr-cert','ac3'=>'audio/ac3','acc'=>'application/vnd.americandynamics.acc','ace'=>'application/x-ace-compressed','acu'=>'application/vnd.acucobol','acutc'=>'application/vnd.acucorp','adp'=>'audio/adpcm','adts'=>'audio/aac','aep'=>'application/vnd.audiograph','afm'=>'application/x-font-type1','afp'=>'application/vnd.ibm.modcap','age'=>'application/vnd.age','ahead'=>'application/vnd.ahead.space','ai'=>'application/postscript','aif'=>'audio/x-aiff','aifc'=>'audio/x-aiff','aiff'=>'audio/x-aiff','air'=>'application/vnd.adobe.air-application-installer-package+zip','ait'=>'application/vnd.dvb.ait','ami'=>'application/vnd.amiga.ami','aml'=>'application/automationml-aml+xml','amlx'=>'application/automationml-amlx+zip','amr'=>'audio/amr','apk'=>'application/vnd.android.package-archive','apng'=>'image/apng','appcache'=>'text/cache-manifest','appinstaller'=>'application/appinstaller','application'=>'application/x-ms-application','appx'=>'application/appx','appxbundle'=>'application/appxbundle','apr'=>'application/vnd.lotus-approach','arc'=>'application/x-freearc','arj'=>'application/x-arj','asc'=>'application/pgp-keys','asf'=>'video/x-ms-asf','asm'=>'text/x-asm','aso'=>'application/vnd.accpac.simply.aso','asx'=>'video/x-ms-asf','atc'=>'application/vnd.acucorp','atom'=>'application/atom+xml','atomcat'=>'application/atomcat+xml','atomdeleted'=>'application/atomdeleted+xml','atomsvc'=>'application/atomsvc+xml','atx'=>'application/vnd.antix.game-component','au'=>'audio/basic','avci'=>'image/avci','avcs'=>'image/avcs','avi'=>'video/x-msvideo','avif'=>'image/avif','aw'=>'application/applixware','azf'=>'application/vnd.airzip.filesecure.azf','azs'=>'application/vnd.airzip.filesecure.azs','azv'=>'image/vnd.airzip.accelerator.azv','azw'=>'application/vnd.amazon.ebook','b16'=>'image/vnd.pco.b16','bary'=>'model/vnd.bary','bat'=>'application/x-msdownload','bcpio'=>'application/x-bcpio','bdf'=>'application/x-font-bdf','bdm'=>'application/vnd.syncml.dm+wbxml','bdo'=>'application/vnd.nato.bindingdataobject+xml','bdoc'=>'application/bdoc','bed'=>'application/vnd.realvnc.bed','bh2'=>'application/vnd.fujitsu.oasysprs','bin'=>'application/octet-stream','blb'=>'application/x-blorb','blend'=>'application/x-blender','blorb'=>'application/x-blorb','bmi'=>'application/vnd.bmi','bmml'=>'application/vnd.balsamiq.bmml+xml','bmp'=>'image/bmp','book'=>'application/vnd.framemaker','box'=>'application/vnd.previewsystems.box','boz'=>'application/x-bzip2','bpk'=>'application/octet-stream','bpmn'=>'application/octet-stream','brush'=>'application/vnd.procreate.brush','brushset'=>'application/vnd.procreate.brushset','bsp'=>'model/vnd.valve.source.compiled-map','btf'=>'image/prs.btif','btif'=>'image/prs.btif','buffer'=>'application/octet-stream','bz'=>'application/x-bzip','bz2'=>'application/x-bzip2','c'=>'text/x-c','c11amc'=>'application/vnd.cluetrust.cartomobile-config','c11amz'=>'application/vnd.cluetrust.cartomobile-config-pkg','c4d'=>'application/vnd.clonk.c4group','c4f'=>'application/vnd.clonk.c4group','c4g'=>'application/vnd.clonk.c4group','c4p'=>'application/vnd.clonk.c4group','c4u'=>'application/vnd.clonk.c4group','cab'=>'application/vnd.ms-cab-compressed','caf'=>'audio/x-caf','cap'=>'application/vnd.tcpdump.pcap','car'=>'application/vnd.curl.car','cat'=>'application/vnd.ms-pki.seccat','cb7'=>'application/x-cbr','cba'=>'application/x-cbr','cbr'=>'application/x-cbr','cbt'=>'application/x-cbr','cbz'=>'application/x-cbr','cc'=>'text/x-c','cco'=>'application/x-cocoa','cct'=>'application/x-director','ccxml'=>'application/ccxml+xml','cdbcmsg'=>'application/vnd.contact.cmsg','cdf'=>'application/x-netcdf','cdfx'=>'application/cdfx+xml','cdkey'=>'application/vnd.mediastation.cdkey','cdmia'=>'application/cdmi-capability','cdmic'=>'application/cdmi-container','cdmid'=>'application/cdmi-domain','cdmio'=>'application/cdmi-object','cdmiq'=>'application/cdmi-queue','cdx'=>'chemical/x-cdx','cdxml'=>'application/vnd.chemdraw+xml','cdy'=>'application/vnd.cinderella','cer'=>'application/pkix-cert','cfs'=>'application/x-cfs-compressed','cgm'=>'image/cgm','chat'=>'application/x-chat','chm'=>'application/vnd.ms-htmlhelp','chrt'=>'application/vnd.kde.kchart','cif'=>'chemical/x-cif','cii'=>'application/vnd.anser-web-certificate-issue-initiation','cil'=>'application/vnd.ms-artgalry','cjs'=>'application/node','cla'=>'application/vnd.claymore','class'=>'application/java-vm','cld'=>'model/vnd.cld','clkk'=>'application/vnd.crick.clicker.keyboard','clkp'=>'application/vnd.crick.clicker.palette','clkt'=>'application/vnd.crick.clicker.template','clkw'=>'application/vnd.crick.clicker.wordbank','clkx'=>'application/vnd.crick.clicker','clp'=>'application/x-msclip','cmc'=>'application/vnd.cosmocaller','cmdf'=>'chemical/x-cmdf','cml'=>'chemical/x-cml','cmp'=>'application/vnd.yellowriver-custom-menu','cmx'=>'image/x-cmx','cod'=>'application/vnd.rim.cod','coffee'=>'text/coffeescript','com'=>'application/x-msdownload','conf'=>'text/plain','cpio'=>'application/x-cpio','cpl'=>'application/cpl+xml','cpp'=>'text/x-c','cpt'=>'application/mac-compactpro','crd'=>'application/x-mscardfile','crl'=>'application/pkix-crl','crt'=>'application/x-x509-ca-cert','crx'=>'application/x-chrome-extension','cryptonote'=>'application/vnd.rig.cryptonote','csh'=>'application/x-csh','csl'=>'application/vnd.citationstyles.style+xml','csml'=>'chemical/x-csml','csp'=>'application/vnd.commonspace','csr'=>'application/octet-stream','css'=>'text/css','cst'=>'application/x-director','csv'=>'text/csv','cu'=>'application/cu-seeme','curl'=>'text/vnd.curl','cwl'=>'application/cwl','cww'=>'application/prs.cww','cxt'=>'application/x-director','cxx'=>'text/x-c','dae'=>'model/vnd.collada+xml','daf'=>'application/vnd.mobius.daf','dart'=>'application/vnd.dart','dataless'=>'application/vnd.fdsn.seed','davmount'=>'application/davmount+xml','dbf'=>'application/vnd.dbf','dbk'=>'application/docbook+xml','dcm'=>'application/dicom','dcmp'=>'application/vnd.dcmp+xml','dcr'=>'application/x-director','dcurl'=>'text/vnd.curl.dcurl','dd2'=>'application/vnd.oma.dd2+xml','ddd'=>'application/vnd.fujixerox.ddd','ddf'=>'application/vnd.syncml.dmddf+xml','dds'=>'image/vnd.ms-dds','deb'=>'application/x-debian-package','def'=>'text/plain','deploy'=>'application/octet-stream','der'=>'application/x-x509-ca-cert','dfac'=>'application/vnd.dreamfactory','dgc'=>'application/x-dgc-compressed','dib'=>'image/bmp','dic'=>'text/x-c','dir'=>'application/x-director','dis'=>'application/vnd.mobius.dis','disposition-notification'=>'message/disposition-notification','dist'=>'application/octet-stream','distz'=>'application/octet-stream','djv'=>'image/vnd.djvu','djvu'=>'image/vnd.djvu','dll'=>'application/octet-stream','dmg'=>'application/x-apple-diskimage','dmn'=>'application/octet-stream','dmp'=>'application/vnd.tcpdump.pcap','dms'=>'application/octet-stream','dna'=>'application/vnd.dna','dng'=>'image/x-adobe-dng','doc'=>'application/msword','docm'=>'application/vnd.ms-word.document.macroenabled.12','docx'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.document','dot'=>'application/msword','dotm'=>'application/vnd.ms-word.template.macroenabled.12','dotx'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.template','dp'=>'application/vnd.osgi.dp','dpg'=>'application/vnd.dpgraph','dpx'=>'image/dpx','dra'=>'audio/vnd.dra','drle'=>'image/dicom-rle','drm'=>'application/vnd.procreate.dream','dsc'=>'text/prs.lines.tag','dssc'=>'application/dssc+der','dst'=>'application/octet-stream','dtb'=>'application/x-dtbook+xml','dtd'=>'application/xml-dtd','dts'=>'audio/vnd.dts','dtshd'=>'audio/vnd.dts.hd','dump'=>'application/octet-stream','dvb'=>'video/vnd.dvb.file','dvi'=>'application/x-dvi','dwd'=>'application/atsc-dwd+xml','dwf'=>'model/vnd.dwf','dwg'=>'image/vnd.dwg','dxf'=>'image/vnd.dxf','dxp'=>'application/vnd.spotfire.dxp','dxr'=>'application/x-director','ear'=>'application/java-archive','ecelp4800'=>'audio/vnd.nuera.ecelp4800','ecelp7470'=>'audio/vnd.nuera.ecelp7470','ecelp9600'=>'audio/vnd.nuera.ecelp9600','ecma'=>'application/ecmascript','edm'=>'application/vnd.novadigm.edm','edx'=>'application/vnd.novadigm.edx','efif'=>'application/vnd.picsel','ei6'=>'application/vnd.pg.osasli','elc'=>'application/octet-stream','emf'=>'image/emf','eml'=>'message/rfc822','emma'=>'application/emma+xml','emotionml'=>'application/emotionml+xml','emz'=>'application/x-msmetafile','eol'=>'audio/vnd.digital-winds','eot'=>'application/vnd.ms-fontobject','eps'=>'application/postscript','epub'=>'application/epub+zip','es3'=>'application/vnd.eszigno3+xml','esa'=>'application/vnd.osgi.subsystem','esf'=>'application/vnd.epson.esf','et3'=>'application/vnd.eszigno3+xml','etx'=>'text/x-setext','eva'=>'application/x-eva','evy'=>'application/x-envoy','exe'=>'application/octet-stream','exi'=>'application/exi','exp'=>'application/express','exr'=>'image/aces','ext'=>'application/vnd.novadigm.ext','ez'=>'application/andrew-inset','ez2'=>'application/vnd.ezpix-album','ez3'=>'application/vnd.ezpix-package','f'=>'text/x-fortran','f4v'=>'video/mp4','f77'=>'text/x-fortran','f90'=>'text/x-fortran','facti'=>'image/vnd.blockfact.facti','fbs'=>'image/vnd.fastbidsheet','fbx'=>'application/vnd.autodesk.fbx','fcdt'=>'application/vnd.adobe.formscentral.fcdt','fcs'=>'application/vnd.isac.fcs','fdf'=>'application/fdf','fdt'=>'application/fdt+xml','fe_launch'=>'application/vnd.denovo.fcselayout-link','fg5'=>'application/vnd.fujitsu.oasysgp','fgd'=>'application/x-director','fh'=>'image/x-freehand','fh4'=>'image/x-freehand','fh5'=>'image/x-freehand','fh7'=>'image/x-freehand','fhc'=>'image/x-freehand','fig'=>'application/x-xfig','fits'=>'image/fits','flac'=>'audio/x-flac','fli'=>'video/x-fli','flo'=>'application/vnd.micrografx.flo','flv'=>'video/x-flv','flw'=>'application/vnd.kde.kivio','flx'=>'text/vnd.fmi.flexstor','fly'=>'text/vnd.fly','fm'=>'application/vnd.framemaker','fnc'=>'application/vnd.frogans.fnc','fo'=>'application/vnd.software602.filler.form+xml','for'=>'text/x-fortran','fpx'=>'image/vnd.fpx','frame'=>'application/vnd.framemaker','fsc'=>'application/vnd.fsc.weblaunch','fst'=>'image/vnd.fst','ftc'=>'application/vnd.fluxtime.clip','fti'=>'application/vnd.anser-web-funds-transfer-initiation','fvt'=>'video/vnd.fvt','fxp'=>'application/vnd.adobe.fxp','fxpl'=>'application/vnd.adobe.fxp','fzs'=>'application/vnd.fuzzysheet','g2w'=>'application/vnd.geoplan','g3'=>'image/g3fax','g3w'=>'application/vnd.geospace','gac'=>'application/vnd.groove-account','gam'=>'application/x-tads','gbr'=>'application/rpki-ghostbusters','gca'=>'application/x-gca-compressed','gdl'=>'model/vnd.gdl','gdoc'=>'application/vnd.google-apps.document','gdraw'=>'application/vnd.google-apps.drawing','ged'=>'text/vnd.familysearch.gedcom','geo'=>'application/vnd.dynageo','geojson'=>'application/geo+json','gex'=>'application/vnd.geometry-explorer','gform'=>'application/vnd.google-apps.form','ggb'=>'application/vnd.geogebra.file','ggs'=>'application/vnd.geogebra.slides','ggt'=>'application/vnd.geogebra.tool','ghf'=>'application/vnd.groove-help','gif'=>'image/gif','gim'=>'application/vnd.groove-identity-message','gjam'=>'application/vnd.google-apps.jam','glb'=>'model/gltf-binary','gltf'=>'model/gltf+json','gmap'=>'application/vnd.google-apps.map','gml'=>'application/gml+xml','gmx'=>'application/vnd.gmx','gnumeric'=>'application/x-gnumeric','gph'=>'application/vnd.flographit','gpx'=>'application/gpx+xml','gqf'=>'application/vnd.grafeq','gqs'=>'application/vnd.grafeq','gram'=>'application/srgs','gramps'=>'application/x-gramps-xml','gre'=>'application/vnd.geometry-explorer','grv'=>'application/vnd.groove-injector','grxml'=>'application/srgs+xml','gscript'=>'application/vnd.google-apps.script','gsf'=>'application/x-font-ghostscript','gsheet'=>'application/vnd.google-apps.spreadsheet','gsite'=>'application/vnd.google-apps.site','gslides'=>'application/vnd.google-apps.presentation','gtar'=>'application/x-gtar','gtm'=>'application/vnd.groove-tool-message','gtw'=>'model/vnd.gtw','gv'=>'text/vnd.graphviz','gxf'=>'application/gxf','gxt'=>'application/vnd.geonext','gz'=>'application/gzip','gzip'=>'application/gzip','h'=>'text/x-c','h261'=>'video/h261','h263'=>'video/h263','h264'=>'video/h264','hal'=>'application/vnd.hal+xml','hbci'=>'application/vnd.hbci','hbs'=>'text/x-handlebars-template','hdd'=>'application/x-virtualbox-hdd','hdf'=>'application/x-hdf','heic'=>'image/heic','heics'=>'image/heic-sequence','heif'=>'image/heif','heifs'=>'image/heif-sequence','hej2'=>'image/hej2k','held'=>'application/atsc-held+xml','hh'=>'text/x-c','hjson'=>'application/hjson','hlp'=>'application/winhlp','hpgl'=>'application/vnd.hp-hpgl','hpid'=>'application/vnd.hp-hpid','hps'=>'application/vnd.hp-hps','hqx'=>'application/mac-binhex40','htc'=>'text/x-component','htke'=>'application/vnd.kenameaapp','htm'=>'text/html','html'=>'text/html','hvd'=>'application/vnd.yamaha.hv-dic','hvp'=>'application/vnd.yamaha.hv-voice','hvs'=>'application/vnd.yamaha.hv-script','i2g'=>'application/vnd.intergeo','icc'=>'application/vnd.iccprofile','ice'=>'x-conference/x-cooltalk','icm'=>'application/vnd.iccprofile','ico'=>'image/vnd.microsoft.icon','ics'=>'text/calendar','ief'=>'image/ief','ifb'=>'text/calendar','ifm'=>'application/vnd.shana.informed.formdata','iges'=>'model/iges','igl'=>'application/vnd.igloader','igm'=>'application/vnd.insors.igm','igs'=>'model/iges','igx'=>'application/vnd.micrografx.igx','iif'=>'application/vnd.shana.informed.interchange','img'=>'application/octet-stream','imp'=>'application/vnd.accpac.simply.imp','ims'=>'application/vnd.ms-ims','in'=>'text/plain','indd'=>'application/x-indesign','ini'=>'text/plain','ink'=>'application/inkml+xml','inkml'=>'application/inkml+xml','install'=>'application/x-install-instructions','iota'=>'application/vnd.astraea-software.iota','ipfix'=>'application/ipfix','ipk'=>'application/vnd.shana.informed.package','ipynb'=>'application/x-ipynb+json','irm'=>'application/vnd.ibm.rights-management','irp'=>'application/vnd.irepository.package+xml','iso'=>'application/x-iso9660-image','itp'=>'application/vnd.shana.informed.formtemplate','its'=>'application/its+xml','ivp'=>'application/vnd.immervision-ivp','ivu'=>'application/vnd.immervision-ivu','jad'=>'text/vnd.sun.j2me.app-descriptor','jade'=>'text/jade','jaii'=>'image/jaii','jais'=>'image/jais','jam'=>'application/vnd.jam','jar'=>'application/java-archive','jardiff'=>'application/x-java-archive-diff','java'=>'text/x-java-source','jfif'=>'image/jpeg','jhc'=>'image/jphc','jisp'=>'application/vnd.jisp','jls'=>'image/jls','jlt'=>'application/vnd.hp-jlyt','jng'=>'image/x-jng','jnlp'=>'application/x-java-jnlp-file','joda'=>'application/vnd.joost.joda-archive','jp2'=>'image/jp2','jpe'=>'image/jpeg','jpeg'=>'image/jpeg','jpf'=>'image/jpx','jpg'=>'image/jpeg','jpg2'=>'image/jp2','jpgm'=>'image/jpm','jpgv'=>'video/jpeg','jph'=>'image/jph','jpm'=>'image/jpm','jpx'=>'image/jpx','js'=>'text/javascript','json'=>'application/json','json5'=>'application/json5','jsonld'=>'application/ld+json','jsonml'=>'application/jsonml+json','jsx'=>'text/jsx','jt'=>'model/jt','jxl'=>'image/jxl','jxr'=>'image/jxr','jxra'=>'image/jxra','jxrs'=>'image/jxrs','jxs'=>'image/jxs','jxsc'=>'image/jxsc','jxsi'=>'image/jxsi','jxss'=>'image/jxss','kar'=>'audio/midi','karbon'=>'application/vnd.kde.karbon','kbl'=>'application/kbl+xml','kdb'=>'application/octet-stream','kdbx'=>'application/x-keepass2','key'=>'application/vnd.apple.keynote','kfo'=>'application/vnd.kde.kformula','kia'=>'application/vnd.kidspiration','kml'=>'application/vnd.google-earth.kml+xml','kmz'=>'application/vnd.google-earth.kmz','kne'=>'application/vnd.kinar','knp'=>'application/vnd.kinar','kon'=>'application/vnd.kde.kontour','kpr'=>'application/vnd.kde.kpresenter','kpt'=>'application/vnd.kde.kpresenter','kpxx'=>'application/vnd.ds-keypoint','ksp'=>'application/vnd.kde.kspread','ktr'=>'application/vnd.kahootz','ktx'=>'image/ktx','ktx2'=>'image/ktx2','ktz'=>'application/vnd.kahootz','kwd'=>'application/vnd.kde.kword','kwt'=>'application/vnd.kde.kword','lasxml'=>'application/vnd.las.las+xml','latex'=>'application/x-latex','lbd'=>'application/vnd.llamagraphics.life-balance.desktop','lbe'=>'application/vnd.llamagraphics.life-balance.exchange+xml','les'=>'application/vnd.hhe.lesson-player','less'=>'text/less','lgr'=>'application/lgr+xml','lha'=>'application/x-lzh-compressed','link66'=>'application/vnd.route66.link66+xml','list'=>'text/plain','list3820'=>'application/vnd.ibm.modcap','listafp'=>'application/vnd.ibm.modcap','litcoffee'=>'text/coffeescript','lnk'=>'application/x-ms-shortcut','log'=>'text/plain','lostxml'=>'application/lost+xml','lottie'=>'application/zip+dotlottie','lrf'=>'application/octet-stream','lrm'=>'application/vnd.ms-lrm','ltf'=>'application/vnd.frogans.ltf','lua'=>'text/x-lua','luac'=>'application/x-lua-bytecode','lvp'=>'audio/vnd.lucent.voice','lwp'=>'application/vnd.lotus-wordpro','lzh'=>'application/x-lzh-compressed','m13'=>'application/x-msmediaview','m14'=>'application/x-msmediaview','m1v'=>'video/mpeg','m21'=>'application/mp21','m2a'=>'audio/mpeg','m2t'=>'video/mp2t','m2ts'=>'video/mp2t','m2v'=>'video/mpeg','m3a'=>'audio/mpeg','m3u'=>'audio/x-mpegurl','m3u8'=>'application/vnd.apple.mpegurl','m4a'=>'audio/mp4','m4b'=>'audio/mp4','m4p'=>'application/mp4','m4s'=>'video/iso.segment','m4u'=>'video/vnd.mpegurl','m4v'=>'video/x-m4v','ma'=>'application/mathematica','mads'=>'application/mads+xml','maei'=>'application/mmt-aei+xml','mag'=>'application/vnd.ecowin.chart','maker'=>'application/vnd.framemaker','man'=>'text/troff','manifest'=>'text/cache-manifest','map'=>'application/json','mar'=>'application/octet-stream','markdown'=>'text/markdown','mathml'=>'application/mathml+xml','mb'=>'application/mathematica','mbk'=>'application/vnd.mobius.mbk','mbox'=>'application/mbox','mc1'=>'application/vnd.medcalcdata','mcd'=>'application/vnd.mcd','mcurl'=>'text/vnd.curl.mcurl','md'=>'text/markdown','mdb'=>'application/x-msaccess','mdi'=>'image/vnd.ms-modi','mdx'=>'text/mdx','me'=>'text/troff','mesh'=>'model/mesh','meta4'=>'application/metalink4+xml','metalink'=>'application/metalink+xml','mets'=>'application/mets+xml','mfm'=>'application/vnd.mfmp','mft'=>'application/rpki-manifest','mgp'=>'application/vnd.osgeo.mapguide.package','mgz'=>'application/vnd.proteus.magazine','mht'=>'message/rfc822','mhtml'=>'message/rfc822','mid'=>'audio/midi','midi'=>'audio/midi','mie'=>'application/x-mie','mif'=>'application/vnd.mif','mime'=>'message/rfc822','mj2'=>'video/mj2','mjp2'=>'video/mj2','mjs'=>'text/javascript','mk3d'=>'video/matroska-3d','mka'=>'audio/matroska','mkd'=>'text/x-markdown','mks'=>'video/x-matroska','mkv'=>'video/matroska','mlp'=>'application/vnd.dolby.mlp','mmd'=>'application/vnd.chipnuts.karaoke-mmd','mmf'=>'application/vnd.smaf','mml'=>'text/mathml','mmr'=>'image/vnd.fujixerox.edmics-mmr','mng'=>'video/x-mng','mny'=>'application/x-msmoney','mobi'=>'application/x-mobipocket-ebook','mods'=>'application/mods+xml','mov'=>'video/quicktime','movie'=>'video/x-sgi-movie','mp2'=>'audio/mpeg','mp21'=>'application/mp21','mp2a'=>'audio/mpeg','mp3'=>'audio/mpeg','mp4'=>'video/mp4','mp4a'=>'audio/mp4','mp4s'=>'application/mp4','mp4v'=>'video/mp4','mpc'=>'application/vnd.mophun.certificate','mpd'=>'application/dash+xml','mpe'=>'video/mpeg','mpeg'=>'video/mpeg','mpf'=>'application/media-policy-dataset+xml','mpg'=>'video/mpeg','mpg4'=>'video/mp4','mpga'=>'audio/mpeg','mpkg'=>'application/vnd.apple.installer+xml','mpm'=>'application/vnd.blueice.multipass','mpn'=>'application/vnd.mophun.application','mpp'=>'application/vnd.ms-project','mpt'=>'application/vnd.ms-project','mpy'=>'application/vnd.ibm.minipay','mqy'=>'application/vnd.mobius.mqy','mrc'=>'application/marc','mrcx'=>'application/marcxml+xml','ms'=>'text/troff','mscml'=>'application/mediaservercontrol+xml','mseed'=>'application/vnd.fdsn.mseed','mseq'=>'application/vnd.mseq','msf'=>'application/vnd.epson.msf','msg'=>'application/vnd.ms-outlook','msh'=>'model/mesh','msi'=>'application/octet-stream','msix'=>'application/msix','msixbundle'=>'application/msixbundle','msl'=>'application/vnd.mobius.msl','msm'=>'application/octet-stream','msp'=>'application/octet-stream','msty'=>'application/vnd.muvee.style','mtl'=>'model/mtl','mts'=>'video/mp2t','mus'=>'application/vnd.musician','musd'=>'application/mmt-usd+xml','musicxml'=>'application/vnd.recordare.musicxml+xml','mvb'=>'application/x-msmediaview','mvt'=>'application/vnd.mapbox-vector-tile','mwf'=>'application/vnd.mfer','mxf'=>'application/mxf','mxl'=>'application/vnd.recordare.musicxml','mxmf'=>'audio/mobile-xmf','mxml'=>'application/xv+xml','mxs'=>'application/vnd.triscape.mxs','mxu'=>'video/vnd.mpegurl','n-gage'=>'application/vnd.nokia.n-gage.symbian.install','n3'=>'text/n3','nb'=>'application/mathematica','nbp'=>'application/vnd.wolfram.player','nc'=>'application/x-netcdf','ncx'=>'application/x-dtbncx+xml','ndjson'=>'application/x-ndjson','nfo'=>'text/x-nfo','ngdat'=>'application/vnd.nokia.n-gage.data','nitf'=>'application/vnd.nitf','nlu'=>'application/vnd.neurolanguage.nlu','nml'=>'application/vnd.enliven','nnd'=>'application/vnd.noblenet-directory','nns'=>'application/vnd.noblenet-sealer','nnw'=>'application/vnd.noblenet-web','npx'=>'image/vnd.net-fpx','nq'=>'application/n-quads','nsc'=>'application/x-conference','nsf'=>'application/vnd.lotus-notes','nt'=>'application/n-triples','ntf'=>'application/vnd.nitf','numbers'=>'application/vnd.apple.numbers','nzb'=>'application/x-nzb','oa2'=>'application/vnd.fujitsu.oasys2','oa3'=>'application/vnd.fujitsu.oasys3','oas'=>'application/vnd.fujitsu.oasys','obd'=>'application/x-msbinder','obgx'=>'application/vnd.openblox.game+xml','obj'=>'model/obj','oda'=>'application/oda','odb'=>'application/vnd.oasis.opendocument.database','odc'=>'application/vnd.oasis.opendocument.chart','odf'=>'application/vnd.oasis.opendocument.formula','odft'=>'application/vnd.oasis.opendocument.formula-template','odg'=>'application/vnd.oasis.opendocument.graphics','odi'=>'application/vnd.oasis.opendocument.image','odm'=>'application/vnd.oasis.opendocument.text-master','odp'=>'application/vnd.oasis.opendocument.presentation','ods'=>'application/vnd.oasis.opendocument.spreadsheet','odt'=>'application/vnd.oasis.opendocument.text','oga'=>'audio/ogg','ogex'=>'model/vnd.opengex','ogg'=>'audio/ogg','ogv'=>'video/ogg','ogx'=>'application/ogg','omdoc'=>'application/omdoc+xml','one'=>'application/onenote','onea'=>'application/onenote','onepkg'=>'application/onenote','onetmp'=>'application/onenote','onetoc'=>'application/onenote','onetoc2'=>'application/onenote','opf'=>'application/oebps-package+xml','opml'=>'text/x-opml','oprc'=>'application/vnd.palm','opus'=>'audio/ogg','org'=>'application/vnd.lotus-organizer','osf'=>'application/vnd.yamaha.openscoreformat','osfpvg'=>'application/vnd.yamaha.openscoreformat.osfpvg+xml','osm'=>'application/vnd.openstreetmap.data+xml','otc'=>'application/vnd.oasis.opendocument.chart-template','otf'=>'font/otf','otg'=>'application/vnd.oasis.opendocument.graphics-template','oth'=>'application/vnd.oasis.opendocument.text-web','oti'=>'application/vnd.oasis.opendocument.image-template','otp'=>'application/vnd.oasis.opendocument.presentation-template','ots'=>'application/vnd.oasis.opendocument.spreadsheet-template','ott'=>'application/vnd.oasis.opendocument.text-template','ova'=>'application/x-virtualbox-ova','ovf'=>'application/x-virtualbox-ovf','owl'=>'application/rdf+xml','oxps'=>'application/oxps','oxt'=>'application/vnd.openofficeorg.extension','p'=>'text/x-pascal','p10'=>'application/pkcs10','p12'=>'application/x-pkcs12','p21'=>'model/step','p7a'=>'application/x-pkcs7-signature','p7b'=>'application/x-pkcs7-certificates','p7c'=>'application/pkcs7-mime','p7e'=>'application/pkcs7-mime','p7m'=>'application/pkcs7-mime','p7r'=>'application/x-pkcs7-certreqresp','p7s'=>'application/pkcs7-signature','p8'=>'application/pkcs8','pac'=>'application/x-ns-proxy-autoconfig','pages'=>'application/vnd.apple.pages','parquet'=>'application/vnd.apache.parquet','pas'=>'text/x-pascal','paw'=>'application/vnd.pawaafile','pbd'=>'application/vnd.powerbuilder6','pbm'=>'image/x-portable-bitmap','pcap'=>'application/vnd.tcpdump.pcap','pcf'=>'application/x-font-pcf','pcl'=>'application/vnd.hp-pcl','pclxl'=>'application/vnd.hp-pclxl','pct'=>'image/x-pict','pcurl'=>'application/vnd.curl.pcurl','pcx'=>'image/vnd.zbrush.pcx','pdb'=>'application/vnd.palm','pde'=>'text/x-processing','pdf'=>'application/pdf','pem'=>'application/x-x509-user-cert','pfa'=>'application/x-font-type1','pfb'=>'application/x-font-type1','pfm'=>'application/x-font-type1','pfr'=>'application/font-tdpfr','pfx'=>'application/x-pkcs12','pgm'=>'image/x-portable-graymap','pgn'=>'application/x-chess-pgn','pgp'=>'application/pgp-encrypted','phar'=>'application/octet-stream','php'=>'application/x-httpd-php','php3'=>'application/x-httpd-php','php4'=>'application/x-httpd-php','phps'=>'application/x-httpd-php-source','phtml'=>'application/x-httpd-php','pic'=>'image/x-pict','pkg'=>'application/octet-stream','pki'=>'application/pkixcmp','pkipath'=>'application/pkix-pkipath','pkpass'=>'application/vnd.apple.pkpass','pl'=>'application/x-perl','plb'=>'application/vnd.3gpp.pic-bw-large','plc'=>'application/vnd.mobius.plc','plf'=>'application/vnd.pocketlearn','pls'=>'application/pls+xml','pm'=>'application/x-perl','pml'=>'application/vnd.ctc-posml','png'=>'image/png','pnm'=>'image/x-portable-anymap','portpkg'=>'application/vnd.macports.portpkg','pot'=>'application/vnd.ms-powerpoint','potm'=>'application/vnd.ms-powerpoint.template.macroenabled.12','potx'=>'application/vnd.openxmlformats-officedocument.presentationml.template','ppa'=>'application/vnd.ms-powerpoint','ppam'=>'application/vnd.ms-powerpoint.addin.macroenabled.12','ppd'=>'application/vnd.cups-ppd','ppm'=>'image/x-portable-pixmap','pps'=>'application/vnd.ms-powerpoint','ppsm'=>'application/vnd.ms-powerpoint.slideshow.macroenabled.12','ppsx'=>'application/vnd.openxmlformats-officedocument.presentationml.slideshow','ppt'=>'application/vnd.ms-powerpoint','pptm'=>'application/vnd.ms-powerpoint.presentation.macroenabled.12','pptx'=>'application/vnd.openxmlformats-officedocument.presentationml.presentation','pqa'=>'application/vnd.palm','prc'=>'model/prc','pre'=>'application/vnd.lotus-freelance','prf'=>'application/pics-rules','provx'=>'application/provenance+xml','ps'=>'application/postscript','psb'=>'application/vnd.3gpp.pic-bw-small','psd'=>'image/vnd.adobe.photoshop','psf'=>'application/x-font-linux-psf','pskcxml'=>'application/pskc+xml','pti'=>'image/prs.pti','ptid'=>'application/vnd.pvi.ptid1','pub'=>'application/x-mspublisher','pv'=>'application/octet-stream','pvb'=>'application/vnd.3gpp.pic-bw-var','pwn'=>'application/vnd.3m.post-it-notes','pxf'=>'application/octet-stream','pya'=>'audio/vnd.ms-playready.media.pya','pyo'=>'model/vnd.pytha.pyox','pyox'=>'model/vnd.pytha.pyox','pyv'=>'video/vnd.ms-playready.media.pyv','qam'=>'application/vnd.epson.quickanime','qbo'=>'application/vnd.intu.qbo','qfx'=>'application/vnd.intu.qfx','qps'=>'application/vnd.publishare-delta-tree','qt'=>'video/quicktime','qwd'=>'application/vnd.quark.quarkxpress','qwt'=>'application/vnd.quark.quarkxpress','qxb'=>'application/vnd.quark.quarkxpress','qxd'=>'application/vnd.quark.quarkxpress','qxl'=>'application/vnd.quark.quarkxpress','qxt'=>'application/vnd.quark.quarkxpress','ra'=>'audio/x-realaudio','ram'=>'audio/x-pn-realaudio','raml'=>'application/raml+yaml','rapd'=>'application/route-apd+xml','rar'=>'application/vnd.rar','ras'=>'image/x-cmu-raster','rcprofile'=>'application/vnd.ipunplugged.rcprofile','rdf'=>'application/rdf+xml','rdz'=>'application/vnd.data-vision.rdz','relo'=>'application/p2p-overlay+xml','rep'=>'application/vnd.businessobjects','res'=>'application/x-dtbresource+xml','rgb'=>'image/x-rgb','rif'=>'application/reginfo+xml','rip'=>'audio/vnd.rip','ris'=>'application/x-research-info-systems','rl'=>'application/resource-lists+xml','rlc'=>'image/vnd.fujixerox.edmics-rlc','rld'=>'application/resource-lists-diff+xml','rm'=>'application/vnd.rn-realmedia','rmi'=>'audio/midi','rmp'=>'audio/x-pn-realaudio-plugin','rms'=>'application/vnd.jcp.javame.midlet-rms','rmvb'=>'application/vnd.rn-realmedia-vbr','rnc'=>'application/relax-ng-compact-syntax','rng'=>'application/xml','roa'=>'application/rpki-roa','roff'=>'text/troff','rp9'=>'application/vnd.cloanto.rp9','rpm'=>'application/x-redhat-package-manager','rpss'=>'application/vnd.nokia.radio-presets','rpst'=>'application/vnd.nokia.radio-preset','rq'=>'application/sparql-query','rs'=>'application/rls-services+xml','rsa'=>'application/x-pkcs7','rsat'=>'application/atsc-rsat+xml','rsd'=>'application/rsd+xml','rsheet'=>'application/urc-ressheet+xml','rss'=>'application/rss+xml','rtf'=>'text/rtf','rtx'=>'text/richtext','run'=>'application/x-makeself','rusd'=>'application/route-usd+xml','rv'=>'video/vnd.rn-realvideo','s'=>'text/x-asm','s3m'=>'audio/s3m','saf'=>'application/vnd.yamaha.smaf-audio','sass'=>'text/x-sass','sbml'=>'application/sbml+xml','sc'=>'application/vnd.ibm.secure-container','scd'=>'application/x-msschedule','scm'=>'application/vnd.lotus-screencam','scq'=>'application/scvp-cv-request','scs'=>'application/scvp-cv-response','scss'=>'text/x-scss','scurl'=>'text/vnd.curl.scurl','sda'=>'application/vnd.stardivision.draw','sdc'=>'application/vnd.stardivision.calc','sdd'=>'application/vnd.stardivision.impress','sdkd'=>'application/vnd.solent.sdkm+xml','sdkm'=>'application/vnd.solent.sdkm+xml','sdp'=>'application/sdp','sdw'=>'application/vnd.stardivision.writer','sea'=>'application/x-sea','see'=>'application/vnd.seemail','seed'=>'application/vnd.fdsn.seed','sema'=>'application/vnd.sema','semd'=>'application/vnd.semd','semf'=>'application/vnd.semf','senmlx'=>'application/senml+xml','sensmlx'=>'application/sensml+xml','ser'=>'application/java-serialized-object','setpay'=>'application/set-payment-initiation','setreg'=>'application/set-registration-initiation','sfd-hdstx'=>'application/vnd.hydrostatix.sof-data','sfs'=>'application/vnd.spotfire.sfs','sfv'=>'text/x-sfv','sgi'=>'image/sgi','sgl'=>'application/vnd.stardivision.writer-global','sgm'=>'text/sgml','sgml'=>'text/sgml','sh'=>'application/x-sh','shar'=>'application/x-shar','shex'=>'text/shex','shf'=>'application/shf+xml','shtml'=>'text/html','sid'=>'image/x-mrsid-image','sieve'=>'application/sieve','sig'=>'application/pgp-signature','sil'=>'audio/silk','silo'=>'model/mesh','sis'=>'application/vnd.symbian.install','sisx'=>'application/vnd.symbian.install','sit'=>'application/x-stuffit','sitx'=>'application/x-stuffitx','siv'=>'application/sieve','skd'=>'application/vnd.koan','skm'=>'application/vnd.koan','skp'=>'application/vnd.koan','skt'=>'application/vnd.koan','sldm'=>'application/vnd.ms-powerpoint.slide.macroenabled.12','sldx'=>'application/vnd.openxmlformats-officedocument.presentationml.slide','slim'=>'text/slim','slm'=>'text/slim','sls'=>'application/route-s-tsid+xml','slt'=>'application/vnd.epson.salt','sm'=>'application/vnd.stepmania.stepchart','smf'=>'application/vnd.stardivision.math','smi'=>'application/smil+xml','smil'=>'application/smil+xml','smv'=>'video/x-smv','smzip'=>'application/vnd.stepmania.package','snd'=>'audio/basic','snf'=>'application/x-font-snf','so'=>'application/octet-stream','spc'=>'application/x-pkcs7-certificates','spdx'=>'text/spdx','spf'=>'application/vnd.yamaha.smaf-phrase','spl'=>'application/x-futuresplash','spot'=>'text/vnd.in3d.spot','spp'=>'application/scvp-vp-response','spq'=>'application/scvp-vp-request','spx'=>'audio/ogg','sql'=>'application/sql','sqlite'=>'application/vnd.sqlite3','sqlite3'=>'application/vnd.sqlite3','src'=>'application/x-wais-source','srt'=>'application/x-subrip','sru'=>'application/sru+xml','srx'=>'application/sparql-results+xml','ssdl'=>'application/ssdl+xml','sse'=>'application/vnd.kodak-descriptor','ssf'=>'application/vnd.epson.ssf','ssml'=>'application/ssml+xml','sst'=>'application/octet-stream','st'=>'application/vnd.sailingtracker.track','stc'=>'application/vnd.sun.xml.calc.template','std'=>'application/vnd.sun.xml.draw.template','step'=>'model/step','stf'=>'application/vnd.wt.stf','sti'=>'application/vnd.sun.xml.impress.template','stk'=>'application/hyperstudio','stl'=>'model/stl','stp'=>'model/step','stpnc'=>'model/step','stpx'=>'model/step+xml','stpxz'=>'model/step-xml+zip','stpz'=>'model/step+zip','str'=>'application/vnd.pg.format','stw'=>'application/vnd.sun.xml.writer.template','styl'=>'text/stylus','stylus'=>'text/stylus','sub'=>'image/vnd.dvb.subtitle','sus'=>'application/vnd.sus-calendar','susp'=>'application/vnd.sus-calendar','sv4cpio'=>'application/x-sv4cpio','sv4crc'=>'application/x-sv4crc','svc'=>'application/vnd.dvb.service','svd'=>'application/vnd.svd','svg'=>'image/svg+xml','svgz'=>'image/svg+xml','swa'=>'application/x-director','swf'=>'application/x-shockwave-flash','swi'=>'application/vnd.aristanetworks.swi','swidtag'=>'application/swid+xml','sxc'=>'application/vnd.sun.xml.calc','sxd'=>'application/vnd.sun.xml.draw','sxg'=>'application/vnd.sun.xml.writer.global','sxi'=>'application/vnd.sun.xml.impress','sxm'=>'application/vnd.sun.xml.math','sxw'=>'application/vnd.sun.xml.writer','systemverify'=>'application/vnd.pp.systemverify+xml','t'=>'text/troff','t3'=>'application/x-t3vm-image','t38'=>'image/t38','taglet'=>'application/vnd.mynfc','tao'=>'application/vnd.tao.intent-module-archive','tap'=>'image/vnd.tencent.tap','tar'=>'application/x-tar','tcap'=>'application/vnd.3gpp2.tcap','tcl'=>'application/x-tcl','td'=>'application/urc-targetdesc+xml','teacher'=>'application/vnd.smart.teacher','tei'=>'application/tei+xml','teicorpus'=>'application/tei+xml','tex'=>'application/x-tex','texi'=>'application/x-texinfo','texinfo'=>'application/x-texinfo','text'=>'text/plain','tfi'=>'application/thraud+xml','tfm'=>'application/x-tex-tfm','tfx'=>'image/tiff-fx','tga'=>'image/x-tga','tgz'=>'application/gzip','thmx'=>'application/vnd.ms-officetheme','tif'=>'image/tiff','tiff'=>'image/tiff','tk'=>'application/x-tcl','tmo'=>'application/vnd.tmobile-livetv','toml'=>'application/toml','torrent'=>'application/x-bittorrent','tpl'=>'application/vnd.groove-tool-template','tpt'=>'application/vnd.trid.tpt','tr'=>'text/troff','tra'=>'application/vnd.trueapp','trig'=>'application/trig','trm'=>'application/x-msterminal','ts'=>'video/mp2t','tsd'=>'application/timestamped-data','tsv'=>'text/tab-separated-values','ttc'=>'font/collection','ttf'=>'font/ttf','ttl'=>'text/turtle','ttml'=>'application/ttml+xml','twd'=>'application/vnd.simtech-mindmapper','twds'=>'application/vnd.simtech-mindmapper','txd'=>'application/vnd.genomatix.tuxedo','txf'=>'application/vnd.mobius.txf','txt'=>'text/plain','u32'=>'application/x-authorware-bin','u3d'=>'model/u3d','u8dsn'=>'message/global-delivery-status','u8hdr'=>'message/global-headers','u8mdn'=>'message/global-disposition-notification','u8msg'=>'message/global','ubj'=>'application/ubjson','udeb'=>'application/x-debian-package','ufd'=>'application/vnd.ufdl','ufdl'=>'application/vnd.ufdl','ulx'=>'application/x-glulx','umj'=>'application/vnd.umajin','unityweb'=>'application/vnd.unity','uo'=>'application/vnd.uoml+xml','uoml'=>'application/vnd.uoml+xml','uri'=>'text/uri-list','uris'=>'text/uri-list','urls'=>'text/uri-list','usda'=>'model/vnd.usda','usdz'=>'model/vnd.usdz+zip','ustar'=>'application/x-ustar','utz'=>'application/vnd.uiq.theme','uu'=>'text/x-uuencode','uva'=>'audio/vnd.dece.audio','uvd'=>'application/vnd.dece.data','uvf'=>'application/vnd.dece.data','uvg'=>'image/vnd.dece.graphic','uvh'=>'video/vnd.dece.hd','uvi'=>'image/vnd.dece.graphic','uvm'=>'video/vnd.dece.mobile','uvp'=>'video/vnd.dece.pd','uvs'=>'video/vnd.dece.sd','uvt'=>'application/vnd.dece.ttml+xml','uvu'=>'video/vnd.uvvu.mp4','uvv'=>'video/vnd.dece.video','uvva'=>'audio/vnd.dece.audio','uvvd'=>'application/vnd.dece.data','uvvf'=>'application/vnd.dece.data','uvvg'=>'image/vnd.dece.graphic','uvvh'=>'video/vnd.dece.hd','uvvi'=>'image/vnd.dece.graphic','uvvm'=>'video/vnd.dece.mobile','uvvp'=>'video/vnd.dece.pd','uvvs'=>'video/vnd.dece.sd','uvvt'=>'application/vnd.dece.ttml+xml','uvvu'=>'video/vnd.uvvu.mp4','uvvv'=>'video/vnd.dece.video','uvvx'=>'application/vnd.dece.unspecified','uvvz'=>'application/vnd.dece.zip','uvx'=>'application/vnd.dece.unspecified','uvz'=>'application/vnd.dece.zip','vbox'=>'application/x-virtualbox-vbox','vbox-extpack'=>'application/x-virtualbox-vbox-extpack','vcard'=>'text/vcard','vcd'=>'application/x-cdlink','vcf'=>'text/x-vcard','vcg'=>'application/vnd.groove-vcard','vcs'=>'text/x-vcalendar','vcx'=>'application/vnd.vcx','vdi'=>'application/x-virtualbox-vdi','vds'=>'model/vnd.sap.vds','vdx'=>'application/vnd.ms-visio.viewer','vec'=>'application/vec+xml','vhd'=>'application/x-virtualbox-vhd','vis'=>'application/vnd.visionary','viv'=>'video/vnd.vivo','vmdk'=>'application/x-virtualbox-vmdk','vob'=>'video/x-ms-vob','vor'=>'application/vnd.stardivision.writer','vox'=>'application/x-authorware-bin','vrml'=>'model/vrml','vsd'=>'application/vnd.visio','vsdx'=>'application/vnd.visio','vsf'=>'application/vnd.vsf','vss'=>'application/vnd.visio','vst'=>'application/vnd.visio','vsw'=>'application/vnd.visio','vtf'=>'image/vnd.valve.source.texture','vtt'=>'text/vtt','vtu'=>'model/vnd.vtu','vtx'=>'application/vnd.visio','vxml'=>'application/voicexml+xml','w3d'=>'application/x-director','wad'=>'application/x-doom','wadl'=>'application/vnd.sun.wadl+xml','war'=>'application/java-archive','wasm'=>'application/wasm','wav'=>'audio/wav','wax'=>'audio/x-ms-wax','wbmp'=>'image/vnd.wap.wbmp','wbs'=>'application/vnd.criticaltools.wbs+xml','wbxml'=>'application/vnd.wap.wbxml','wcm'=>'application/vnd.ms-works','wdb'=>'application/vnd.ms-works','wdp'=>'image/vnd.ms-photo','weba'=>'audio/webm','webapp'=>'application/x-web-app-manifest+json','webm'=>'video/webm','webmanifest'=>'application/manifest+json','webp'=>'image/webp','wg'=>'application/vnd.pmi.widget','wgsl'=>'text/wgsl','wgt'=>'application/widget','wif'=>'application/watcherinfo+xml','wks'=>'application/vnd.ms-works','wm'=>'video/x-ms-wm','wma'=>'audio/x-ms-wma','wmd'=>'application/x-ms-wmd','wmf'=>'image/wmf','wml'=>'text/vnd.wap.wml','wmlc'=>'application/vnd.wap.wmlc','wmls'=>'text/vnd.wap.wmlscript','wmlsc'=>'application/vnd.wap.wmlscriptc','wmv'=>'video/x-ms-wmv','wmx'=>'video/x-ms-wmx','wmz'=>'application/x-ms-wmz','woff'=>'font/woff','woff2'=>'font/woff2','word'=>'application/msword','wpd'=>'application/vnd.wordperfect','wpl'=>'application/vnd.ms-wpl','wps'=>'application/vnd.ms-works','wqd'=>'application/vnd.wqd','wri'=>'application/x-mswrite','wrl'=>'model/vrml','wsc'=>'message/vnd.wfa.wsc','wsdl'=>'application/wsdl+xml','wspolicy'=>'application/wspolicy+xml','wtb'=>'application/vnd.webturbo','wvx'=>'video/x-ms-wvx','x32'=>'application/x-authorware-bin','x3d'=>'model/x3d+xml','x3db'=>'model/x3d+fastinfoset','x3dbz'=>'model/x3d+binary','x3dv'=>'model/x3d-vrml','x3dvz'=>'model/x3d+vrml','x3dz'=>'model/x3d+xml','x_b'=>'model/vnd.parasolid.transmit.binary','x_t'=>'model/vnd.parasolid.transmit.text','xaml'=>'application/xaml+xml','xap'=>'application/x-silverlight-app','xar'=>'application/vnd.xara','xav'=>'application/xcap-att+xml','xbap'=>'application/x-ms-xbap','xbd'=>'application/vnd.fujixerox.docuworks.binder','xbm'=>'image/x-xbitmap','xca'=>'application/xcap-caps+xml','xcs'=>'application/calendar+xml','xdcf'=>'application/vnd.gov.sk.xmldatacontainer+xml','xdf'=>'application/xcap-diff+xml','xdm'=>'application/vnd.syncml.dm+xml','xdp'=>'application/vnd.adobe.xdp+xml','xdssc'=>'application/dssc+xml','xdw'=>'application/vnd.fujixerox.docuworks','xel'=>'application/xcap-el+xml','xenc'=>'application/xenc+xml','xer'=>'application/patch-ops-error+xml','xfdf'=>'application/xfdf','xfdl'=>'application/vnd.xfdl','xht'=>'application/xhtml+xml','xhtm'=>'application/vnd.pwg-xhtml-print+xml','xhtml'=>'application/xhtml+xml','xhvml'=>'application/xv+xml','xif'=>'image/vnd.xiff','xl'=>'application/vnd.ms-excel','xla'=>'application/vnd.ms-excel','xlam'=>'application/vnd.ms-excel.addin.macroenabled.12','xlc'=>'application/vnd.ms-excel','xlf'=>'application/xliff+xml','xlm'=>'application/vnd.ms-excel','xls'=>'application/vnd.ms-excel','xlsb'=>'application/vnd.ms-excel.sheet.binary.macroenabled.12','xlsm'=>'application/vnd.ms-excel.sheet.macroenabled.12','xlsx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','xlt'=>'application/vnd.ms-excel','xltm'=>'application/vnd.ms-excel.template.macroenabled.12','xltx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.template','xlw'=>'application/vnd.ms-excel','xm'=>'audio/xm','xml'=>'application/xml','xns'=>'application/xcap-ns+xml','xo'=>'application/vnd.olpc-sugar','xop'=>'application/xop+xml','xpi'=>'application/x-xpinstall','xpl'=>'application/xproc+xml','xpm'=>'image/x-xpixmap','xpr'=>'application/vnd.is-xpr','xps'=>'application/vnd.ms-xpsdocument','xpw'=>'application/vnd.intercon.formnet','xpx'=>'application/vnd.intercon.formnet','xsd'=>'application/xml','xsf'=>'application/prs.xsf+xml','xsl'=>'application/xslt+xml','xslt'=>'application/xslt+xml','xsm'=>'application/vnd.syncml+xml','xspf'=>'application/xspf+xml','xul'=>'application/vnd.mozilla.xul+xml','xvm'=>'application/xv+xml','xvml'=>'application/xv+xml','xwd'=>'image/x-xwindowdump','xyz'=>'chemical/x-xyz','xz'=>'application/x-xz','yaml'=>'text/yaml','yang'=>'application/yang','yin'=>'application/yin+xml','yml'=>'text/yaml','ymp'=>'text/x-suse-ymp','z'=>'application/x-compress','z1'=>'application/x-zmachine','z2'=>'application/x-zmachine','z3'=>'application/x-zmachine','z4'=>'application/x-zmachine','z5'=>'application/x-zmachine','z6'=>'application/x-zmachine','z7'=>'application/x-zmachine','z8'=>'application/x-zmachine','zaz'=>'application/vnd.zzazz.deck+xml','zip'=>'application/zip','zir'=>'application/vnd.zul','zirz'=>'application/vnd.zul','zmm'=>'application/vnd.handheld-entertainment+xml','zsh'=>'text/x-scriptzsh',];
static function fromFilename(string$filename):?string
{
return self::fromExtension(pathinfo($filename,PATHINFO_EXTENSION));
}
static function fromExtension(string$extension):?string
{
return self::MIME_TYPES[Utils::asciiToLower($extension)]??null;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class MultipartStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private string$boundary;
private StreamInterface$stream;
private const BOUNDARY_CHARS="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'()+_,-./:=? ";
function __construct(array$elements=[],?string$boundary=null){
if($boundary!==null){
self::validateBoundary($boundary);
}
$this->boundary=$boundary??bin2hex(random_bytes(20));
$this->stream=$this->createStream($elements);
}
function getBoundary():string
{
return$this->boundary;
}
function isWritable():bool
{
return false;
}
private function getHeaders(array$headers):string
{
$str='';
foreach($headers as$key=>$value){
$key=(string)$key;
self::validatePartHeaderName($key);
self::validatePartHeaderValue($key,$value);
$str.="{$key}: {$value}\r\n";
}
return"--{$this->boundary}\r\n".rtrim($str,"\r\n")."\r\n\r\n";
}
protected function createStream(array$elements=[]):StreamInterface
{
$stream=new AppendStream;
foreach($elements as$element){
if(!is_array($element)){
throw new\UnexpectedValueException('An array is expected');
}
$this->addElement($stream,$element);
}
$stream->addStream(Utils::streamFor("--{$this->boundary}--\r\n"));
return$stream;
}
private function addElement(AppendStream$stream,array$element):void
{
foreach(['contents','name']as$key){
if(!key_exists($key,$element)){
throw new\InvalidArgumentException("A '{$key}' key is required");
}
}
if(!is_string($element['name'])&&!is_int($element['name'])){
throw new\InvalidArgumentException("The 'name' key must be a string or integer");
}
if(is_array($element['contents'])){
if(key_exists('filename',$element)||key_exists('headers',$element)){
throw new\InvalidArgumentException("The 'filename' and 'headers' options cannot be used when 'contents' is an array");
}
$this->addNestedElements($stream,$element['contents'],(string)$element['name']);
return;
}
$contents=$element['contents'];
if(is_scalar($contents)&&!is_string($contents)){
if(is_float($contents)&&!is_finite($contents)){
throw new\InvalidArgumentException('Cannot create a stream from a non-finite float.');
}
$contents=(string)$contents;
}
$element['contents']=Utils::streamFor($contents);
if(empty($element['filename'])){
$uri=$element['contents']->getMetadata('uri');
if($uri&&\is_string($uri)&&!str_starts_with($uri,'php://')&&!str_starts_with($uri,'data://')){
$element['filename']=$uri;
}
}
[$body,$headers]=$this->createElement((string)$element['name'],$element['contents'],$element['filename']??null,$element['headers']??[]);
$stream->addStream(Utils::streamFor($this->getHeaders($headers)));
$stream->addStream($body);
$stream->addStream(Utils::streamFor("\r\n"));
}
private function addNestedElements(AppendStream$stream,array$contents,string$root):void
{
foreach($contents as$key=>$value){
$fieldName=$root===''?sprintf('[%s]',(string)$key):sprintf('%s[%s]',$root,(string)$key);
if(is_array($value)){
$this->addNestedElements($stream,$value,$fieldName);
}else{
$this->addElement($stream,['name'=>$fieldName,'contents'=>$value]);
}
}
}
private function createElement(string$name,StreamInterface$stream,?string$filename,array$headers):array
{
$headers=self::normalizePartHeaders($headers);
$disposition=self::getHeader($headers,'content-disposition');
if(!$disposition){
$escapedName=self::escapeContentDispositionParameter($name);
$headers['Content-Disposition']=($filename==='0'||$filename)?sprintf('form-data; name="%s"; filename="%s"',$escapedName,self::escapeContentDispositionParameter(basename($filename))):sprintf('form-data; name="%s"',$escapedName);
}
$type=self::getHeader($headers,'content-type');
if(!$type&&($filename==='0'||$filename)){
$headers['Content-Type']=MimeType::fromFilename($filename)??'application/octet-stream';
}
return[$stream,$headers];
}
private static function getHeader(array$headers,string$key):?string
{
$lowercaseHeader=Utils::asciiToLower($key);
foreach($headers as$k=>$v){
if(Utils::asciiToLower((string)$k)===$lowercaseHeader){
return$v;
}
}
return;
}
private static function validateBoundary(string$boundary):void
{
$length=strlen($boundary);
if($length<1||$length>70||$boundary[$length-1]===' '){
throw new\InvalidArgumentException('Invalid multipart boundary.');
}
if(strspn($boundary,self::BOUNDARY_CHARS)!==$length){
throw new\InvalidArgumentException('Invalid multipart boundary.');
}
}
private static function normalizePartHeaders(array$headers):array
{
$normalized=[];
foreach($headers as$key=>$value){
$key=(string)$key;
self::validatePartHeaderName($key);
if(!is_string($value)){
throw new\InvalidArgumentException('Multipart part header value must be a string.');
}
self::validatePartHeaderValue($key,$value);
$normalized[$key]=$value;
}
return$normalized;
}
private static function validatePartHeaderName(string$name):void
{
if(!Rfc9110::isToken($name)){
throw new\InvalidArgumentException(sprintf('Invalid multipart part header name: %s',DiagnosticValue::escape($name)));
}
}
private static function validatePartHeaderValue(string$name,string$value):void
{
if(!Rfc9110::isFieldValue($value)){
$reason=strpbrk($value,"\r\n")!==false
?'must not contain CR or LF characters':'contains an invalid control character';
throw new\InvalidArgumentException(sprintf('Multipart part header "%s" %s.',DiagnosticValue::escape($name),$reason));
}
}
private static function escapeContentDispositionParameter(string$value):string
{
return str_replace(["\r","\n",'"'],['%0D','%0A','%22'],$value);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class NoSeekStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private StreamInterface$stream;
function seek(int$offset,int$whence=SEEK_SET):void
{
throw new\RuntimeException('Cannot seek a NoSeekStream');
}
function isSeekable():bool
{
return false;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class PumpStream implements StreamInterface
{
use NonSerializableStreamTrait;
private$source;
private?int$size;
private int$tellPos=0;
private array$metadata;
private BufferStream$buffer;
function __construct(callable$source,array$options=[]){
$this->source=$source;
$this->size=Integers::assertOptionalNonNegativeSize($options['size']??null,'Stream size');
$this->metadata=$options['metadata']??[];
$this->buffer=new BufferStream;
}
function __unserialize(array$data):void
{
$this->source=null;
$this->size=null;
$this->tellPos=0;
$this->metadata=[];
$this->buffer=new BufferStream;
throw new\LogicException(static::class.' should never be unserialized');
}
function __toString():string
{
return Utils::copyToString($this);
}
function close():void
{
$this->detach();
}
function detach(){
$this->tellPos=0;
$this->source=null;
$this->buffer->close();
return;
}
function getSize():?int
{
return$this->size;
}
function tell():int
{
return$this->tellPos;
}
function eof():bool
{
return$this->source===null;
}
function isSeekable():bool
{
return false;
}
function rewind():void
{
$this->seek(0);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
throw new\RuntimeException('Cannot seek a PumpStream');
}
function isWritable():bool
{
return false;
}
function write(string$string):int
{
throw new\RuntimeException('Cannot write to a PumpStream');
}
function isReadable():bool
{
return true;
}
function read(int$length):string
{
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
$bufferLength=$this->buffer->getSize()??0;
if($length>$bufferLength){
$this->pump($length-$bufferLength);
}
$data=$this->buffer->read($length);
$this->tellPos=Integers::add($this->tellPos,strlen($data));
return$data;
}
function getContents():string
{
return Utils::copyToString($this);
}
function getMetadata(?string$key=null){
if($key===null){
return$this->metadata;
}
return$this->metadata[$key]??null;
}
private function pump(int$length):void
{
if($this->source!==null){
do{
$data=($this->source)($length);
if($data===false||$data===null){
$this->source=null;
return;
}
if($data===''){
throw new\RuntimeException('PumpStream source returned an empty string');
}
$this->buffer->write($data);
$length-=strlen($data);
}while($length>0);
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class Query
{
private function __construct(){
}
static function parse(string$str,$urlEncoding=true):array
{
$result=[];
if($str===''){
return$result;
}
if($urlEncoding===true){
$decoder=function(string$value):string{
return\rawurldecode(str_replace('+',' ',$value));
};
}elseif($urlEncoding===PHP_QUERY_RFC3986){
$decoder=static function(string$value):string{
return\rawurldecode($value);
};
}elseif($urlEncoding===PHP_QUERY_RFC1738){
$decoder=static function(string$value):string{
return\urldecode($value);
};
}else{
$decoder=function(string$str):string{
return$str;
};
}
foreach(explode('&',$str)as$kvp){
$parts=explode('=',$kvp,2);
$key=$decoder($parts[0]);
$value=isset($parts[1])?$decoder($parts[1]):null;
if(!key_exists($key,$result)){
$result[$key]=$value;
}else{
if(!is_array($result[$key])){
$result[$key]=[$result[$key]];
}
$result[$key][]=$value;
}
}
return$result;
}
static function build(array$params,$encoding=PHP_QUERY_RFC3986,bool$treatBoolsAsInts=true):string
{
if(!$params){
return'';
}
if($encoding===false){
$encoder=function(string$str):string{
return$str;
};
}elseif($encoding===PHP_QUERY_RFC3986){
$encoder=static function(string$value):string{
return\rawurlencode($value);
};
}elseif($encoding===PHP_QUERY_RFC1738){
$encoder=static function(string$value):string{
return\urlencode($value);
};
}else{
throw new\InvalidArgumentException('Invalid type');
}
$qs='';
foreach($params as$k=>$v){
$k=$encoder((string)$k);
if(!is_array($v)){
$qs.=$k;
$v=self::normalizeValue($v,$treatBoolsAsInts);
if($v!==null){
$qs.='='.$encoder($v);
}
$qs.='&';
}else{
foreach($v as$vv){
$qs.=$k;
$vv=self::normalizeValue($vv,$treatBoolsAsInts);
if($vv!==null){
$qs.='='.$encoder($vv);
}
$qs.='&';
}
}
}
return$qs?(string)substr($qs,0,-1):'';
}
private static function normalizeValue($value,bool$treatBoolsAsInts):?string
{
if($value===null){
return;
}
if(is_bool($value)){
return$treatBoolsAsInts?(string)(int)$value:($value?'true':'false');
}
if(is_float($value)&&!is_finite($value)){
throw new\InvalidArgumentException('Query string values must be finite; non-finite floats are not supported.');
}
if(is_scalar($value)){
return(string)$value;
}
if(is_object($value)&&method_exists($value,'__toString')){
return$value->__toString();
}
throw new\InvalidArgumentException('Query string values must be scalar, null, or stringable objects');
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class ReadFailureCapturingStream implements StreamInterface
{
use StreamDecoratorTrait;
use NonSerializableStreamTrait;
private StreamInterface$stream;
private?\Exception$readFailure=null;
private bool$capturing=true;
function read(int$length):string
{
if(!$this->capturing){
return$this->stream->read($length);
}
try{
return$this->stream->read($length);
}catch(\Exception$e){
$this->readFailure=$e;
return'';
}
}
function stopCapturing():void
{
$this->capturing=false;
$this->readFailure=null;
}
function hasReadFailure():bool
{
return$this->readFailure!==null;
}
function takeReadFailure():?\Exception
{
$failure=$this->readFailure;
$this->readFailure=null;
return$failure;
}
}
namespace Psr\Http\Message;
interface MessageInterface
{
function getProtocolVersion():string;
function withProtocolVersion(string$version):MessageInterface;
function getHeaders():array;
function hasHeader(string$name):bool;
function getHeader(string$name):array;
function getHeaderLine(string$name):string;
function withHeader(string$name,$value):MessageInterface;
function withAddedHeader(string$name,$value):MessageInterface;
function withoutHeader(string$name):MessageInterface;
function getBody():StreamInterface;
function withBody(StreamInterface$body):MessageInterface;
}
namespace Psr\Http\Message;
interface RequestInterface extends MessageInterface
{
function getRequestTarget():string;
function withRequestTarget(string$requestTarget):RequestInterface;
function getMethod():string;
function withMethod(string$method):RequestInterface;
function getUri():UriInterface;
function withUri(UriInterface$uri,bool$preserveHost=false):RequestInterface;
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
class Request implements RequestInterface
{
use MessageTrait;
private string$method;
private?string$requestTarget=null;
private UriInterface$uri;
function __construct(string$method,$uri,array$headers=[],$body=null,string$version='1.1'){
$this->assertMethod($method);
$this->assertProtocolVersion($version);
if(!$uri instanceof UriInterface){
$uri=new Uri($uri);
}
self::getRequestTargetFromUri($uri);
$this->method=$method;
$this->uri=$uri;
$this->setHeaders($headers);
$this->protocol=$version;
if(!isset($this->headerNames['host'])){
$this->updateHostFromUri();
}
if($body!==''&&$body!==null){
$this->stream=Utils::streamFor($body);
}
}
function getRequestTarget():string
{
if($this->requestTarget!==null){
return$this->requestTarget;
}
return self::getRequestTargetFromUri($this->uri);
}
function withRequestTarget(string$requestTarget):RequestInterface
{
self::assertRequestTarget($requestTarget);
$new=clone$this;
$new->requestTarget=$requestTarget;
return$new;
}
function getMethod():string
{
return$this->method;
}
function withMethod(string$method):RequestInterface
{
$this->assertMethod($method);
$new=clone$this;
$new->method=$method;
return$new;
}
function getUri():UriInterface
{
return$this->uri;
}
function withUri(UriInterface$uri,bool$preserveHost=false):RequestInterface
{
$sameUri=$uri===$this->uri;
if(!$sameUri&&$this->requestTarget===null){
self::getRequestTargetFromUri($uri);
}
$currentHost=$this->getHeaderLine('Host');
$host=null;
if(!$preserveHost||$currentHost===''){
$host=$this->getHostFromUri($uri);
}
if($sameUri&&($host===null||$currentHost===$host)){
return$this;
}
$new=clone$this;
$new->uri=$uri;
if($host!==null){
$new->setHostHeader($host);
}
return$new;
}
private function updateHostFromUri():void
{
$host=$this->getHostFromUri($this->uri);
if($host===null){
return;
}
$this->setHostHeader($host);
}
private function getHostFromUri(UriInterface$uri):?string
{
$host=$uri->getHost();
if($host===''){
return;
}
Uri::assertValidHost($host);
if(($port=$uri->getPort())!==null){
$host.=':'.$port;
}
$this->assertValue('Host',$host);
return$host;
}
private function setHostHeader(string$host):void
{
if(isset($this->headerNames['host'])){
$header=$this->headerNames['host'];
}else{
$header='Host';
$this->headerNames['host']='Host';
}
$this->headers=[$header=>[$host]]+$this->headers;
}
private function assertMethod(string$method):void
{
if(!Rfc9110::isToken($method)){
throw new InvalidArgumentException('Method must be a valid HTTP token.');
}
}
private static function getRequestTargetFromUri(UriInterface$uri):string
{
$target=self::normalizePathForOriginForm($uri->getPath());
if($target===''){
$target='/';
}
if($uri->getQuery()!=''){
$target.='?'.$uri->getQuery();
}
self::assertRequestTarget($target);
return$target;
}
private static function assertRequestTarget(string$requestTarget):void
{
if(!Rfc9112::isValidRequestTarget($requestTarget)){
throw new InvalidArgumentException('Invalid request target provided; cannot be empty or contain whitespace or control characters');
}
}
private static function normalizePathForOriginForm(string$path):string
{
if(str_starts_with($path,'//')){
return'/'.ltrim($path,'/');
}
return$path;
}
}
namespace Psr\Http\Message;
interface ResponseInterface extends MessageInterface
{
function getStatusCode():int;
function withStatus(int$code,string$reasonPhrase=''):ResponseInterface;
function getReasonPhrase():string;
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
class Response implements ResponseInterface
{
use MessageTrait;
private const PHRASES=[100=>'Continue',101=>'Switching Protocols',102=>'Processing',200=>'OK',201=>'Created',202=>'Accepted',203=>'Non-Authoritative Information',204=>'No Content',205=>'Reset Content',206=>'Partial Content',207=>'Multi-status',208=>'Already Reported',300=>'Multiple Choices',301=>'Moved Permanently',302=>'Found',303=>'See Other',304=>'Not Modified',305=>'Use Proxy',306=>'Switch Proxy',307=>'Temporary Redirect',308=>'Permanent Redirect',400=>'Bad Request',401=>'Unauthorized',402=>'Payment Required',403=>'Forbidden',404=>'Not Found',405=>'Method Not Allowed',406=>'Not Acceptable',407=>'Proxy Authentication Required',408=>'Request Time-out',409=>'Conflict',410=>'Gone',411=>'Length Required',412=>'Precondition Failed',413=>'Request Entity Too Large',414=>'Request-URI Too Large',415=>'Unsupported Media Type',416=>'Requested range not satisfiable',417=>'Expectation Failed',418=>'I\'m a teapot',422=>'Unprocessable Entity',423=>'Locked',424=>'Failed Dependency',425=>'Unordered Collection',426=>'Upgrade Required',428=>'Precondition Required',429=>'Too Many Requests',431=>'Request Header Fields Too Large',451=>'Unavailable For Legal Reasons',500=>'Internal Server Error',501=>'Not Implemented',502=>'Bad Gateway',503=>'Service Unavailable',504=>'Gateway Time-out',505=>'HTTP Version not supported',506=>'Variant Also Negotiates',507=>'Insufficient Storage',508=>'Loop Detected',510=>'Not Extended',511=>'Network Authentication Required',];
private string$reasonPhrase;
private int$statusCode;
function __construct(int$status=200,array$headers=[],$body=null,string$version='1.1',?string$reason=null
){
$this->assertStatusCodeRange($status);
$this->assertProtocolVersion($version);
$this->statusCode=$status;
if($body!==''&&$body!==null){
$this->stream=Utils::streamFor($body);
}
$this->setHeaders($headers);
if($reason==''&&isset(self::PHRASES[$this->statusCode])){
$reasonPhrase=self::PHRASES[$this->statusCode];
}else{
$reasonPhrase=(string)$reason;
}
$this->assertReasonPhrase($reasonPhrase);
$this->reasonPhrase=$reasonPhrase;
$this->protocol=$version;
}
function getStatusCode():int
{
return$this->statusCode;
}
function getReasonPhrase():string
{
return$this->reasonPhrase;
}
function withStatus(int$code,string$reasonPhrase=''):ResponseInterface
{
$this->assertStatusCodeRange($code);
$new=clone$this;
$new->statusCode=$code;
if($reasonPhrase===''&&isset(self::PHRASES[$new->statusCode])){
$reasonPhrase=self::PHRASES[$new->statusCode];
}
$this->assertReasonPhrase($reasonPhrase);
$new->reasonPhrase=$reasonPhrase;
return$new;
}
private function assertStatusCodeRange(int$statusCode):void
{
if($statusCode<100||$statusCode>=600){
throw new\InvalidArgumentException('Status code must be an integer value between 1xx and 5xx.');
}
}
private function assertReasonPhrase(string$reasonPhrase):void
{
if(!Rfc9112::isValidReasonPhrase($reasonPhrase)){
throw new\InvalidArgumentException('Reason phrase must not contain invalid control characters.');
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class Rfc3986
{
private function __construct(){
}
const CHAR_SUB_DELIMS='!\$&\'\(\)\*\+,;=';
const CHAR_UNRESERVED='a-zA-Z0-9_\-\.~';
const HEX_OCTET='[A-Fa-f0-9]{2}';
static function isValidScheme(string$scheme):bool
{
return$scheme===''||preg_match('/^[A-Za-z][A-Za-z0-9.+-]*$/D',$scheme)===1;
}
static function isValidHost(string$host):bool
{
if($host===''){
return true;
}
$invalidHost=preg_match('/[\x00-\x20\x7F\/\?#@\\\\]/',$host);
if($invalidHost===false){
return false;
}
if($invalidHost===1){
return false;
}
if(str_contains($host,'[')||str_contains($host,']')){
return self::isValidIpLiteralHost($host);
}
if(str_contains($host,':')){
return false;
}
return!str_contains($host,'%')||self::hasValidHostPercentEncoding($host);
}
static function isValidPort(string$port):bool
{
if($port===''||!ctype_digit($port)){
return false;
}
$normalized=ltrim($port,'0');
if($normalized===''){
return true;
}
return strlen($normalized)<=5&&(int)$normalized<=65535;
}
static function canonicalizeIpv6(string$address):string
{
$canonical=self::tryCanonicalizeIpv6($address);
if($canonical===null){
throw new\InvalidArgumentException('Invalid IPv6 address');
}
return$canonical;
}
static function tryCanonicalizeIpv6(string$address):?string
{
if(\filter_var($address,\FILTER_VALIDATE_IP,\FILTER_FLAG_IPV6)===false){
return;
}
$words=self::parseIpv6Words($address);
if($words===null){
return;
}
$bestStart=0;
$bestLen=0;
$start=-1;
foreach($words as$i=>$word){
if($word!==0){
$start=-1;
continue;
}
if($start===-1){
$start=$i;
}
if($i-$start+1>$bestLen){
$bestStart=$start;
$bestLen=$i-$start+1;
}
}
if($bestLen<2){
$bestLen=0;
}
$mixed=$bestStart===0
&&($bestLen===6||($bestLen===5&&$words[5]===65535));
$groups=[];
for($i=0,$n=$mixed?6:8;$i<$n;++$i){
$groups[]=dechex($words[$i]);
}
if($mixed){
$groups[]=sprintf('%d.%d.%d.%d',$words[6]>>8,$words[6]&255,$words[7]>>8,$words[7]&255
);
}
if($bestLen===0){
return join(':',$groups);
}
return join(':',array_slice($groups,0,$bestStart)).'::'.join(':',array_slice($groups,$bestStart+$bestLen));
}
private static function hasValidHostPercentEncoding(string$host):bool
{
$invalidEncoding=preg_match('/%(?!'.self::HEX_OCTET.')|%(?:[01][0-9A-Fa-f]|2[035F]|3[AF]|40|5[BCD]|7F)/i',$host
);
return$invalidEncoding===0;
}
private static function isValidIpLiteralHost(string$host):bool
{
if(!str_starts_with($host,'[')||!str_ends_with($host,']')){
return false;
}
$address=substr($host,1,-1);
if(\filter_var($address,\FILTER_VALIDATE_IP,\FILTER_FLAG_IPV6)!==false){
return true;
}
return preg_match('/^v[0-9a-f]+\.['.self::CHAR_UNRESERVED.self::CHAR_SUB_DELIMS.':]+$/iD',$address)===1;
}
private static function parseIpv6Words(string$address):?array
{
$dot=strpos($address,'.');
if($dot!==false){
$colon=strrpos($address,':');
if($colon===false||$colon>$dot){
return;
}
$octets=explode('.',substr($address,$colon+1));
if(count($octets)!==4){
return;
}
$bytes=[];
foreach($octets as$octet){
if($octet===''||strlen($octet)>3||!ctype_digit($octet)){
return;
}
if($octet[0]==='0'&&$octet!=='0'){
return;
}
$byte=(int)$octet;
if($byte>255){
return;
}
$bytes[]=$byte;
}
$address=substr($address,0,$colon+1).dechex(($bytes[0]<<8)|$bytes[1]).':'.dechex(($bytes[2]<<8)|$bytes[3]);
}
$halves=explode('::',$address);
if(count($halves)>2){
return;
}
$head=self::parseHexFields($halves[0]);
if($head===null){
return;
}
if(count($halves)===1){
return count($head)===8?$head:null;
}
$tail=self::parseHexFields($halves[1]);
if($tail===null){
return;
}
$elided=8-count($head)-count($tail);
if($elided<1){
return;
}
return array_merge($head,array_fill(0,$elided,0),$tail);
}
private static function parseHexFields(string$fields):?array
{
if($fields===''){
return[];
}
$words=[];
foreach(explode(':',$fields)as$field){
if($field===''||strlen($field)>4||!ctype_xdigit($field)){
return;
}
$words[]=intval($field,16);
}
return$words;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class Rfc9110
{
const TOKEN_PATTERN='[!#$%&\'*+.^_`|~0-9A-Za-z-]+';
const FIELD_VALUE_PATTERN='[\x09\x20-\x7E\x80-\xFF]*';
private function __construct(){
}
static function isToken(string$value):bool
{
return preg_match('/^'.self::TOKEN_PATTERN.'$/D',$value)===1;
}
static function isFieldValue(string$value):bool
{
return preg_match('/^'.self::FIELD_VALUE_PATTERN.'$/D',$value)===1;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class Rfc9112
{
const PROTOCOL_VERSION_PATTERN='\d+(?:\.\d+)?';
const REQUEST_TARGET_PATTERN='[^\x00-\x20\x7F]+';
private function __construct(){
}
const HEADER_REGEX="(^([^()<>@,;:\\\"/[\]?={}\x01-\x20\x7F]++):[ \t]*+((?:[ \t]*+[\x21-\x7E\x80-\xFF]++)*+)[ \t]*+\r?\n)m";
const HEADER_FOLD_REGEX="(\r?\n[ \t]++)";
static function isValidProtocolVersion(string$version):bool
{
return preg_match('/^'.self::PROTOCOL_VERSION_PATTERN.'$/D',$version)===1;
}
static function isValidRequestTarget(string$target):bool
{
return preg_match('/^'.self::REQUEST_TARGET_PATTERN.'$/D',$target)===1;
}
static function isValidReasonPhrase(string$reasonPhrase):bool
{
return Rfc9110::isFieldValue($reasonPhrase);
}
static function parseHostHeader(string$authority):?array
{
if($authority===''){
return;
}
$host=$authority;
$port=null;
if(str_starts_with($authority,'[')){
$closingBracket=strpos($authority,']');
if($closingBracket===false){
return;
}
$host=substr($authority,0,$closingBracket+1);
$remainder=substr($authority,$closingBracket+1);
if($remainder!==''){
if(!str_starts_with($remainder,':')){
return;
}
$port=self::parsePort(substr($remainder,1));
if($port===null){
return;
}
}
}elseif(false!==($colon=strpos($authority,':'))){
$host=substr($authority,0,$colon);
$port=self::parsePort(substr($authority,$colon+1));
if($port===null){
return;
}
}
if($host===''||!Rfc3986::isValidHost($host)){
return;
}
return[$host,$port];
}
static function isAbsoluteFormRequestTarget(string$target):bool
{
return preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:\/\//D',$target)===1;
}
static function isAsteriskFormRequestTarget(string$method,string$target):bool
{
return$method==='OPTIONS'&&$target==='*';
}
static function isConnectAuthorityFormRequestTarget(string$method,string$target):bool
{
return$method==='CONNECT'&&strpbrk($target,'/?#')===false;
}
static function parsePort(string$port):?int
{
if(!Rfc3986::isValidPort($port)){
return;
}
$parsed=(int)ltrim($port,'0');
return$parsed===0?null:$parsed;
}
}
namespace Psr\Http\Message;
interface ServerRequestInterface extends RequestInterface
{
function getServerParams():array;
function getCookieParams():array;
function withCookieParams(array$cookies):ServerRequestInterface;
function getQueryParams():array;
function withQueryParams(array$query):ServerRequestInterface;
function getUploadedFiles():array;
function withUploadedFiles(array$uploadedFiles):ServerRequestInterface;
function getParsedBody();
function withParsedBody($data):ServerRequestInterface;
function getAttributes():array;
function getAttribute(string$name,$default=null);
function withAttribute(string$name,$value):ServerRequestInterface;
function withoutAttribute(string$name):ServerRequestInterface;
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UploadedFileInterface;
use Psr\Http\Message\UriInterface;
class ServerRequest extends Request implements ServerRequestInterface
{
private array$attributes=[];
private array$cookieParams=[];
private$parsedBody;
private array$queryParams=[];
private array$serverParams;
private array$uploadedFiles=[];
function __construct(string$method,$uri,array$headers=[],$body=null,string$version='1.1',#[\SensitiveParameter]array$serverParams=[]){
$this->serverParams=$serverParams;
parent::__construct($method,$uri,$headers,$body,$version);
}
static function normalizeFiles(array$files):array
{
return UploadedFileNormalizer::normalize($files);
}
static function fromGlobals():ServerRequestInterface
{
return ServerRequestGlobalsFactory::fromArrays($_SERVER,$_GET,$_POST,$_COOKIE,$_FILES,static function(){
if(!\function_exists('apache_request_headers')){
return false;
}
return\apache_request_headers();
}
);
}
static function getUriFromGlobals():UriInterface
{
return ServerRequestGlobalsFactory::getUriFromServerParams($_SERVER);
}
function getServerParams():array
{
return$this->serverParams;
}
function getUploadedFiles():array
{
return$this->uploadedFiles;
}
function withUploadedFiles(array$uploadedFiles):ServerRequestInterface
{
$stack=[$uploadedFiles];
for($i=0;$i<\count($stack);++$i){
foreach($stack[$i]as$uploadedFile){
if($uploadedFile instanceof UploadedFileInterface){
continue;
}
if(\is_array($uploadedFile)){
$stack[]=$uploadedFile;
continue;
}
throw new InvalidArgumentException(sprintf('Invalid uploaded file tree; expected UploadedFileInterface instances but %s provided.',\get_debug_type($uploadedFile)));
}
}
$new=clone$this;
$new->uploadedFiles=$uploadedFiles;
return$new;
}
function getCookieParams():array
{
return$this->cookieParams;
}
function withCookieParams(#[\SensitiveParameter]array$cookies
):ServerRequestInterface{
$new=clone$this;
$new->cookieParams=$cookies;
return$new;
}
function getQueryParams():array
{
return$this->queryParams;
}
function withQueryParams(array$query):ServerRequestInterface
{
$new=clone$this;
$new->queryParams=$query;
return$new;
}
function getParsedBody(){
return$this->parsedBody;
}
function withParsedBody($data):ServerRequestInterface
{
if($data!==null&&!\is_array($data)&&!\is_object($data)){
throw new InvalidArgumentException('Parsed body must be an array, object, or null.');
}
$new=clone$this;
$new->parsedBody=$data;
return$new;
}
function getAttributes():array
{
return$this->attributes;
}
function getAttribute(string$name,$default=null){
if(false===key_exists($name,$this->attributes)){
return$default;
}
return$this->attributes[$name];
}
function withAttribute(string$name,$value):ServerRequestInterface
{
$new=clone$this;
$new->attributes[$name]=$value;
return$new;
}
function withoutAttribute(string$name):ServerRequestInterface
{
if(false===key_exists($name,$this->attributes)){
return$this;
}
$new=clone$this;
unset($new->attributes[$name]);
return$new;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
final class ServerRequestGlobalsFactory
{
private function __construct(){
}
static function fromArrays(#[\SensitiveParameter]array$server,array$query,array$post,#[\SensitiveParameter]array$cookies,array$files,?callable$headerProvider=null
):ServerRequestInterface{
$method=self::getRequestMethodFromServer($server);
$headers=self::removeInvalidHostHeader(self::getAllHeaders($server,$headerProvider));
[$uri,$requestTarget]=self::getUriAndRequestTargetFromServer($server,$method);
$body=new CachingStream(new LazyOpenStream('php://input','r+'));
$serverRequest=new ServerRequest($method,$uri,$headers,$body,self::getProtocolFromServer($server),$server);
if($requestTarget!==null){
$serverRequest=$serverRequest->withRequestTarget($requestTarget);
}
return$serverRequest
->withCookieParams($cookies)->withQueryParams($query)->withParsedBody($post)->withUploadedFiles(UploadedFileNormalizer::normalize($files));
}
static function getUriFromServerParams(#[\SensitiveParameter]array$server
):UriInterface{
$method=self::getRequestMethodFromServer($server);
return self::getUriAndRequestTargetFromServer($server,$method)[0];
}
private static function getAllHeaders(#[\SensitiveParameter]array$server,?callable$headerProvider
):array{
$headers=$headerProvider!==null?$headerProvider():false;
if(!is_array($headers)){
$headers=self::getHeadersFromServer($server);
}
return self::normalizeHeaderValues($headers);
}
private static function normalizeHeaderValues(#[\SensitiveParameter]array$headers
):array{
$normalized=[];
foreach($headers as$name=>$value){
if(is_scalar($value)||(is_object($value)&&method_exists($value,'__toString'))){
$normalized[$name]=(string)$value;
}
}
return$normalized;
}
private static function getHeadersFromServer(array$server):array
{
$headers=[];
$copyServer=['CONTENT_TYPE'=>'Content-Type','CONTENT_LENGTH'=>'Content-Length','CONTENT_MD5'=>'Content-Md5',];
foreach($server as$key=>$value){
if(!is_string($key)||!is_string($value)){
continue;
}
if(str_starts_with($key,'HTTP_')){
$header=substr($key,5);
if(isset($copyServer[$header],$server[$header])&&is_string($server[$header])){
continue;
}
$parts=explode(' ',Utils::asciiToLower(str_replace('_',' ',$header)));
foreach($parts as$i=>$part){
$parts[$i]=Utils::asciiUcFirst($part);
}
$header=join('-',$parts);
$headers[$header]=$value;
continue;
}
if(isset($copyServer[$key])){
$headers[$copyServer[$key]]=$value;
}
}
if(!isset($headers['Authorization'])){
if(isset($server['REDIRECT_HTTP_AUTHORIZATION'])&&is_string($server['REDIRECT_HTTP_AUTHORIZATION'])){
$headers['Authorization']=$server['REDIRECT_HTTP_AUTHORIZATION'];
}elseif(isset($server['PHP_AUTH_USER'])&&is_string($server['PHP_AUTH_USER'])){
$password=isset($server['PHP_AUTH_PW'])&&is_string($server['PHP_AUTH_PW'])?$server['PHP_AUTH_PW']:'';
$headers['Authorization']='Basic '.base64_encode($server['PHP_AUTH_USER'].':'.$password);
}elseif(isset($server['PHP_AUTH_DIGEST'])&&is_string($server['PHP_AUTH_DIGEST'])){
$headers['Authorization']=$server['PHP_AUTH_DIGEST'];
}
}
return$headers;
}
private static function removeInvalidHostHeader(array$headers):array
{
foreach($headers as$name=>$value){
if(Utils::asciiToLower((string)$name)!=='host'){
continue;
}
[$host]=self::extractHostAndPortFromAuthority($value);
if($host===null){
unset($headers[$name]);
}
}
return$headers;
}
private static function getServerParam(array$server,string$key):?string
{
return isset($server[$key])&&is_string($server[$key])?$server[$key]:null;
}
private static function getRequestMethodFromServer(array$server):string
{
return Utils::asciiToUpper(self::getServerParam($server,'REQUEST_METHOD')??'GET');
}
private static function getProtocolFromServer(array$server):string
{
$serverProtocol=self::getServerParam($server,'SERVER_PROTOCOL');
if($serverProtocol===null){
return'1.1';
}
return str_starts_with($serverProtocol,'HTTP/')?substr($serverProtocol,5):$serverProtocol;
}
private static function extractHostAndPortFromAuthority(string$authority):array
{
return Rfc9112::parseHostHeader($authority)??[null,null];
}
private static function parseServerPort(string$port):int
{
$parsed=Rfc9112::parsePort($port);
if($parsed===null){
throw new InvalidArgumentException('Invalid SERVER_PORT; expected an integer between 1 and 65535.');
}
return$parsed;
}
private static function withHostFromServer(UriInterface$uri,?string$host):?UriInterface
{
if($host===null){
return;
}
try{
return$uri->withHost($host);
}catch(InvalidArgumentException$e){
return;
}
}
private static function getUriWithSchemeFromServer(array$server):UriInterface
{
$uri=new Uri('');
$https=self::getServerParam($server,'HTTPS');
return$uri->withScheme(!empty($https)&&$https!=='off'?'https':'http');
}
private static function getAuthorityUriFromServer(#[\SensitiveParameter]array$server
):UriInterface{
$uri=self::getUriWithSchemeFromServer($server);
$hasPort=false;
$hasHost=false;
$authority=self::getServerParam($server,'HTTP_HOST');
if($authority!==null){
[$host,$port]=self::extractHostAndPortFromAuthority($authority);
if($host!==null){
$hostUri=self::withHostFromServer($uri,$host);
if($hostUri!==null){
$uri=$hostUri;
$hasHost=true;
if($port!==null){
$hasPort=true;
$uri=$uri->withPort($port);
}
}
}
}
foreach(['SERVER_NAME','SERVER_ADDR']as$serverParam){
if($hasHost){
continue;
}
$hostUri=self::withHostFromServer($uri,self::getServerParam($server,$serverParam));
if($hostUri!==null){
$uri=$hostUri;
$hasHost=true;
}
}
$serverPort=self::getServerParam($server,'SERVER_PORT');
if(!$hasPort&&$serverPort!==null){
$uri=$uri->withPort(self::parseServerPort($serverPort));
}
return$uri;
}
private static function getUriAndRequestTargetFromServer(#[\SensitiveParameter]array$server,string$method
):array{
$requestUri=self::getServerParam($server,'REQUEST_URI');
$queryString=self::getServerParam($server,'QUERY_STRING');
if($requestUri!==null){
$connectAuthority=self::parseConnectAuthorityFormRequestTarget($method,$requestUri);
if($connectAuthority!==null){
[$host,$port]=$connectAuthority;
$uri=self::getUriWithSchemeFromServer($server);
return[$uri->withHost($host)->withPort($port)->withPath('')->withQuery(''),$requestUri,];
}
$absoluteForm=self::getAbsoluteFormUriAndRequestTarget($requestUri,$queryString);
if($absoluteForm!==null){
return$absoluteForm;
}
}
$uri=self::getAuthorityUriFromServer($server);
if($requestUri===null){
if($queryString!==null){
$uri=$uri->withQuery($queryString);
}
return[$uri,null];
}
if(Rfc9112::isAsteriskFormRequestTarget($method,$requestUri)){
return[$uri->withPath('')->withQuery(''),'*'];
}
[$path,$query,$hasQuery]=self::splitRequestTargetQuery($requestUri);
$uri=$uri->withPath(self::normalizeOriginFormPathFromServer($path));
if($hasQuery){
$uri=$uri->withQuery($query);
}elseif($queryString!==null){
$uri=$uri->withQuery($queryString);
}
return[$uri,null];
}
private static function getAbsoluteFormUriAndRequestTarget(#[\SensitiveParameter]string$requestUri,?string$queryString
):?array{
if(!Rfc9112::isAbsoluteFormRequestTarget($requestUri)){
return;
}
try{
$targetUri=(new Uri($requestUri))->withFragment('');
}catch(InvalidArgumentException$e){
return;
}
if($targetUri->getHost()===''){
return;
}
$requestTarget=self::removeRequestTargetFragment($requestUri);
$requestTargetWithoutUserInfo=self::removeUserInfoFromAbsoluteFormRequestTarget($requestTarget);
if($requestTargetWithoutUserInfo!==$requestTarget){
$targetUri=$targetUri->withUserInfo('');
$requestTarget=$requestTargetWithoutUserInfo;
}
if(!str_contains($requestTarget,'?')&&$queryString!==null&&$queryString!==''){
$targetUri=$targetUri->withQuery($queryString);
$requestTarget.='?'.$queryString;
}
$normalizeRequestTarget=!Rfc9112::isValidRequestTarget($requestTarget)||self::hasEmptyPortInAbsoluteFormRequestTarget($requestTarget);
return[$targetUri,$normalizeRequestTarget?(string)$targetUri:$requestTarget];
}
private static function removeUserInfoFromAbsoluteFormRequestTarget(string$target):string
{
$authorityStart=strpos($target,'://');
if($authorityStart===false){
return$target;
}
$authorityStart+=3;
$authorityLength=strcspn($target,'/?#',$authorityStart);
$authority=substr($target,$authorityStart,$authorityLength);
if($authority===''){
return$target;
}
$lastAt=strrpos($authority,'@');
if($lastAt===false){
return$target;
}
$authorityEnd=$authorityStart+$authorityLength;
return substr($target,0,$authorityStart).substr($authority,$lastAt+1).substr($target,$authorityEnd);
}
private static function hasEmptyPortInAbsoluteFormRequestTarget(string$target):bool
{
$authorityStart=strpos($target,'://');
if($authorityStart===false){
return false;
}
$authorityStart+=3;
$authority=substr($target,$authorityStart,strcspn($target,'/?#',$authorityStart));
if($authority===''){
return false;
}
$lastAt=strrpos($authority,'@');
if($lastAt!==false){
$authority=substr($authority,$lastAt+1);
}
if($authority===''){
return false;
}
if(str_starts_with($authority,'[')){
$closingBracket=strpos($authority,']');
return$closingBracket!==false&&substr($authority,$closingBracket+1)===':';
}
return str_ends_with($authority,':');
}
private static function parseConnectAuthorityFormRequestTarget(string$method,string$target):?array
{
if(!Rfc9112::isConnectAuthorityFormRequestTarget($method,$target)){
return;
}
[$host,$port]=self::extractHostAndPortFromAuthority($target);
if($host===null||$port===null){
return;
}
return[$host,$port];
}
private static function removeRequestTargetFragment(string$target):string
{
return explode('#',$target,2)[0];
}
private static function splitRequestTargetQuery(string$target):array
{
$parts=explode('?',$target,2);
return[$parts[0],$parts[1]??'',isset($parts[1])];
}
private static function normalizeOriginFormPathFromServer(string$path):string
{
if($path===''||str_starts_with($path,'/')){
return$path;
}
return'/'.$path;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use Psr\Http\Message\StreamInterface;
class Stream implements StreamInterface
{
use NonSerializableStreamTrait;
private$stream;
private?int$size=null;
private bool$seekable;
private bool$readable;
private bool$writable;
private?string$uri=null;
private array$customMetadata;
function __construct($stream,array$options=[]){
if(!is_resource($stream)){
throw new\InvalidArgumentException('Stream must be a resource');
}
$this->size=Integers::assertOptionalNonNegativeSize($options['size']??null,'Stream size');
$this->customMetadata=$options['metadata']??[];
$this->stream=$stream;
$meta=stream_get_meta_data($this->stream);
$this->seekable=$meta['seekable'];
$this->readable=self::isReadableMode($meta['mode']);
$this->writable=self::isWritableMode($meta['mode']);
$this->uri=$meta['uri']??null;
}
function __destruct(){
$this->close();
}
function __toString():string
{
if($this->isSeekable()){
$this->seek(0);
}
return$this->getContents();
}
function getContents():string
{
if(!isset($this->stream)){
throw new\RuntimeException('Stream is detached');
}
if(!$this->readable){
throw new\RuntimeException('Cannot read from non-readable stream');
}
return Utils::tryGetContents($this->stream);
}
function close():void
{
if(isset($this->stream)){
if(is_resource($this->stream)){
fclose($this->stream);
}
$this->detach();
}
}
function detach(){
if(!isset($this->stream)){
return;
}
$result=$this->stream;
unset($this->stream);
$this->size=$this->uri=null;
$this->readable=$this->writable=$this->seekable=false;
return$result;
}
function getSize():?int
{
if($this->size!==null){
return$this->size;
}
if(!isset($this->stream)){
return;
}
if($this->uri){
clearstatcache(true,$this->uri);
}
$stats=fstat($this->stream);
if($stats===false){
return;
}
$this->size=Integers::assertEngineInteger($stats['size'],'Stream size');
return$this->size;
}
function isReadable():bool
{
return$this->readable;
}
function isWritable():bool
{
return$this->writable;
}
function isSeekable():bool
{
return$this->seekable;
}
function eof():bool
{
if(!isset($this->stream)){
throw new\RuntimeException('Stream is detached');
}
return feof($this->stream);
}
function tell():int
{
if(!isset($this->stream)){
throw new\RuntimeException('Stream is detached');
}
$result=ftell($this->stream);
if($result===false){
throw new\RuntimeException('Unable to determine stream position');
}
$position=Integers::assertEngineInteger($result,'Stream position');
if($position===null){
throw new\RuntimeException('Unable to determine stream position');
}
return$position;
}
function rewind():void
{
$this->seek(0);
}
function seek(int$offset,int$whence=SEEK_SET):void
{
if(!isset($this->stream)){
throw new\RuntimeException('Stream is detached');
}
if(!$this->seekable){
throw new\RuntimeException('Stream is not seekable');
}
if(fseek($this->stream,$offset,$whence)===-1){
throw new\RuntimeException('Unable to seek to stream position '.$offset.' with whence '.var_export($whence,true));
}
}
function read(int$length):string
{
if(!isset($this->stream)){
throw new\RuntimeException('Stream is detached');
}
if(!$this->readable){
throw new\RuntimeException('Cannot read from non-readable stream');
}
if($length<0){
throw new\RuntimeException('Length parameter cannot be negative');
}
if(0===$length){
return'';
}
try{
$string=fread($this->stream,$length);
}catch(TimeoutException$e){
throw$e;
}catch(\Exception$e){
if($this->timedOut()){
throw new TimeoutException('Unable to read from stream: timed out',0,$e);
}
throw new\RuntimeException('Unable to read from stream',0,$e);
}
if(false===$string){
if($this->timedOut()){
throw new TimeoutException('Unable to read from stream: timed out');
}
throw new\RuntimeException('Unable to read from stream');
}
if($string===''&&$this->timedOut()){
throw new TimeoutException('Unable to read from stream: timed out');
}
return$string;
}
function write(string$string):int
{
if(!isset($this->stream)){
throw new\RuntimeException('Stream is detached');
}
if(!$this->writable){
throw new\RuntimeException('Cannot write to a non-writable stream');
}
if($string===''){
return 0;
}
$this->size=null;
try{
$result=fputs($this->stream,$string);
}catch(TimeoutException$e){
throw$e;
}catch(\Exception$e){
if($this->writeTimedOut()){
throw new TimeoutException('Unable to write to stream: timed out',0,$e);
}
throw new\RuntimeException('Unable to write to stream',0,$e);
}
if($result===false){
if($this->writeTimedOut()){
throw new TimeoutException('Unable to write to stream: timed out');
}
throw new\RuntimeException('Unable to write to stream');
}
if($result===0&&$this->writeTimedOut()){
throw new TimeoutException('Unable to write to stream: timed out');
}
return$result;
}
function getMetadata(?string$key=null){
if(!isset($this->stream)){
return$key===null?[]:null;
}elseif($key===null){
return$this->customMetadata+stream_get_meta_data($this->stream);
}elseif(isset($this->customMetadata[$key])){
return$this->customMetadata[$key];
}
$meta=stream_get_meta_data($this->stream);
return$meta[$key]??null;
}
private static function isReadableMode(string$mode):bool
{
return str_starts_with($mode,'r')||str_contains($mode,'+');
}
private static function isWritableMode(string$mode):bool
{
return str_starts_with($mode,'a')||str_starts_with($mode,'w')||str_starts_with($mode,'x')||str_starts_with($mode,'c')||str_contains($mode,'+');
}
private function timedOut():bool
{
return StreamTimeout::isResourceReadTimedOut($this->stream);
}
private function writeTimedOut():bool
{
return StreamTimeout::isResourceWriteTimedOut($this->stream);
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use Psr\Http\Message\StreamInterface;
final class StreamTimeout
{
private function __construct(){
}
static function read(StreamInterface$stream,int$length,string$timeoutMessage):string
{
try{
$buffer=$stream->read($length);
}catch(TimeoutException$e){
throw$e;
}catch(\RuntimeException$e){
self::throwIfReadTimedOut($stream,$timeoutMessage,$e);
throw$e;
}
if($buffer===''){
self::throwIfReadTimedOut($stream,$timeoutMessage);
}
return$buffer;
}
static function throwIfReadTimedOut(StreamInterface$stream,string$message,?\Throwable$previous=null
):void{
if(self::isReadTimedOut($stream)){
throw new TimeoutException($message,0,$previous);
}
}
static function throwIfWriteTimedOut(StreamInterface$stream,?\Throwable$previous=null):void
{
if(self::isWriteTimedOut($stream)){
throw new TimeoutException('Unable to write to stream: timed out',0,$previous);
}
}
static function isReadTimedOut(StreamInterface$stream):bool
{
try{
if($stream->getMetadata('timed_out')!==true){
return false;
}
return!$stream->eof();
}catch(\Throwable$e){
return false;
}
}
static function isWriteTimedOut(StreamInterface$stream):bool
{
try{
return$stream->getMetadata('timed_out')===true;
}catch(\Throwable$e){
return false;
}
}
static function isResourceReadTimedOut($resource):bool
{
try{
$metadata=stream_get_meta_data($resource);
return($metadata['timed_out']??false)===true&&!feof($resource);
}catch(\Throwable$e){
return false;
}
}
static function isResourceWriteTimedOut($resource):bool
{
try{
$metadata=stream_get_meta_data($resource);
return($metadata['timed_out']??false)===true;
}catch(\Throwable$e){
return false;
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;
final class StreamWrapper
{
var$context;
private StreamInterface$stream;
private string$mode;
static function getResource(StreamInterface$stream){
self::register();
if($stream->isReadable()){
$mode=$stream->isWritable()?'r+':'r';
}elseif($stream->isWritable()){
$mode='w';
}else{
throw new\InvalidArgumentException('The stream must be readable, '.'writable, or both.');
}
$resource=@fopen('guzzle://stream',$mode,false,self::createStreamContext($stream));
if($resource===false){
throw new\RuntimeException('Unable to create stream resource');
}
return$resource;
}
static function createStreamContext(StreamInterface$stream){
return stream_context_create(['guzzle'=>['stream'=>$stream],]);
}
static function register():void
{
if(!in_array('guzzle',stream_get_wrappers())){
stream_wrapper_register('guzzle',__CLASS__);
}
}
function stream_open(string$path,string$mode,int$options,?string&$opened_path=null):bool
{
$options=stream_context_get_options($this->context);
$stream=$options['guzzle']['stream']??null;
if(!$stream instanceof StreamInterface){
return false;
}
$this->mode=$mode;
$this->stream=$stream;
return true;
}
function stream_read(int$count){
try{
return$this->stream->read($count);
}catch(\RuntimeException$e){
return false;
}
}
function stream_write(string$data):int
{
try{
return$this->stream->write($data);
}catch(\RuntimeException$e){
return-1;
}
}
function stream_flush():bool
{
return true;
}
function stream_tell(){
try{
return$this->stream->tell();
}catch(\RuntimeException$e){
return false;
}
}
function stream_eof():bool
{
try{
return$this->stream->eof();
}catch(\RuntimeException$e){
return true;
}
}
function stream_seek(int$offset,int$whence):bool
{
try{
$this->stream->seek($offset,$whence);
}catch(\RuntimeException$e){
return false;
}
return true;
}
function stream_cast(int$cast_as){
try{
$stream=clone$this->stream;
$resource=$stream->detach();
}catch(\RuntimeException$e){
return false;
}
return$resource??false;
}
function stream_stat(){
try{
$size=$this->stream->getSize();
}catch(\RuntimeException$e){
return false;
}
if($size===null){
return false;
}
static$modeMap=['r'=>33060,'rb'=>33060,'r+'=>33206,'w'=>33188,'wb'=>33188,];
return['dev'=>0,'ino'=>0,'mode'=>$modeMap[$this->mode]??0,'nlink'=>0,'uid'=>0,'gid'=>0,'rdev'=>0,'size'=>$size,'atime'=>0,'mtime'=>0,'ctime'=>0,'blksize'=>0,'blocks'=>0,];
}
function url_stat(string$path,int$flags):array
{
return['dev'=>0,'ino'=>0,'mode'=>0,'nlink'=>0,'uid'=>0,'gid'=>0,'rdev'=>0,'size'=>0,'atime'=>0,'mtime'=>0,'ctime'=>0,'blksize'=>0,'blocks'=>0,];
}
}
namespace Psr\Http\Message;
interface UploadedFileInterface
{
function getStream():StreamInterface;
function moveTo(string$targetPath):void;
function getSize():?int;
function getError():int;
function getClientFilename():?string;
function getClientMediaType():?string;
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use InvalidArgumentException;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UploadedFileInterface;
use RuntimeException;
class UploadedFile implements UploadedFileInterface
{
private const ERROR_MAP=[UPLOAD_ERR_OK=>'UPLOAD_ERR_OK',UPLOAD_ERR_INI_SIZE=>'UPLOAD_ERR_INI_SIZE',UPLOAD_ERR_FORM_SIZE=>'UPLOAD_ERR_FORM_SIZE',UPLOAD_ERR_PARTIAL=>'UPLOAD_ERR_PARTIAL',UPLOAD_ERR_NO_FILE=>'UPLOAD_ERR_NO_FILE',UPLOAD_ERR_NO_TMP_DIR=>'UPLOAD_ERR_NO_TMP_DIR',UPLOAD_ERR_CANT_WRITE=>'UPLOAD_ERR_CANT_WRITE',UPLOAD_ERR_EXTENSION=>'UPLOAD_ERR_EXTENSION',];
private?string$clientFilename;
private?string$clientMediaType;
private int$error;
private?string$file=null;
private bool$moved=false;
private?int$size;
private?StreamInterface$stream=null;
function __construct($streamOrFile,?int$size,int$errorStatus,?string$clientFilename=null,?string$clientMediaType=null
){
$this->setError($errorStatus);
$this->size=Integers::assertOptionalNonNegativeSize($size,'Uploaded file size');
$this->clientFilename=$clientFilename;
$this->clientMediaType=$clientMediaType;
if($this->isOk()){
$this->setStreamOrFile($streamOrFile);
}
}
private function setStreamOrFile($streamOrFile):void
{
if(is_string($streamOrFile)){
$this->file=$streamOrFile;
}elseif(is_resource($streamOrFile)){
$this->stream=new Stream($streamOrFile);
}elseif($streamOrFile instanceof StreamInterface){
$this->stream=$streamOrFile;
}else{
throw new InvalidArgumentException('Invalid stream or file provided for UploadedFile');
}
}
private function setError(int$error):void
{
if(!isset(UploadedFile::ERROR_MAP[$error])){
throw new InvalidArgumentException('Invalid error status for UploadedFile');
}
$this->error=$error;
}
private function isOk():bool
{
return$this->error===UPLOAD_ERR_OK;
}
function isMoved():bool
{
return$this->moved;
}
private function validateActive():void
{
if(false===$this->isOk()){
throw new RuntimeException(\sprintf('Cannot retrieve stream due to upload error (%s)',self::ERROR_MAP[$this->error]));
}
if($this->isMoved()){
throw new RuntimeException('Cannot retrieve stream after it has already been moved');
}
}
function getStream():StreamInterface
{
$this->validateActive();
if($this->stream instanceof StreamInterface){
return$this->stream;
}
$file=$this->file;
return new LazyOpenStream($file,'r+');
}
function moveTo(string$targetPath):void
{
$this->validateActive();
if($targetPath===''){
throw new InvalidArgumentException('Invalid path provided for move operation; must be a non-empty string');
}
if($this->file){
$this->moved=PHP_SAPI==='cli'?rename($this->file,$targetPath):move_uploaded_file($this->file,$targetPath);
}else{
$stream=$this->getStream();
if($stream->isSeekable()){
$stream->rewind();
}
Utils::copyToStream($stream,new LazyOpenStream($targetPath,'w'));
$this->moved=true;
}
if(false===$this->moved){
throw new RuntimeException(sprintf('Uploaded file could not be moved to %s',DiagnosticValue::escape($targetPath)));
}
}
function getSize():?int
{
return$this->size;
}
function getError():int
{
return$this->error;
}
function getClientFilename():?string
{
return$this->clientFilename;
}
function getClientMediaType():?string
{
return$this->clientMediaType;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use InvalidArgumentException;
use Psr\Http\Message\UploadedFileInterface;
final class UploadedFileNormalizer
{
private function __construct(){
}
static function normalize(array$files):array
{
$normalized=[];
foreach($files as$key=>$value){
if($value instanceof UploadedFileInterface){
$normalized[$key]=$value;
}elseif(is_array($value)&&key_exists('tmp_name',$value)){
$normalized[$key]=self::createUploadedFileFromSpec($value);
}elseif(is_array($value)){
$normalized[$key]=self::normalize($value);
continue;
}else{
throw new InvalidArgumentException('Invalid value in files specification');
}
}
return$normalized;
}
private static function createUploadedFileFromSpec(array$value){
self::assertFileSpec($value);
if(is_array($value['tmp_name'])){
return self::normalizeNestedFileSpec($value);
}
return new UploadedFile($value['tmp_name'],Integers::assertNonNegativeInteger($value['size'],'Uploaded file size'),Integers::assertNonNegativeInteger($value['error'],'Uploaded file error'),$value['name']??null,$value['type']??null
);
}
private static function assertFileSpec(array$value):void
{
if(!isset($value['tmp_name'],$value['size'],$value['error'])){
throw new InvalidArgumentException('Invalid file specification; expected keys "tmp_name", "size", and "error".');
}
}
private static function normalizeNestedFileSpec(array$files=[]):array
{
self::assertNestedFileSpec($files);
$normalizedFiles=[];
foreach(array_keys($files['tmp_name'])as$key){
if(!key_exists($key,$files['size'])||!key_exists($key,$files['error'])){
throw new InvalidArgumentException('Invalid nested file specification; expected "tmp_name", "size", and "error" arrays to have matching keys.');
}
$spec=['tmp_name'=>$files['tmp_name'][$key],'size'=>$files['size'][$key],'error'=>$files['error'][$key],'name'=>$files['name'][$key]??null,'type'=>$files['type'][$key]??null,];
$normalizedFiles[$key]=self::createUploadedFileFromSpec($spec);
}
return$normalizedFiles;
}
private static function assertNestedFileSpec(array$files):void
{
foreach(['tmp_name','size','error']as$key){
if(!isset($files[$key])||!is_array($files[$key])){
throw new InvalidArgumentException('Invalid nested file specification; expected keys "tmp_name", "size", and "error" to be arrays.');
}
}
foreach(['name','type']as$key){
if(isset($files[$key])&&!is_array($files[$key])){
throw new InvalidArgumentException(sprintf('Invalid nested file specification; expected key "%s" to be an array when present.',$key));
}
}
}
}
namespace Psr\Http\Message;
interface UriInterface
{
function getScheme():string;
function getAuthority():string;
function getUserInfo():string;
function getHost():string;
function getPort():?int;
function getPath():string;
function getQuery():string;
function getFragment():string;
function withScheme(string$scheme):UriInterface;
function withUserInfo(string$user,?string$password=null):UriInterface;
function withHost(string$host):UriInterface;
function withPort(?int$port):UriInterface;
function withPath(string$path):UriInterface;
function withQuery(string$query):UriInterface;
function withFragment(string$fragment):UriInterface;
function __toString():string;
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\MalformedUriException;
use Psr\Http\Message\UriInterface;
class Uri implements UriInterface,\JsonSerializable
{
private const HTTP_DEFAULT_HOST='localhost';
private const DEFAULT_PORTS=['http'=>80,'https'=>443,'ftp'=>21,'gopher'=>70,'nntp'=>119,'news'=>119,'telnet'=>23,'tn3270'=>23,'imap'=>143,'pop'=>110,'ldap'=>389,'ws'=>80,'wss'=>443,];
private const QUERY_SEPARATORS_REPLACEMENT=['='=>'%3D','&'=>'%26','+'=>'%2B'];
private string$scheme='';
private string$userInfo='';
private string$host='';
private?int$port=null;
private string$path='';
private string$query='';
private string$fragment='';
function __construct(#[\SensitiveParameter]string$uri=''){
if($uri!==''){
$parts=UriParser::parse($uri);
if($parts===false){
throw new MalformedUriException(\sprintf('Unable to parse URI: %s',Utils::redactUriStringForMessage($uri)));
}
try{
$this->applyParts($parts);
}catch(MalformedUriException$e){
throw$e;
}catch(\InvalidArgumentException$e){
throw new MalformedUriException($e->getMessage(),0,$e);
}
}
}
function __toString():string
{
return self::composeComponents($this->scheme,$this->getAuthority(),$this->path,$this->query,$this->fragment
);
}
static function composeComponents(?string$scheme,?string$authority,string$path,?string$query,?string$fragment):string
{
$uri='';
if($scheme!=''){
$uri.=$scheme.':';
}
if($authority!=''||($scheme==='file'&&str_starts_with($path,'/'))){
$uri.='//'.$authority;
}
if($authority!=''&&$path!=''&&!str_starts_with($path,'/')){
$path='/'.$path;
}
$uri.=$path;
if($query!=''){
$uri.='?'.$query;
}
if($fragment!=''){
$uri.='#'.$fragment;
}
return$uri;
}
static function isDefaultPort(UriInterface$uri):bool
{
return$uri->getPort()===null
||(isset(self::DEFAULT_PORTS[$uri->getScheme()])&&$uri->getPort()===self::DEFAULT_PORTS[$uri->getScheme()]);
}
static function isAbsolute(UriInterface$uri):bool
{
return$uri->getScheme()!=='';
}
static function isNetworkPathReference(UriInterface$uri):bool
{
return$uri->getScheme()===''&&$uri->getAuthority()!=='';
}
static function isAbsolutePathReference(UriInterface$uri):bool
{
return$uri->getScheme()===''&&$uri->getAuthority()===''&&isset($uri->getPath()[0])&&$uri->getPath()[0]==='/';
}
static function isRelativePathReference(UriInterface$uri):bool
{
return$uri->getScheme()===''&&$uri->getAuthority()===''&&(!isset($uri->getPath()[0])||$uri->getPath()[0]!=='/');
}
static function isSameDocumentReference(UriInterface$uri,?UriInterface$base=null):bool
{
if($base!==null){
$uri=UriResolver::resolve($base,$uri);
return($uri->getScheme()===$base->getScheme())&&($uri->getAuthority()===$base->getAuthority())&&(self::rawPath($uri)===self::rawPath($base))&&($uri->getQuery()===$base->getQuery());
}
return$uri->getScheme()===''&&$uri->getAuthority()===''&&$uri->getPath()===''&&$uri->getQuery()==='';
}
static function withoutQueryValue(UriInterface$uri,string$key):UriInterface
{
$result=self::getFilteredQueryString($uri,[$key]);
return$uri->withQuery(join('&',$result));
}
static function withQueryValue(UriInterface$uri,string$key,?string$value):UriInterface
{
$result=self::getFilteredQueryString($uri,[$key]);
$result[]=self::generateQueryString($key,$value);
return$uri->withQuery(join('&',$result));
}
static function withQueryValues(UriInterface$uri,array$keyValueArray):UriInterface
{
$result=self::getFilteredQueryString($uri,array_keys($keyValueArray));
foreach($keyValueArray as$key=>$value){
self::assertStringOrNullQueryValue($value);
$result[]=self::generateQueryString((string)$key,$value!==null?(string)$value:null);
}
return$uri->withQuery(join('&',$result));
}
private static function assertStringOrNullQueryValue($value):void
{
if($value!==null&&!is_string($value)){
throw new\InvalidArgumentException(\sprintf('Query string values must be a string or null, %s given.',\get_debug_type($value)));
}
}
static function fromParts(#[\SensitiveParameter]array$parts
):UriInterface{
$uri=new self;
try{
$uri->applyParts($parts);
$uri->validateState();
}catch(MalformedUriException$e){
throw$e;
}catch(\InvalidArgumentException$e){
throw new MalformedUriException($e->getMessage(),0,$e);
}
return$uri;
}
static function assertValidHost(string$host):void
{
if(!Rfc3986::isValidHost($host)){
throw new\InvalidArgumentException(sprintf('Invalid host: %s',DiagnosticValue::escape($host)));
}
}
function getScheme():string
{
return$this->scheme;
}
function getAuthority():string
{
$authority=$this->host;
if($this->userInfo!==''){
$authority=$this->userInfo.'@'.$authority;
}
if($this->port!==null){
$authority.=':'.$this->port;
}
return$authority;
}
function getUserInfo():string
{
return$this->userInfo;
}
function getHost():string
{
return$this->host;
}
function getPort():?int
{
return$this->port;
}
function getPath():string
{
if(str_starts_with($this->path,'//')){
return'/'.ltrim($this->path,'/');
}
return$this->path;
}
static function rawPath(UriInterface$uri):string
{
if(get_class($uri)===self::class){
if($uri->path!==''&&!str_starts_with($uri->path,'/')&&$uri->getAuthority()!==''){
return'/'.$uri->path;
}
return$uri->path;
}
$pattern=$uri->getScheme()===''?'%^(?://[^/?#]*)?([^?#]*)%':'%^(?:[^:/?#]+:)?(?://[^/?#]*)?([^?#]*)%';
$count=preg_match($pattern,(string)$uri,$matches);
if($count===false){
throw new\RuntimeException('Unable to read the URI path: '.preg_last_error_msg());
}
return$matches[1]??'';
}
function getQuery():string
{
return$this->query;
}
function getFragment():string
{
return$this->fragment;
}
function withScheme(string$scheme):UriInterface
{
$scheme=$this->filterScheme($scheme);
if($this->scheme===$scheme){
return$this;
}
$new=clone$this;
$new->scheme=$scheme;
$new->removeDefaultPort();
$new->validateState();
return$new;
}
function withUserInfo(string$user,#[\SensitiveParameter]?string$password=null
):UriInterface{
$info=$this->filterUserInfoComponent($user);
if($password!==null){
$info.=':'.$this->filterUserInfoComponent($password);
}
if($this->userInfo===$info){
return$this;
}
$new=clone$this;
$new->userInfo=$info;
$new->validateState();
return$new;
}
function withHost(string$host):UriInterface
{
$host=$this->filterHost($host);
if($this->host===$host){
return$this;
}
$new=clone$this;
$new->host=$host;
$new->validateState();
return$new;
}
function withPort(?int$port):UriInterface
{
$port=$this->filterPort($port);
if($this->port===$port){
return$this;
}
$new=clone$this;
$new->port=$port;
$new->removeDefaultPort();
$new->validateState();
return$new;
}
function withPath(string$path):UriInterface
{
$path=$this->filterPath($path);
if($this->path===$path){
return$this;
}
$new=clone$this;
$new->path=$path;
$new->validateState();
return$new;
}
function withQuery(string$query):UriInterface
{
$query=$this->filterQueryAndFragment($query);
if($this->query===$query){
return$this;
}
$new=clone$this;
$new->query=$query;
return$new;
}
function withFragment(string$fragment):UriInterface
{
$fragment=$this->filterQueryAndFragment($fragment);
if($this->fragment===$fragment){
return$this;
}
$new=clone$this;
$new->fragment=$fragment;
return$new;
}
function jsonSerialize():string
{
return$this->__toString();
}
private function applyParts(#[\SensitiveParameter]array$parts
):void{
$this->scheme=isset($parts['scheme'])?$this->filterScheme($parts['scheme']):'';
$this->userInfo=isset($parts['user'])?$this->filterUserInfoComponent($parts['user']):'';
$this->host=isset($parts['host'])?$this->filterHost($parts['host']):'';
$this->port=isset($parts['port'])?$this->filterPortPart($parts['port']):null;
$this->path=isset($parts['path'])?$this->filterPath($parts['path']):'';
$this->query=isset($parts['query'])?$this->filterQueryAndFragment($parts['query']):'';
$this->fragment=isset($parts['fragment'])?$this->filterQueryAndFragment($parts['fragment']):'';
if(isset($parts['pass'])){
$this->userInfo.=':'.$this->filterUserInfoComponent($parts['pass']);
}
$this->removeDefaultPort();
}
private function filterScheme(string$scheme):string
{
$scheme=Utils::asciiToLower($scheme);
if(!Rfc3986::isValidScheme($scheme)){
throw new\InvalidArgumentException(sprintf('Invalid scheme: %s',DiagnosticValue::escape($scheme)));
}
return$scheme;
}
private function filterUserInfoComponent(#[\SensitiveParameter]string$component
):string{
return$this->filterComponent('/(?:[^%'.Rfc3986::CHAR_UNRESERVED.Rfc3986::CHAR_SUB_DELIMS.']++|%(?!'.Rfc3986::HEX_OCTET.'))/',$component,'Unable to filter URI user info');
}
private function filterHost(string$host):string
{
$host=Utils::asciiToLower($host);
$filtered=\preg_replace_callback('/%'.Rfc3986::HEX_OCTET.'/',static function(array$m):string{
return Utils::asciiToUpper($m[0]);
},$host);
if($filtered===null){
throw new\RuntimeException('Unable to normalize URI host percent-encoding: '.\preg_last_error_msg());
}
self::assertValidHost($filtered);
if(str_starts_with($filtered,'[')&&!str_starts_with($filtered,'[v')){
$canonical=Rfc3986::tryCanonicalizeIpv6(substr($filtered,1,-1));
if($canonical!==null){
$filtered='['.$canonical.']';
}
}
return$filtered;
}
private function filterPort(?int$port):?int
{
if($port===null){
return;
}
if(0>$port||65535<$port){
throw new\InvalidArgumentException(sprintf('Invalid port: %d. Must be between 0 and 65535',$port));
}
return$port;
}
private function filterPortPart($port):?int
{
if(\is_int($port)){
return$this->filterPort($port);
}
if(\is_string($port)&&\ctype_digit($port)){
if(Rfc3986::isValidPort($port)){
return(int)\ltrim($port,'0');
}
throw new\InvalidArgumentException(sprintf('Invalid port: %s. Must be between 0 and 65535',\ltrim($port,'0')));
}
throw new\InvalidArgumentException(sprintf('Invalid port: %s. Must be between 0 and 65535',self::describeInvalidPort($port)));
}
private static function describeInvalidPort($port):string
{
if(\is_string($port)){
return DiagnosticValue::escape($port);
}
if(\is_int($port)){
return(string)$port;
}
if(\is_bool($port)){
return$port?'true':'false';
}
if($port===null){
return'null';
}
if(\is_float($port)){
if(\is_nan($port)){
return'NAN';
}
if(\is_infinite($port)){
return$port>0?'INF':'-INF';
}
return\sprintf('%.14G',$port);
}
return\get_debug_type($port);
}
private static function getFilteredQueryString(UriInterface$uri,array$keys):array
{
$current=$uri->getQuery();
if($current===''){
return[];
}
$decodedKeys=array_map(function($k):string{
return rawurldecode((string)$k);
},$keys);
return array_filter(explode('&',$current),static function(string$part)use($decodedKeys):bool{
return!in_array(rawurldecode(explode('=',$part)[0]),$decodedKeys,true);
});
}
private static function generateQueryString(string$key,?string$value):string
{
$queryString=strtr($key,self::QUERY_SEPARATORS_REPLACEMENT);
if($value!==null){
$queryString.='='.strtr($value,self::QUERY_SEPARATORS_REPLACEMENT);
}
return$queryString;
}
private function removeDefaultPort():void
{
if($this->port!==null&&self::isDefaultPort($this)){
$this->port=null;
}
}
private function filterPath(string$path):string
{
return$this->filterComponent('/(?:[^'.Rfc3986::CHAR_UNRESERVED.Rfc3986::CHAR_SUB_DELIMS.'%:@\/]++|%(?!'.Rfc3986::HEX_OCTET.'))/',$path,'Unable to filter URI path');
}
private function filterQueryAndFragment(string$str):string
{
return$this->filterComponent('/(?:[^'.Rfc3986::CHAR_UNRESERVED.Rfc3986::CHAR_SUB_DELIMS.'%:@\/\?]++|%(?!'.Rfc3986::HEX_OCTET.'))/',$str,'Unable to filter URI query or fragment');
}
private function filterComponent(string$pattern,#[\SensitiveParameter]string$component,string$context
):string{
$filtered=preg_replace_callback($pattern,[$this,'rawurlencodeMatchZero'],$component);
if($filtered===null){
throw new\RuntimeException($context.': '.preg_last_error_msg());
}
return$filtered;
}
private function rawurlencodeMatchZero(array$match):string
{
return rawurlencode($match[0]);
}
private function validateState():void
{
if($this->host===''&&($this->scheme==='http'||$this->scheme==='https')){
$this->host=self::HTTP_DEFAULT_HOST;
}
if($this->getAuthority()===''){
if(str_starts_with($this->path,'//')){
throw new MalformedUriException('The path of a URI without an authority must not start with two slashes "//"');
}
if($this->scheme===''&&str_contains(explode('/',$this->path,2)[0],':')){
throw new MalformedUriException('A relative URI must not have a path beginning with a segment containing a colon');
}
}
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\UriInterface;
final class UriComparator
{
static function isCrossOrigin(UriInterface$original,UriInterface$modified):bool
{
if(!Utils::caselessEquals(self::normalizeHost($original),self::normalizeHost($modified))){
return true;
}
if($original->getScheme()!==$modified->getScheme()){
return true;
}
if(self::computePort($original)!==self::computePort($modified)){
return true;
}
return false;
}
private static function normalizeHost(UriInterface$uri):string
{
$host=$uri->getHost();
if(!str_starts_with($host,'[')||!str_ends_with($host,']')){
return$host;
}
$canonical=Rfc3986::tryCanonicalizeIpv6(substr($host,1,-1));
if($canonical===null){
return$host;
}
return'['.$canonical.']';
}
private static function computePort(UriInterface$uri):?int
{
$port=$uri->getPort();
if(null!==$port){
return$port;
}
if(\in_array($uri->getScheme(),['http','ws'],true)){
return 80;
}
if(\in_array($uri->getScheme(),['https','wss'],true)){
return 443;
}
return;
}
private function __construct(){
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\UriInterface;
final class UriNormalizer
{
const PRESERVING_NORMALIZATIONS=self::CAPITALIZE_PERCENT_ENCODING|self::DECODE_UNRESERVED_CHARACTERS|self::CONVERT_EMPTY_PATH|self::REMOVE_DEFAULT_HOST|self::REMOVE_DEFAULT_PORT|self::REMOVE_DOT_SEGMENTS|self::CANONICALIZE_IPV6_HOST;
const CAPITALIZE_PERCENT_ENCODING=1;
const DECODE_UNRESERVED_CHARACTERS=2;
const CONVERT_EMPTY_PATH=4;
const REMOVE_DEFAULT_HOST=8;
const REMOVE_DEFAULT_PORT=16;
const REMOVE_DOT_SEGMENTS=32;
const REMOVE_DUPLICATE_SLASHES=64;
const SORT_QUERY_PARAMETERS=128;
const CANONICALIZE_IPV6_HOST=256;
static function normalize(UriInterface$uri,int$flags=self::PRESERVING_NORMALIZATIONS):UriInterface
{
if($flags&self::CAPITALIZE_PERCENT_ENCODING){
$uri=self::capitalizePercentEncoding($uri);
}
if($flags&self::DECODE_UNRESERVED_CHARACTERS){
$uri=self::decodeUnreservedCharacters($uri);
}
if($flags&self::CONVERT_EMPTY_PATH&&$uri->getPath()===''&&($uri->getScheme()==='http'||$uri->getScheme()==='https')){
$uri=$uri->withPath('/');
}
if($flags&self::REMOVE_DEFAULT_HOST&&$uri->getScheme()==='file'&&$uri->getHost()==='localhost'){
if($uri->getUserInfo()===''&&$uri->getPort()===null){
$path=Uri::rawPath($uri);
if(str_starts_with($path,'//')){
$uri=$uri->withPath('/.'.$path);
}
}
$uri=$uri->withHost('');
}
if($flags&self::REMOVE_DEFAULT_PORT&&$uri->getPort()!==null&&Uri::isDefaultPort($uri)){
$uri=$uri->withPort(null);
}
$removeDotSegments=($flags&self::REMOVE_DOT_SEGMENTS)&&!Uri::isRelativePathReference($uri);
if($removeDotSegments||$flags&self::REMOVE_DUPLICATE_SLASHES){
$path=Uri::rawPath($uri);
if($removeDotSegments){
$path=UriResolver::removeDotSegments($path);
}
if($flags&self::REMOVE_DUPLICATE_SLASHES){
$path=preg_replace('#//++#','/',$path);
if($path===null){
throw new\RuntimeException('Unable to remove duplicate slashes from URI path: '.preg_last_error_msg());
}
}
$uri=$uri->withPath(UriResolver::guardedPath($uri,$path));
}
if($flags&self::SORT_QUERY_PARAMETERS&&$uri->getQuery()!==''){
$queryKeyValues=explode('&',$uri->getQuery());
sort($queryKeyValues);
$uri=$uri->withQuery(join('&',$queryKeyValues));
}
if($flags&self::CANONICALIZE_IPV6_HOST){
$uri=self::canonicalizeIpv6Host($uri);
}
return$uri;
}
static function isEquivalent(UriInterface$uri1,UriInterface$uri2,int$normalizations=self::PRESERVING_NORMALIZATIONS):bool
{
return(string)self::normalize($uri1,$normalizations)===(string)self::normalize($uri2,$normalizations);
}
private static function capitalizePercentEncoding(UriInterface$uri):UriInterface
{
$regex='/(?:%'.Rfc3986::HEX_OCTET.')++/';
$callback=function(array$match):string{
return Utils::asciiToUpper($match[0]);
};
$uri=self::withNormalizedUserInfo($uri,$regex,$callback);
$uri=self::withNormalizedHost($uri,$regex,$callback);
return self::withGuardedPath($uri,self::normalizePercentEncodingInComponent(Uri::rawPath($uri),$regex,$callback))->withQuery(self::normalizePercentEncodingInComponent($uri->getQuery(),$regex,$callback))->withFragment(self::normalizePercentEncodingInComponent($uri->getFragment(),$regex,$callback));
}
private static function decodeUnreservedCharacters(UriInterface$uri):UriInterface
{
$regex='/%(?:2D|2E|5F|7E|3[0-9]|[46][1-9A-F]|[57][0-9A])/i';
$callback=function(array$match):string{
return rawurldecode($match[0]);
};
$hostCallback=function(array$match):string{
return Utils::asciiToLower(rawurldecode($match[0]));
};
$uri=self::withNormalizedUserInfo($uri,$regex,$callback);
$uri=self::withNormalizedHost($uri,$regex,$hostCallback);
return self::withGuardedPath($uri,self::normalizePercentEncodingInComponent(Uri::rawPath($uri),$regex,$callback))->withQuery(self::normalizePercentEncodingInComponent($uri->getQuery(),$regex,$callback))->withFragment(self::normalizePercentEncodingInComponent($uri->getFragment(),$regex,$callback));
}
private static function withGuardedPath(UriInterface$uri,string$path):UriInterface
{
if($path===Uri::rawPath($uri)){
return$uri;
}
return$uri->withPath(UriResolver::guardedPath($uri,$path));
}
private static function withNormalizedUserInfo(UriInterface$uri,string$regex,callable$callback):UriInterface
{
$userInfo=$uri->getUserInfo();
if(!str_contains($userInfo,'%')){
return$uri;
}
$normalized=self::normalizePercentEncodingInComponent($userInfo,$regex,$callback);
if($normalized===$userInfo){
return$uri;
}
$parts=explode(':',$normalized,2);
if($parts[0]===''){
return$uri;
}
$candidate=$uri->withUserInfo($parts[0],$parts[1]??null);
if($candidate->getUserInfo()!==$normalized){
return$uri;
}
return$candidate;
}
private static function withNormalizedHost(UriInterface$uri,string$regex,callable$callback):UriInterface
{
$host=$uri->getHost();
if(str_starts_with($host,'[')||!str_contains($host,'%')){
return$uri;
}
$normalized=self::normalizePercentEncodingInComponent($host,$regex,$callback);
if($normalized===$host){
return$uri;
}
$candidate=$uri->withHost($normalized);
if($candidate->getHost()!==$normalized){
return$uri;
}
return$candidate;
}
private static function normalizePercentEncodingInComponent(string$component,string$regex,callable$callback):string
{
$malformed=preg_match('/%(?!'.Rfc3986::HEX_OCTET.')/',$component);
if($malformed===false){
throw new\RuntimeException('Unable to scan URI component percent-encoding: '.preg_last_error_msg());
}
if($malformed===1){
return$component;
}
$normalized=preg_replace_callback($regex,$callback,$component);
if($normalized===null){
throw new\RuntimeException('Unable to normalize URI component percent-encoding: '.preg_last_error_msg());
}
return$normalized;
}
private static function canonicalizeIpv6Host(UriInterface$uri):UriInterface
{
$host=$uri->getHost();
if(!str_starts_with($host,'[')||!str_ends_with($host,']')){
return$uri;
}
$canonical=Rfc3986::tryCanonicalizeIpv6(substr($host,1,-1));
if($canonical===null||'['.$canonical.']'===$host){
return$uri;
}
$candidate=$uri->withHost('['.$canonical.']');
if($candidate->getHost()!=='['.$canonical.']'){
return$uri;
}
return$candidate;
}
private function __construct(){
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
final class UriParser
{
private function __construct(){
}
static function parse(string$url){
if(self::isPathNoSchemeReference($url)){
return self::parsePathNoSchemeReference($url);
}
$prefix='';
$ipv6Prefix=preg_match('%\A((?:[0-9A-Za-z+.-]+:)?//)(?:([^/?#@]*)(@))?(\[[^\]\x00-\x20\x7F/?#@]+\])(.*)\z%s',$url,$matches);
if($ipv6Prefix===false){
return false;
}
if($ipv6Prefix===1){
$suffix=$matches[5];
if(preg_match('%\A(?::[0-9]*)?(?:[/?#].*)?\z%s',$suffix)!==1){
return false;
}
if(str_contains($matches[4],'%')){
return false;
}
$prefix=$matches[1];
if($matches[3]==='@'){
$encodedUserInfo=preg_replace_callback('%[^:/@?&=#]+%usD',static function(array$matches):string{
return urlencode($matches[0]);
},$matches[2]);
if($encodedUserInfo===null){
return false;
}
$prefix.=$encodedUserInfo.'@';
}
$prefix.=$matches[4];
$url=$suffix;
}
$encodedUrl=preg_replace_callback('%[^:/@?&=#]+%usD',static function(array$matches):string{
return urlencode($matches[0]);
},$url
);
if($encodedUrl===null){
return false;
}
$result=parse_url($prefix.$encodedUrl);
if($result===false){
return false;
}
return array_map('urldecode',$result);
}
private static function isPathNoSchemeReference(string$url):bool
{
if($url===''||str_starts_with($url,'/')||str_starts_with($url,'?')||str_starts_with($url,'#')){
return false;
}
$firstSegment=substr($url,0,strcspn($url,'/?#'));
return!str_contains($firstSegment,':');
}
private static function parsePathNoSchemeReference(string$url):array
{
$parts=[];
if(false!==($fragmentPosition=strpos($url,'#'))){
$parts['fragment']=substr($url,$fragmentPosition+1);
$url=substr($url,0,$fragmentPosition);
}
if(false!==($queryPosition=strpos($url,'?'))){
$parts['query']=substr($url,$queryPosition+1);
$url=substr($url,0,$queryPosition);
}
$parts['path']=$url;
return$parts;
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use Psr\Http\Message\UriInterface;
final class UriResolver
{
static function removeDotSegments(string$path):string
{
if($path===''||$path==='/'){
return$path;
}
$results=[];
$segments=explode('/',$path);
$floor=$segments[0]===''?1:0;
foreach($segments as$segment){
if($segment==='..'){
if(count($results)>$floor){
array_pop($results);
}
}elseif($segment!=='.'){
$results[]=$segment;
}
}
$newPath=join('/',$results);
if(str_starts_with($path,'/')&&!str_starts_with($newPath,'/')){
$newPath='/'.$newPath;
}elseif($newPath!==''&&($segment==='.'||$segment==='..')){
$newPath.='/';
}
return$newPath;
}
static function guardedPath(UriInterface$uri,string$path):string
{
if($uri->getAuthority()!==''){
return$path;
}
if(str_starts_with($path,'//')){
if($uri instanceof Uri&&($uri->getScheme()==='http'||$uri->getScheme()==='https')){
return$path;
}
return'/.'.$path;
}
if($uri->getScheme()===''&&str_contains(explode('/',$path,2)[0],':')){
return'./'.$path;
}
return$path;
}
static function resolve(UriInterface$base,UriInterface$rel):UriInterface
{
if((string)$rel===''){
return$base;
}
if($rel->getScheme()!=''){
return$rel->withPath(self::guardedPath($rel,self::removeDotSegments(Uri::rawPath($rel))));
}
if($rel->getAuthority()!=''){
return$rel
->withScheme($base->getScheme())->withPath(self::removeDotSegments(Uri::rawPath($rel)));
}
$relPath=Uri::rawPath($rel);
if($relPath===''){
return$base
->withQuery($rel->getQuery()!=''?$rel->getQuery():$base->getQuery())->withFragment($rel->getFragment());
}
if(str_starts_with($relPath,'/')){
$targetPath=$relPath;
}else{
$basePath=Uri::rawPath($base);
if($base->getAuthority()!=''&&$basePath===''){
$targetPath='/'.$relPath;
}else{
$lastSlashPos=strrpos($basePath,'/');
if($lastSlashPos===false){
$targetPath=$relPath;
}else{
$targetPath=substr($basePath,0,$lastSlashPos+1).$relPath;
}
}
}
$targetPath=self::removeDotSegments($targetPath);
return$base
->withPath(self::guardedPath($base,$targetPath))->withQuery($rel->getQuery())->withFragment($rel->getFragment());
}
static function relativize(UriInterface$base,UriInterface$target):UriInterface
{
if($target->getScheme()!==''&&($base->getScheme()!==$target->getScheme()||$target->getAuthority()===''&&$base->getAuthority()!=='')){
return$target;
}
if(Uri::isRelativePathReference($target)){
return$target;
}
if($target->getAuthority()!==''&&$base->getAuthority()!==$target->getAuthority()){
return$target->withScheme('');
}
if(self::needsNetworkPathReference($base,$target)){
return$target->withScheme('');
}
$emptyPathUri=$target->withScheme('')->withPath('')->withUserInfo('')->withPort(null)->withHost('');
if(Uri::rawPath($base)!==Uri::rawPath($target)){
return$emptyPathUri->withPath(self::getRelativePath($base,$target));
}
if($base->getQuery()===$target->getQuery()&&($target->getFragment()!==''||$base->getFragment()==='')){
return$emptyPathUri->withQuery('');
}
if($target->getQuery()===''){
$segments=explode('/',Uri::rawPath($target));
$lastSegment=end($segments);
if($lastSegment===''||str_contains($lastSegment,':')){
$lastSegment="./$lastSegment";
}
return$emptyPathUri->withPath($lastSegment);
}
return$emptyPathUri;
}
private static function needsNetworkPathReference(UriInterface$base,UriInterface$target):bool
{
if($target->getAuthority()===''||Uri::rawPath($target)!==''){
return false;
}
return Uri::rawPath($base)!==''||($base->getQuery()!==''&&$target->getQuery()==='')||($base->getFragment()!==''&&$target->getFragment()===''&&$base->getQuery()===$target->getQuery());
}
private static function getRelativePath(UriInterface$base,UriInterface$target):string
{
$sourceSegments=explode('/',Uri::rawPath($base));
$targetSegments=explode('/',Uri::rawPath($target));
array_pop($sourceSegments);
$targetLastSegment=array_pop($targetSegments);
foreach($sourceSegments as$i=>$segment){
if(isset($targetSegments[$i])&&$segment===$targetSegments[$i]){
unset($sourceSegments[$i],$targetSegments[$i]);
}else{
break;
}
}
$targetSegments[]=$targetLastSegment;
$relativePath=str_repeat('../',count($sourceSegments)).join('/',$targetSegments);
if($relativePath===''||str_contains(explode('/',$relativePath,2)[0],':')){
$relativePath="./$relativePath";
}elseif(str_starts_with($relativePath,'/')){
if($base->getAuthority()!=''&&Uri::rawPath($base)===''){
$relativePath=".$relativePath";
}else{
$relativePath="./$relativePath";
}
}
return$relativePath;
}
private function __construct(){
}
}
declare(strict_types=1);
namespace GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Exception\TimeoutException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
final class Utils
{
private function __construct(){
}
static function asciiToLower(string$string):string
{
return strtr($string,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz');
}
static function asciiToUpper(string$string):string
{
return strtr($string,'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ');
}
static function asciiUcFirst(string$string):string
{
if($string===''){
return'';
}
return self::asciiToUpper($string[0]).substr($string,1);
}
static function caselessContains(string$haystack,string$needle):bool
{
return str_contains(self::asciiToLower($haystack),self::asciiToLower($needle));
}
static function caselessEquals(string$left,string$right):bool
{
return self::asciiToLower($left)===self::asciiToLower($right);
}
static function caselessRemove(array$keys,array$data):array
{
$result=[];
foreach($keys as&$key){
$key=self::asciiToLower((string)$key);
}
foreach($data as$k=>$v){
if(!in_array(self::asciiToLower((string)$k),$keys)){
$result[$k]=$v;
}
}
return$result;
}
static function copyToStream(StreamInterface$source,StreamInterface$dest,int$maxLen=-1):int
{
$bufferSize=8192;
$copied=0;
if($maxLen===-1){
while(!$source->eof()){
$buf=StreamTimeout::read($source,$bufferSize,'Unable to read from stream: timed out');
if($buf===''){
break;
}
self::writeAll($dest,$buf);
$copied=Integers::add($copied,strlen($buf));
}
}else{
$remaining=$maxLen;
while($remaining>0&&!$source->eof()){
$buf=StreamTimeout::read($source,min($bufferSize,$remaining),'Unable to read from stream: timed out');
$len=strlen($buf);
if(!$len){
break;
}
$remaining-=$len;
self::writeAll($dest,$buf);
$copied=Integers::add($copied,$len);
}
}
return$copied;
}
private static function writeAll(StreamInterface$dest,string$buf):void
{
$written=0;
$len=strlen($buf);
while($written<$len){
try{
$result=$dest->write(substr($buf,$written));
}catch(TimeoutException$e){
throw$e;
}catch(\RuntimeException$e){
StreamTimeout::throwIfWriteTimedOut($dest,$e);
throw$e;
}
if($result<=0){
StreamTimeout::throwIfWriteTimedOut($dest);
throw new\RuntimeException('Unable to write to stream');
}
$written+=$result;
}
}
static function copyToString(StreamInterface$stream,int$maxLen=-1):string
{
$buffer='';
if($maxLen===-1){
while(!$stream->eof()){
$buf=StreamTimeout::read($stream,1048576,'Unable to read from stream: timed out');
if($buf===''){
break;
}
$buffer.=$buf;
}
return$buffer;
}
$len=0;
while(!$stream->eof()&&$len<$maxLen){
$buf=StreamTimeout::read($stream,$maxLen-$len,'Unable to read from stream: timed out');
if($buf===''){
break;
}
$buffer.=$buf;
$len=strlen($buffer);
}
return$buffer;
}
static function hash(StreamInterface$stream,string$algo,bool$rawOutput=false):string
{
$pos=$stream->tell();
if($pos>0){
$stream->rewind();
}
$ctx=hash_init($algo);
while(!$stream->eof()){
$buf=StreamTimeout::read($stream,1048576,'Unable to calculate stream hash: timed out');
if($buf===''){
break;
}
hash_update($ctx,$buf);
}
$out=hash_final($ctx,$rawOutput);
$stream->seek($pos);
return$out;
}
static function modifyRequest(RequestInterface$request,array$changes):RequestInterface
{
if(!$changes){
return$request;
}
self::assertValidModifyRequestChanges($changes);
$headers=$request->getHeaders();
if(!isset($changes['uri'])){
$uri=$request->getUri();
}else{
$uri=$changes['uri'];
$host=$uri->getHost();
if($host!==''){
Uri::assertValidHost($host);
if(isset($changes['set_headers'])&&is_array($changes['set_headers'])){
foreach(array_keys($changes['set_headers'])as$header){
if(self::asciiToLower((string)$header)==='host'){
throw new\InvalidArgumentException('Cannot modify request with both a URI containing a host and an explicit Host header.');
}
}
}
$changes['set_headers']['Host']=$host;
$port=$uri->getPort();
if($port!==null){
$standardPorts=['http'=>80,'https'=>443];
$scheme=$uri->getScheme();
if(!isset($standardPorts[$scheme])||$port!=$standardPorts[$scheme]){
$changes['set_headers']['Host'].=':'.$port;
}
}
}
}
if(!empty($changes['remove_headers'])){
$headers=self::caselessRemove($changes['remove_headers'],$headers);
}
if(!empty($changes['set_headers'])){
$headers=self::caselessRemove(array_keys($changes['set_headers']),$headers);
$headers=$changes['set_headers']+$headers;
}
if(isset($changes['query'])){
$uri=$uri->withQuery($changes['query']);
}
$hasHost=false;
foreach(array_keys($headers)as$header){
if(self::asciiToLower((string)$header)==='host'){
$hasHost=true;
break;
}
}
if(!$hasHost&&$uri->getHost()!==''){
$host=$uri->getHost();
Uri::assertValidHost($host);
if(($port=$uri->getPort())!==null){
$host.=':'.$port;
}
$headers=['Host'=>[$host]]+$headers;
}
$new=$request;
if(isset($changes['method'])){
$new=$new->withMethod($changes['method']);
}
if(isset($changes['uri'])||isset($changes['query'])){
$new=$new->withUri($uri,true);
}
if($headers!==$new->getHeaders()){
foreach(array_keys($new->getHeaders())as$header){
$new=$new->withoutHeader((string)$header);
}
$addedHeaders=[];
foreach($headers as$header=>$value){
$header=(string)$header;
$normalized=self::asciiToLower($header);
if(isset($addedHeaders[$normalized])){
$new=$new->withAddedHeader($addedHeaders[$normalized],$value);
}else{
$new=$new->withHeader($header,$value);
$addedHeaders[$normalized]=$header;
}
}
}
if(isset($changes['body'])){
$new=$new->withBody(self::streamFor($changes['body']));
}
if(isset($changes['version'])){
$new=$new->withProtocolVersion($changes['version']);
}
return$new;
}
private static function assertValidModifyRequestChanges(array$changes):void
{
foreach(['method','query','version']as$key){
if(\array_key_exists($key,$changes)&&!\is_string($changes[$key])){
self::assertValidModifyRequestChange($key,'string',$changes[$key]);
}
}
if(\array_key_exists('uri',$changes)&&!$changes['uri']instanceof UriInterface){
self::assertValidModifyRequestChange('uri','UriInterface',$changes['uri']);
}
if(\array_key_exists('body',$changes)&&$changes['body']===null){
self::assertValidModifyRequestChange('body','resource|string|StreamInterface|callable|\Iterator|\Stringable',$changes['body']);
}
if(\array_key_exists('set_headers',$changes)){
if(!\is_array($changes['set_headers'])){
self::assertValidModifyRequestChange('set_headers','array<array-key, string|non-empty-array<array-key, string>>',$changes['set_headers']);
}else{
foreach($changes['set_headers']as$header=>$value){
$headerPath=\sprintf('set_headers.%s',(string)$header);
if(\is_array($value)){
if($value===[]){
self::assertValidModifyRequestChange($headerPath,'string|non-empty-array<array-key, string>',$value);
break;
}
foreach($value as$index=>$item){
if(!\is_string($item)){
self::assertValidModifyRequestChange(\sprintf('%s.%s',$headerPath,(string)$index),'string',$item);
break 2;
}
}
}elseif(!\is_string($value)){
self::assertValidModifyRequestChange($headerPath,'string|non-empty-array<array-key, string>',$value);
break;
}
}
}
}
if(!\array_key_exists('remove_headers',$changes)){
return;
}
if(!\is_array($changes['remove_headers'])){
self::assertValidModifyRequestChange('remove_headers','array<array-key, string|int>',$changes['remove_headers']);
return;
}
foreach($changes['remove_headers']as$index=>$header){
if(!\is_string($header)&&!\is_int($header)){
self::assertValidModifyRequestChange(\sprintf('remove_headers.%s',(string)$index),'string|int',$header);
return;
}
}
}
private static function assertValidModifyRequestChange(string$key,string$expected,$value):void
{
throw new\InvalidArgumentException(\sprintf('Utils::modifyRequest() change "%s" must be %s; %s provided.',DiagnosticValue::escape($key),$expected,\get_debug_type($value)));
}
static function readLine(StreamInterface$stream,?int$maxLength=null):string
{
$buffer='';
$size=0;
while(!$stream->eof()){
if(''===($byte=StreamTimeout::read($stream,1,'Unable to read line from stream: timed out'))){
return$buffer;
}
$buffer.=$byte;
if($byte==="\n"||++$size===$maxLength-1){
break;
}
}
return$buffer;
}
static function redactUserInfo(#[\SensitiveParameter]UriInterface$uri
):UriInterface{
return$uri->getUserInfo()===''?$uri:$uri->withUserInfo('***');
}
static function redactUserInfoInString(string$subject,string$uri):string
{
if(\strpos($uri,'@')===false){
return$subject;
}
$schemePosition=\strpos($uri,'://');
$remainder=$schemePosition===false?$uri:\substr($uri,$schemePosition+3);
if(\parse_url($schemePosition===false?'http://'.$uri:$uri)===false){
$atPosition=\strrpos($remainder,'@');
if($atPosition===false||$atPosition===0){
return$subject;
}
return\str_replace(\substr($remainder,0,$atPosition).'@','***@',$subject);
}
$authority=\substr($remainder,0,\strcspn($remainder,'/?#'));
$atPosition=\strrpos($authority,'@');
if($atPosition===false||$atPosition===0){
return$subject;
}
return\str_replace(\substr($authority,0,$atPosition).'@','***@',$subject);
}
static function redactUriForMessage(#[\SensitiveParameter]UriInterface$uri
):string{
try{
$raw=(string)$uri;
}catch(\Throwable$e){
return'[unavailable URI]';
}
try{
if($uri->getUserInfo()!==''){
$uri=$uri->withUserInfo('***');
}
return DiagnosticValue::escape((string)$uri->withQuery('')->withFragment(''));
}catch(\Throwable$e){
return self::redactUriStringForMessage($raw);
}
}
static function redactUriStringForMessage(#[\SensitiveParameter]string$uri
):string{
try{
$uri=self::redactUserInfoInString($uri,$uri);
return DiagnosticValue::escape(\substr($uri,0,\strcspn($uri,'?#')));
}catch(\Throwable$e){
return'[unavailable URI]';
}
}
static function streamFor($resource='',array$options=[]):StreamInterface
{
if(is_scalar($resource)){
if(!is_string($resource)){
throw new\InvalidArgumentException(\sprintf('Cannot create a stream from %s; pass a string, resource, StreamInterface, Stringable, Iterator, callable, or null.',\get_debug_type($resource)));
}
$stream=self::tryFopen('php://temp','r+');
if($resource!==''){
fputs($stream,$resource);
fseek($stream,0);
}
return new Stream($stream,$options);
}
switch(gettype($resource)){
case'resource':if((\stream_get_meta_data($resource)['uri']??'')==='php://input'){
$stream=self::tryFopen('php://temp','w+');
stream_copy_to_stream($resource,$stream);
fseek($stream,0);
$resource=$stream;
}
return new Stream($resource,$options);
case'object':if($resource instanceof StreamInterface){
return$resource;
}elseif($resource instanceof\Iterator){
return new PumpStream(function(int$length)use($resource){
while($resource->valid()){
$result=$resource->current();
$resource->next();
if(is_float($result)&&!is_finite($result)){
throw new\UnexpectedValueException('Iterator must not yield non-finite float values');
}
if($result===null||is_scalar($result)){
$data=(string)$result;
}elseif(is_object($result)&&method_exists($result,'__toString')){
$data=(string)$result;
}else{
throw new\UnexpectedValueException('Iterator must yield scalar, null, or stringable values');
}
if($data!==''){
return$data;
}
}
return false;
},$options);
}elseif(method_exists($resource,'__toString')){
return self::streamFor((string)$resource,$options);
}
break;
case'NULL':return new Stream(self::tryFopen('php://temp','r+'),$options);
}
if(is_callable($resource)){
return new PumpStream($resource,$options);
}
throw new\InvalidArgumentException('Invalid resource type: '.\get_debug_type($resource));
}
static function tryFopen(string$filename,string$mode){
$ex=null;
set_error_handler(static function(int$errno,string$errstr)use($filename,$mode,&$ex):bool{
$ex=new\RuntimeException(sprintf('Unable to open %s using mode %s: %s',DiagnosticValue::escape($filename),DiagnosticValue::escape($mode),DiagnosticValue::escape($errstr)));
return true;
});
try{
$handle=fopen($filename,$mode);
}catch(\Throwable$e){
$ex=new\RuntimeException(sprintf('Unable to open %s using mode %s: %s',DiagnosticValue::escape($filename),DiagnosticValue::escape($mode),$e->getMessage()),0,$e);
}
restore_error_handler();
if($ex){
throw$ex;
}
return$handle;
}
static function tryGetContents($stream):string
{
$ex=null;
set_error_handler(static function(int$errno,string$errstr)use(&$ex):bool{
$ex=new\RuntimeException(sprintf('Unable to read stream contents: %s',DiagnosticValue::escape($errstr)));
return true;
});
try{
$contents=stream_get_contents($stream);
if($contents===false){
$ex=StreamTimeout::isResourceReadTimedOut($stream)?new TimeoutException('Unable to read stream contents: timed out'):new\RuntimeException('Unable to read stream contents');
}elseif(StreamTimeout::isResourceReadTimedOut($stream)){
$ex=new TimeoutException('Unable to read stream contents: timed out');
}
}catch(TimeoutException$e){
$ex=$e;
}catch(\Throwable$e){
$ex=StreamTimeout::isResourceReadTimedOut($stream)?new TimeoutException('Unable to read stream contents: timed out',0,$e):new\RuntimeException(sprintf('Unable to read stream contents: %s',$e->getMessage()),0,$e);
}
restore_error_handler();
if($ex){
throw$ex;
}
return$contents;
}
static function uriFor($uri):UriInterface
{
if($uri instanceof UriInterface){
return$uri;
}
if(is_string($uri)){
return new Uri($uri);
}
throw new\InvalidArgumentException('URI must be a string or UriInterface');
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Exception\ResponseException;
use GuzzleHttp\Exception\TooManyRedirectsException;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
class RedirectMiddleware
{
use NonSerializableTrait;
const HISTORY_HEADER='X-Guzzle-Redirect-History';
const STATUS_HISTORY_HEADER='X-Guzzle-Redirect-Status-History';
const DEFAULT_SETTINGS=['max'=>5,'protocols'=>['http','https'],'strict'=>false,'referer'=>false,'track_redirects'=>false,];
private$nextHandler;
function __construct(callable$nextHandler){
$this->nextHandler=$nextHandler;
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
$fn=$this->nextHandler;
if(empty($options['allow_redirects'])){
return$fn($request,$options);
}
if($options['allow_redirects']===true){
$options['allow_redirects']=self::DEFAULT_SETTINGS;
}elseif(!\is_array($options['allow_redirects'])){
throw new InvalidArgumentException('allow_redirects must be true, false, or array');
}else{
$options['allow_redirects']+=self::DEFAULT_SETTINGS;
}
if(empty($options['allow_redirects']['max'])){
return$fn($request,$options);
}
return$fn($request,$options)->then(function(#[\SensitiveParameter]ResponseInterface$response
)use($request,$options){
return$this->checkRedirect($request,$options,$response);
});
}
function checkRedirect(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]ResponseInterface$response
){
if(!self::isRedirectStatusCode($response->getStatusCode())||!$response->hasHeader('Location')){
return$response;
}
$this->guardMax($request,$response,$options);
$nextRequest=$this->modifyRequest($request,$options,$response);
if(Psr7\UriComparator::isCrossOrigin($request->getUri(),$nextRequest->getUri())){
unset($options['auth'],$options['__guzzle_digest_retries']);
if(defined('\CURLOPT_HTTPAUTH')&&defined('\CURLOPT_USERPWD')){
unset($options['curl'][\CURLOPT_HTTPAUTH],$options['curl'][\CURLOPT_USERPWD]);
}
}
if(isset($options['allow_redirects']['on_redirect'])){
($options['allow_redirects']['on_redirect'])($request,$response,$nextRequest->getUri());
}
unset($options['delay']);
$promise=$this($nextRequest,$options);
if(!empty($options['allow_redirects']['track_redirects'])){
return$this->withTracking($promise,(string)$nextRequest->getUri(),$response->getStatusCode());
}
return$promise;
}
private function withTracking(PromiseInterface$promise,#[\SensitiveParameter]string$uri,int$statusCode
):PromiseInterface{
return$promise->then(static function(#[\SensitiveParameter]ResponseInterface$response
)use($uri,$statusCode):ResponseInterface{
$historyHeader=$response->getHeader(self::HISTORY_HEADER);
$statusHeader=$response->getHeader(self::STATUS_HISTORY_HEADER);
\array_unshift($historyHeader,$uri);
\array_unshift($statusHeader,(string)$statusCode);
return$response->withHeader(self::HISTORY_HEADER,$historyHeader)->withHeader(self::STATUS_HISTORY_HEADER,$statusHeader);
}
);
}
private function guardMax(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response,#[\SensitiveParameter]array&$options
):void{
$current=$options['__redirect_count']??0;
$options['__redirect_count']=$current+1;
$max=$options['allow_redirects']['max'];
if($options['__redirect_count']>$max){
throw new TooManyRedirectsException("Will not follow more than {$max} redirects",$request,$response);
}
}
function modifyRequest(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]ResponseInterface$response
):RequestInterface{
$modify=self::getRedirectRequestModifiers($request,$options,$response);
$protocols=$options['allow_redirects']['protocols'];
$uriFactory=$options[RequestOptions::URI_FACTORY]??new HttpFactory;
if(!$uriFactory instanceof UriFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::URI_FACTORY,UriFactoryInterface::class
));
}
$uri=self::redirectUri($uriFactory,$request,$response,$protocols);
$idnOptions=Idn::normalizeConversionOption($options['idn_conversion']??null);
if($idnOptions!==null){
$uri=Idn::convertUri($uri,$idnOptions);
}
$modify['uri']=$uri;
if(!isset($modify['body'])){
try{
Psr7\Message::rewindBody($request);
}catch(\Exception$e){
throw new ResponseException('Redirect failed because the request body could not be rewound',$request,$response,$e
);
}
}
$crossOrigin=Psr7\UriComparator::isCrossOrigin($request->getUri(),$modify['uri']);
if($options['allow_redirects']['referer']&&$modify['uri']->getScheme()===$request->getUri()->getScheme()){
$referer=$request->getUri()->withUserInfo('')->withFragment('');
if($crossOrigin){
$referer=$referer->withPath('/')->withQuery('');
}
$modify['set_headers']['Referer']=(string)$referer;
}else{
$modify['remove_headers'][]='Referer';
}
if($crossOrigin){
$modify['remove_headers'][]='Authorization';
$modify['remove_headers'][]='Cookie';
}
return Psr7\Utils::modifyRequest($request,$modify);
}
private static function isRedirectStatusCode(int$statusCode):bool
{
return\in_array($statusCode,[301,302,303,307,308],true);
}
private static function getRedirectRequestModifiers(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]ResponseInterface$response
):array{
$statusCode=$response->getStatusCode();
if($statusCode!==303
&&($statusCode>302||$options['allow_redirects']['strict'])){
return[];
}
$requestMethod=$request->getMethod();
if($requestMethod==='QUERY'&&\in_array($statusCode,[301,302],true)){
return[];
}
$streamFactory=$options[RequestOptions::STREAM_FACTORY]??new HttpFactory;
if(!$streamFactory instanceof StreamFactoryInterface){
throw new InvalidArgumentException(\sprintf('%s must be an instance of %s',RequestOptions::STREAM_FACTORY,StreamFactoryInterface::class
));
}
return['method'=>\in_array($requestMethod,['GET','HEAD','OPTIONS'],true)?$requestMethod:'GET','body'=>$streamFactory->createStream(''),'remove_headers'=>['Content-Length','Transfer-Encoding'],];
}
private static function redirectUri(UriFactoryInterface$uriFactory,#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]ResponseInterface$response,array$protocols
):UriInterface{
$location=$response->getHeaderLine('Location');
try{
$locationUri=$uriFactory->createUri($location);
$resolvedUri=Psr7\UriResolver::resolve($request->getUri(),$locationUri
);
if(!$uriFactory instanceof HttpFactory
&&$locationUri->getScheme()===''&&$locationUri->getAuthority()===''){
$resolvedUri=$uriFactory->createUri((string)$resolvedUri);
}
}catch(\InvalidArgumentException$e){
throw new BadResponseException(\sprintf('Redirect URI, %s, is invalid.',Psr7\Utils::redactUriStringForMessage($location)),$request,$response,$e);
}
if(!\in_array($resolvedUri->getScheme(),$protocols,true)){
throw new BadResponseException(\sprintf('Redirect URI, %s, does not use one of the allowed redirect protocols: %s',Psr7\Utils::redactUriForMessage($resolvedUri),\implode(', ',$protocols)),$request,$response);
}
return$resolvedUri;
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
final class RequestOptions
{
private function __construct(){
}
const ALLOW_REDIRECTS='allow_redirects';
const AUTH='auth';
const BODY='body';
const CERT='cert';
const CERT_TYPE='cert_type';
const COOKIES='cookies';
const CONNECT_TIMEOUT='connect_timeout';
const CRYPTO_METHOD='crypto_method';
const CRYPTO_METHOD_MAX='crypto_method_max';
const CURL='curl';
const DEBUG='debug';
const DECODE_CONTENT='decode_content';
const DELAY='delay';
const EXPECT='expect';
const FORM_PARAMS='form_params';
const HEADERS='headers';
const HTTP_ERRORS='http_errors';
const IDN_CONVERSION='idn_conversion';
const JSON='json';
const MULTIPART='multipart';
const MULTIPLEX='multiplex';
const ON_HEADERS='on_headers';
const ON_STATS='on_stats';
const ON_TRAILERS='on_trailers';
const PROGRESS='progress';
const PROTOCOLS='protocols';
const PROXY='proxy';
const QUERY='query';
const REQUEST_FACTORY='request_factory';
const STREAM_FACTORY='stream_factory';
const RESPONSE_FACTORY='response_factory';
const SINK='sink';
const SYNCHRONOUS='synchronous';
const SSL_KEY='ssl_key';
const SSL_KEY_TYPE='ssl_key_type';
const STREAM='stream';
const STREAM_CONTEXT='stream_context';
const VERIFY='verify';
const TIMEOUT='timeout';
const READ_TIMEOUT='read_timeout';
const RETRIES='retries';
const URI_FACTORY='uri_factory';
const VERSION='version';
const FORCE_IP_RESOLVE='force_ip_resolve';
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Promise as P;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
class RetryMiddleware
{
use NonSerializableTrait;
private$nextHandler;
private$decider;
private$delay;
function __construct(callable$decider,callable$nextHandler,?callable$delay=null){
$this->decider=$decider;
$this->nextHandler=$nextHandler;
$this->delay=$delay?:static function(int$retries):int{
return(int)((2**($retries-1))*1000);
};
}
function __invoke(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options
):PromiseInterface{
if(!isset($options['retries'])){
$options['retries']=0;
}elseif(!\is_int($options['retries'])){
throw new\InvalidArgumentException('retries must be an integer');
}
return($this->nextHandler)($request,$options)->then($this->onFulfilled($request,$options),$this->onRejected($request,$options));
}
private function onFulfilled(RequestInterface$request,array$options):callable
{
return function(#[\SensitiveParameter]$value
)use($request,$options){
if(!($this->decider)($options['retries'],$request,$value,null
)){
return$value;
}
return$this->doRetry($request,$options,$value);
};
}
private function onRejected(RequestInterface$req,array$options):callable
{
return function(#[\SensitiveParameter]$reason
)use($req,$options):PromiseInterface{
if(!($this->decider)($options['retries'],$req,null,$reason
)){
return P\Create::rejectionFor($reason);
}
return$this->doRetry($req,$options);
};
}
private function doRetry(#[\SensitiveParameter]RequestInterface$request,#[\SensitiveParameter]array$options,#[\SensitiveParameter]?ResponseInterface$response=null
):PromiseInterface{
++$options['retries'];
$options['delay']=($this->delay)($options['retries'],$response,$request);
return$this($request,$options);
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
final class TransferStats
{
private RequestInterface$request;
private?ResponseInterface$response;
private?float$transferTime;
private array$handlerStats;
private$handlerErrorData;
function __construct(RequestInterface$request,?ResponseInterface$response=null,?float$transferTime=null,$handlerErrorData=null,array$handlerStats=[]){
$this->request=$request;
$this->response=$response;
$this->transferTime=$transferTime;
$this->handlerErrorData=$handlerErrorData;
$this->handlerStats=$handlerStats;
}
function getRequest():RequestInterface
{
return$this->request;
}
function getResponse():?ResponseInterface
{
return$this->response;
}
function hasResponse():bool
{
return$this->response!==null;
}
function getHandlerErrorData(){
return$this->handlerErrorData;
}
function getEffectiveUri():UriInterface
{
return$this->request->getUri();
}
function getTransferTime():?float
{
return$this->transferTime;
}
function getHandlerStats():array
{
return$this->handlerStats;
}
function getHandlerStat(string$stat){
return$this->handlerStats[$stat]??null;
}
}
declare(strict_types=1);
namespace GuzzleHttp;
final class TransportSharing
{
const NONE='none';
const HANDLER_PREFER='handler_prefer';
const HANDLER_REQUIRE='handler_require';
const PERSISTENT_PREFER='persistent_prefer';
const PERSISTENT_REQUIRE='persistent_require';
private function __construct(){
}
}
declare(strict_types=1);
namespace GuzzleHttp;
use GuzzleHttp\Exception\InvalidArgumentException;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\Handler\CurlShareHandleState;
use GuzzleHttp\Handler\CurlVersion;
use GuzzleHttp\Handler\Proxy;
use GuzzleHttp\Handler\StreamHandler;
use GuzzleHttp\Handler\StreamTlsSessionCache;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
final class Utils
{
private function __construct(){
}
static function headersFromLines(iterable$lines):array
{
$headers=[];
foreach($lines as$line){
$parts=\explode(':',$line,2);
$headers[\trim($parts[0]," \n\r\t\0\x0B")][]=isset($parts[1])?\trim($parts[1]," \n\r\t\0\x0B"):null;
}
return$headers;
}
static function debugResource($value=null){
if(\is_resource($value)){
return$value;
}
if(\defined('STDOUT')){
return\STDOUT;
}
return Psr7\Utils::tryFopen('php://output','w');
}
static function chooseHandler(array$handlerOptions=[]):callable
{
$sharingMode=CurlShareHandleState::normalizeMode($handlerOptions['transport_sharing']??null,'transport_sharing');
$sharingRequired=self::isTransportSharingRequired($sharingMode);
$connectionCapsRequired=self::hasConnectionCapOptions($handlerOptions);
$sharedPoolCapsSupported=CurlVersion::supportsSharedPoolConnectionCaps();
if($connectionCapsRequired&&!$sharedPoolCapsSupported&&$sharingMode===TransportSharing::PERSISTENT_REQUIRE){
throw new InvalidArgumentException(\sprintf('The "max_host_connections" and "max_total_connections" options cannot be combined with required persistent transport sharing because applying connection caps to shared connection pools requires libcurl %s or higher.',CurlVersion::SHARED_POOL_CONNECTION_CAP_VERSION));
}
if($connectionCapsRequired&&!$sharedPoolCapsSupported&&$sharingMode===TransportSharing::PERSISTENT_PREFER){
$sharingMode=TransportSharing::HANDLER_PREFER;
}
$handler=self::createCurlHandler($sharingMode,$handlerOptions);
$streamCanShareSessions=(bool)\ini_get('allow_url_fopen')&&StreamTlsSessionCache::isSupported();
if($sharingRequired&&$handler===null){
if($sharingMode===TransportSharing::PERSISTENT_REQUIRE){
throw new\RuntimeException('Required persistent transport sharing requires the PHP cURL extension, curl_exec() or curl_multi_exec(), and a supported libcurl version with SSL support.');
}
if(!$streamCanShareSessions){
throw new\RuntimeException('Required transport sharing requires the PHP cURL extension (curl_exec()/curl_multi_exec()) with a supported libcurl version and SSL support, or PHP 8.6+ with the OpenSSL TLS session API and the allow_url_fopen ini setting.');
}
}
if(\ini_get('allow_url_fopen')){
return self::addStreamHandler($handler,$sharingMode,self::connectionCapOptions($handlerOptions));
}
if($handler!==null){
return$handler;
}
if($connectionCapsRequired){
throw new\RuntimeException('Connection cap options require a cap-capable cURL multi handler or the allow_url_fopen ini setting for stream fallback.');
}
throw new\RuntimeException('GuzzleHttp requires a supported cURL version with SSL support, the allow_url_fopen ini setting, or a custom HTTP handler.');
}
private static function isTransportSharingRequired(string$sharingMode):bool
{
return\in_array($sharingMode,[TransportSharing::HANDLER_REQUIRE,TransportSharing::PERSISTENT_REQUIRE],true);
}
private static function hasConnectionCapOptions(array$handlerOptions):bool
{
return self::connectionCapOptions($handlerOptions)!==[];
}
private static function createCurlHandler(string$sharingMode,array$handlerOptions):?callable
{
if(!CurlVersion::supportsCurlHandler()){
return;
}
if($sharingMode===TransportSharing::HANDLER_REQUIRE&&!CurlShareHandleState::supportsHandlerRequireShare()){
return;
}
$connectionCapOptions=self::connectionCapOptions($handlerOptions);
if($connectionCapOptions!==[]&&!\function_exists('curl_multi_exec')){
return;
}
$curlHandlerOptions=self::createCurlHandlerOptions($sharingMode);
$curlMultiHandlerOptions=$curlHandlerOptions+$connectionCapOptions;
if(($handlerOptions['multiplex']??null)===Multiplexing::NONE){
$curlMultiHandlerOptions['multiplex']=Multiplexing::NONE;
}
if(\function_exists('curl_multi_exec')&&\function_exists('curl_exec')){
$multiHandler=new CurlMultiHandler($curlMultiHandlerOptions);
if($connectionCapOptions!==[]){
return$multiHandler;
}
return Proxy::wrapSync($multiHandler,new CurlHandler($curlHandlerOptions));
}
if($connectionCapOptions===[]&&\function_exists('curl_exec')){
return new CurlHandler($curlHandlerOptions);
}
if(\function_exists('curl_multi_exec')){
return new CurlMultiHandler($curlMultiHandlerOptions);
}
return;
}
private static function createCurlHandlerOptions(string$sharingMode):array
{
if($sharingMode===TransportSharing::NONE){
return[];
}
$shareState=CurlShareHandleState::fromOption($sharingMode);
return$shareState===null?[]:['transport_sharing'=>$shareState];
}
private static function connectionCapOptions(array$handlerOptions):array
{
$options=[];
foreach(['max_host_connections','max_total_connections']as$capOption){
$value=$handlerOptions[$capOption]??null;
if($value===null){
continue;
}
if(!\is_int($value)||$value<1){
throw new InvalidArgumentException(\sprintf('%s must be a positive integer.',$capOption));
}
$options[$capOption]=$value;
}
return$options;
}
private static function addStreamHandler(?callable$handler,string$sharingMode,array$connectionCapOptions):callable
{
$streamHandler=new StreamHandler(['transport_sharing'=>$sharingMode]+$connectionCapOptions);
return$handler
?Proxy::wrapStreaming($handler,$streamHandler):$streamHandler;
}
static function defaultUserAgent():string
{
return sprintf('GuzzleHttp/%d',ClientInterface::MAJOR_VERSION);
}
static function normalizeHeaderKeys(array$headers):array
{
$result=[];
foreach(\array_keys($headers)as$key){
$result[Psr7\Utils::asciiToLower((string)$key)]=$key;
}
return$result;
}
static function normalizeProtocols($protocols):array
{
if(!\is_array($protocols)||$protocols===[]){
throw new InvalidArgumentException('protocols must be a non-empty array of "http" and/or "https"');
}
$normalized=[];
foreach($protocols as$protocol){
if(!\is_string($protocol)){
throw new InvalidArgumentException('protocols must contain only strings');
}
if($protocol!=='http'&&$protocol!=='https'){
throw new InvalidArgumentException('protocols may only contain "http" and "https"');
}
$normalized[$protocol]=true;
}
return\array_keys($normalized);
}
}
namespace Symfony\Polyfill\Php80;
final class Php80
{
static function fdiv(float$dividend,float$divisor):float
{
return@($dividend/$divisor);
}
static function get_debug_type($value):string
{
switch(true){
case null===$value:return'null';
case\is_bool($value):return'bool';
case\is_string($value):return'string';
case\is_array($value):return'array';
case\is_int($value):return'int';
case\is_float($value):return'float';
case\is_object($value):break;
case$value instanceof\__PHP_Incomplete_Class:return'__PHP_Incomplete_Class';
default:if(null===$type=@get_resource_type($value)){
return'unknown';
}
if('Unknown'===$type){
$type='closed';
}
return"resource ($type)";
}
$class=\get_class($value);
if(false===strpos($class,'@')){
return$class;
}
return(get_parent_class($class)?:key(class_implements($class))?:'class').'@anonymous';
}
static function get_resource_id($res):int
{
if(!\is_resource($res)&&null===@get_resource_type($res)){
throw new\TypeError(\sprintf('Argument 1 passed to get_resource_id() must be of the type resource, %s given',get_debug_type($res)));
}
return(int)$res;
}
static function preg_last_error_msg():string
{
switch(preg_last_error()){
case\PREG_INTERNAL_ERROR:return'Internal error';
case\PREG_BAD_UTF8_ERROR:return'Malformed UTF-8 characters, possibly incorrectly encoded';
case\PREG_BAD_UTF8_OFFSET_ERROR:return'The offset did not correspond to the beginning of a valid UTF-8 code point';
case\PREG_BACKTRACK_LIMIT_ERROR:return'Backtrack limit exhausted';
case\PREG_RECURSION_LIMIT_ERROR:return'Recursion limit exhausted';
case\PREG_JIT_STACKLIMIT_ERROR:return'JIT stack limit exhausted';
case\PREG_NO_ERROR:return'No error';
default:return'Unknown error';
}
}
static function str_contains(string$haystack,string$needle):bool
{
return''===$needle||false!==strpos($haystack,$needle);
}
static function str_starts_with(string$haystack,string$needle):bool
{
return 0===strncmp($haystack,$needle,\strlen($needle));
}
static function str_ends_with(string$haystack,string$needle):bool
{
if(''===$needle||$needle===$haystack){
return true;
}
if(''===$haystack){
return false;
}
$needleLength=\strlen($needle);
return$needleLength<=\strlen($haystack)&&0===substr_compare($haystack,$needle,-$needleLength);
}
}
namespace Symfony\Polyfill\Php80;
class PhpToken implements\Stringable
{
var$id;
var$text;
var$line;
var$pos;
function __construct(int$id,string$text,int$line=-1,int$position=-1){
$this->id=$id;
$this->text=$text;
$this->line=$line;
$this->pos=$position;
}
function getTokenName():?string
{
if($this->id<256){
return\chr($this->id&255);
}
return'UNKNOWN'===($name=token_name($this->id))?null:$name;
}
function is($kind):bool
{
foreach((array)$kind as$value){
if(\in_array($value,[$this->id,$this->text],true)){
return true;
}
}
return false;
}
function isIgnorable():bool
{
return\in_array($this->id,[\T_WHITESPACE,\T_COMMENT,\T_DOC_COMMENT,\T_OPEN_TAG],true);
}
function __toString():string
{
return(string)$this->text;
}
static function tokenize(string$code,int$flags=0):array
{
$line=1;
$position=0;
$tokens=token_get_all($code,$flags);
foreach($tokens as$index=>$token){
if(\is_string($token)){
$id=\ord($token[-1]);
$text=$token;
}else{
[$id,$text,$line]=$token;
}
$tokens[$index]=new static($id,$text,$line,$position);
$position+=\strlen($text);
$line+=preg_match_all('/\r\n?|\n/',$text);
}
return$tokens;
}
}
namespace Symfony\Polyfill\Php82;
trait NoDynamicProperties
{
function __set(string$name,$value):void
{
throw new\Error('Cannot create dynamic property '.self::class.'::$'.$name);
}
}
namespace Symfony\Polyfill\Php82;
class Php82
{
static function odbc_connection_string_is_quoted(string$str):bool
{
if(''===$str||'{'!==$str[0]){
return false;
}
$length=\strlen($str)-1;
for($i=0;$i<$length;++$i){
if('}'!==$str[$i]){
continue;
}
if('}'!==$str[++$i]){
return false;
}
}
return true;
}
static function odbc_connection_string_should_quote(string$str):bool
{
return false!==strpbrk($str,'[]{}(),;?*=!@ ');
}
static function odbc_connection_string_quote(string$str):string
{
return'{'.str_replace('}','}}',$str).'}';
}
static function ini_parse_quantity(string$value):int
{
$ctype_space=" \t\v\r\n\f";
$str=0;
$str_end=\strlen($value);
$digits=$str;
$overflow=false;
while($digits<$str_end&&false!==strpos($ctype_space,$value[$digits])){
++$digits;
}
while($digits<$str_end&&false!==strpos($ctype_space,$value[$str_end-1])){
--$str_end;
}
if($digits===$str_end){
return 0;
}
$is_negative=false;
if('+'===$value[$digits]){
++$digits;
}elseif('-'===$value[$digits]){
$is_negative=true;
++$digits;
}
if($digits===$str_end||$value[$digits]<'0'||$value[$digits]>'9'){
$message=\sprintf('Invalid quantity "%s": no valid leading digits, interpreting as "0" for backwards compatibility',self::escapeString($value));
trigger_error($message,\E_USER_WARNING);
return 0;
}
$base=10;
$allowed_digits='0123456789';
if('0'===$value[$digits]&&($digits+1===$str_end||false===strpos($allowed_digits,$value[$digits+1]))){
if($digits+1===$str_end){
return 0;
}
switch($value[$digits+1]){
case'g':case'G':case'm':case'M':case'k':case'K':goto evaluation;
case'x':case'X':$base=16;
$allowed_digits='0123456789abcdefABCDEF';
break;
case'o':case'O':$base=8;
$allowed_digits='01234567';
break;
case'b':case'B':$base=2;
$allowed_digits='01';
break;
default:$message=\sprintf('Invalid prefix "0%s", interpreting as "0" for backwards compatibility',$value[$digits+1]);
trigger_error($message,\E_USER_WARNING);
return 0;
}
$digits+=2;
if($digits===$str_end){
$message=\sprintf('Invalid quantity "%s": no digits after base prefix, interpreting as "0" for backwards compatibility',self::escapeString($value));
trigger_error($message,\E_USER_WARNING);
return 0;
}
$digits_consumed=$digits;
while($digits_consumed<$str_end&&false!==strpos($ctype_space,$value[$digits_consumed])){
++$digits_consumed;
}
if($digits_consumed!==$str_end&&('+'===$value[$digits_consumed]||'-'===$value[$digits_consumed])){
++$digits_consumed;
}
if($digits_consumed+1<$str_end&&'0'===$value[$digits_consumed]){
switch($value[$digits_consumed+1]){
case'x':case'X':case'o':case'O':$digits_consumed+=2;
break;
case'b':case'B':if(16!==$base){
$digits_consumed+=2;
}
break;
}
}
if($digits!==$digits_consumed){
$message=\sprintf('Invalid quantity "%s": no digits after base prefix, interpreting as "0" for backwards compatibility',self::escapeString($value));
trigger_error($message,\E_USER_WARNING);
return 0;
}
}
evaluation:if(10===$base&&'0'===$value[$digits]){
$base=8;
$allowed_digits='01234567';
}
while($digits<$str_end&&' '===$value[$digits]){
++$digits;
}
if($digits<$str_end&&'+'===$value[$digits]){
++$digits;
}elseif($digits<$str_end&&'-'===$value[$digits]){
$is_negative=true;
$overflow=true;
++$digits;
}
$digits_end=$digits;
while($digits_end<$str_end&&false!==strpos($allowed_digits,$value[$digits_end])){
++$digits_end;
}
$bits=\PHP_INT_SIZE<<2;
$mask=(1<<$bits)-1;
$high=$low=0;
for($i=$digits;$i<$digits_end;++$i){
$low=$low*$base+hexdec($value[$i]);
$high=$high*$base+($low>>$bits);
$low&=$mask;
if($high>$mask){
break;
}
}
if($high>$mask){
$retval=-1;
$overflow=true;
}else{
$retval=($high<<$bits)|$low;
if($is_negative&&0===$retval){
$is_negative=false;
$overflow=false;
}elseif(0>$retval){
$overflow=$overflow||!$is_negative||\PHP_INT_MIN!==$retval;
}elseif($is_negative){
$retval=-$retval;
}
}
if($digits_end===$digits){
$message=\sprintf('Invalid quantity "%s": no valid leading digits, interpreting as "0" for backwards compatibility',self::escapeString($value));
trigger_error($message,\E_USER_WARNING);
return 0;
}
while($digits_end<$str_end&&false!==strpos($ctype_space,$value[$digits_end])){
++$digits_end;
}
if($digits_end===$str_end){
goto end;
}
switch($value[$str_end-1]){
case'g':case'G':$shift=30;
break;
case'm':case'M':$shift=20;
break;
case'k':case'K':$shift=10;
break;
default:$invalid=self::escapeString($value);
$interpreted=self::escapeString(substr($value,$str,$digits_end-$str));
$chr=self::escapeString($value[$str_end-1]);
$message=\sprintf('Invalid quantity "%s": unknown multiplier "%s", interpreting as "%s" for backwards compatibility',$invalid,$chr,$interpreted
);
trigger_error($message,\E_USER_WARNING);
return$retval;
}
$factor=1<<$shift;
if(!$overflow){
if($retval>0){
$overflow=$retval>\PHP_INT_MAX/$factor;
}else{
$overflow=$retval<\PHP_INT_MIN/$factor;
}
}
if(\is_float($retval*$factor)){
$overflow=true;
$retval<<=$shift;
}else{
$retval*=$factor;
}
if($digits_end!==$str_end-1){
$message=\sprintf('Invalid quantity "%s", interpreting as "%s%s" for backwards compatibility',self::escapeString($value),self::escapeString(substr($value,$str,$digits_end-$str)),self::escapeString($value[$str_end-1]));
trigger_error($message,\E_USER_WARNING);
return$retval;
}
end:if($overflow){
$message=\sprintf('Invalid quantity "%s": value is out of range, using overflow result for backwards compatibility',self::escapeString($value));
trigger_error($message,\E_USER_WARNING);
}
return$retval;
}
private static function escapeString(string$string):string
{
$escaped='';
for($n=0,$len=\strlen($string);$n<$len;++$n){
$c=\ord($string[$n]);
if($c<32||'\\'===$string[$n]||$c>126){
switch($string[$n]){
case"\n":$escaped.='\\n';break;
case"\r":$escaped.='\\r';break;
case"\t":$escaped.='\\t';break;
case"\f":$escaped.='\\f';break;
case"\v":$escaped.='\\v';break;
case'\\':$escaped.='\\\\';break;
case"\x1B":$escaped.='\\e';break;
default:$escaped.='\\x'.strtoupper(\sprintf('%02x',$c));
}
}else{
$escaped.=$string[$n];
}
}
return$escaped;
}
}
namespace Symfony\Polyfill\Php82\Random\Engine;
use Random\RandomException;
use Symfony\Polyfill\Php82\NoDynamicProperties;
class Secure
{
use NoDynamicProperties;
function generate():string
{
try{
return random_bytes(\PHP_INT_SIZE);
}catch(\Exception$e){
throw new RandomException($e->getMessage(),$e->getCode(),$e->getPrevious());
}
}
function __sleep():array
{
throw new\Exception("Serialization of 'Random\Engine\Secure' is not allowed");
}
function __wakeup():void
{
throw new\Exception("Unserialization of 'Random\Engine\Secure' is not allowed");
}
function __clone(){
throw new\Error('Trying to clone an uncloneable object of class Random\Engine\Secure');
}
}
namespace Symfony\Polyfill\Php82;
class SensitiveParameterValue
{
private$value;
function __construct($value){
$this->value=$value;
}
function getValue(){
return$this->value;
}
function __debugInfo():array
{
return[];
}
function __sleep():array
{
throw new\Exception("Serialization of 'SensitiveParameterValue' is not allowed");
}
function __wakeup():void
{
throw new\Exception("Unserialization of 'SensitiveParameterValue' is not allowed");
}
}
