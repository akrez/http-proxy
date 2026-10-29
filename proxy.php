<?php
#20261029124335
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

use Akrez\HttpProxy\Proxy;
use GuzzleHttp\Psr7\ServerRequest;
Proxy::inlineCurl(ServerRequest::fromGlobals());