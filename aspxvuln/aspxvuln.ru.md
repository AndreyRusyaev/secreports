# XSS уязвимость в ASP.Net

Андрей Русяев, аспирант кафедры защиты информации ДВГУ, Владивосток, [andir@it-project.ru](mailto:andir@it-project.ru).

9 февраля 2005 года, обновлена 14 февраля 2005 года.

### Аннотация

При определённых условиях возможно проведение кросс-сайт скриптинг атаки (XSS) [1] на сайт находящийся под управлением ASP.Net, из-за неправильной фильтрации специальных символов HTML. Атака эксплуатирует уязвимость механизма преобразования Unicode строк [2] обрабатываемых .NetFramework при выводе их в национальной кодировке ASCII на ASP.NetWeb-страницу. Основная проблема возникает из-за отсутствия фильтрации специальных символов HTML в диапазоне U+ff00-U+ff60 (широкие символы ASCII) [3].

### Введение

Проблема была обнаружена и исследована в августе 2004 года. Опасности подвержены все версии .NetFramework, которые существуют на данный момент:

1. .NetFramework, версия 1.0,
2. .Net Framework, версия 1.0 + service pack 1,
3. .Net Framework, версия 1.0 + service pack 2,
4. .NetFramework, версия 1.1,
5. .Net Framework, версия 1.1 + service pack 1,
6. .Net Framework, версия 1.1 + service pack 1 + Security Bulletin MS05-004 от 8 февраля 2005 года.

После дополнительных проверок было выяснено, что свободная реализация .NetFramework, которая называется Mono [4], также уязвима:

1. Mono, версия 1.0.5.

_Замечание: Остальные версии_ _Mono_ _протестированы не были._

### Предварительные сведения

Платформа .NetFramework работает только с Unicode строками. При вводе/выводе возможно преобразование из/в различные национальные кодовые страницы ASCII. В частности, при использовании технологии ASP.Net вывод на страницу может осуществляться в национальных кодировках, для этого осуществляется преобразование использующихся строк в требуемую кодировку. При этом символы Unicode из диапазона широких символов ASCII (U+ff00-U+ff60) преобразуются в обычные ASCII символы, в частности, среди этих символов присутствуют и специальные символы HTML (&#39;<&#39;, &#39;>&#39; и другие), с помощью которых может быть произведено внедрение вредоносного HTML кода или вредоносного скрипта (с помощью тега \<script>), также возможны и другие варианты (подробнее можно обратиться к [5]).

### Описание уязвимости

Обнаружено отсутствие фильтрации механизмами ASP.Net специальных символов HTML (таких как &#39;<&#39;, &#39;>&#39; и других) в Unicode строках в диапазоне символов U+ff00-U+ff60 (широкие символы ASCII) при выводе в национальных кодировках.

1. Возможно внедрение специальных HTML символов в Web-страницу, обрабатываемую ASP.Net при помощи широких символов ASCII из таблицы символов Unicode.

Пример:

    http://server.com/attack1.aspx?test=%uff1cscript%uff1ealert(&#39;vulnerability&#39;)%uff1c/script%uff1e

На уязвимой web-странице _&#39; __attack__ 1. __aspx__&#39;_ производится вывод на страницу параметра _&#39; __test__&#39;_, полученного из HTTP запроса.

Страница может выглядить следующим образом:
```csharp
    <!-- Web-страница attack1.aspx -->
    <% @Page Language="cs" %>
    <%
    Response.Write(Request.QueryString["test"]); // Атака через параметр URL
    %>
```

Конфигурационный файл _Web __.__ config_ для сервера _server __.__ com_ может выглядеть так:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="windows-1251"** />
        </system.web>
    </configuration>
```

1. Обход механизма защиты чувствительных данных объекта HttpRequest для ASP.Net (ValidationRequest).

Механизм защиты чувствительных данных объекта HttpRequest для ASP.Net не проверяет Unicode символы из диапазона U+ff00-U+ff60. И поэтому внедрение специальных символов HTML в код web-страницы не обнаруживается.

Пример:

    http://server.com/attack2.aspx?test=%uff1cscript%uff1ealert(&#39;vulnerability&#39;)%uff1c/script%uff1e

На уязвимой web-странице _&#39; __attack__ 2. __aspx__&#39;_ производится вывод на страницу параметра _&#39; __test__&#39;_, полученного из HTTP запроса.

Страница может выглядить следующим образом:
```csharp
    <!-- Web-страница attack2.aspx -->
    <% @Page Language="cs" **validateRequest="true"** %>
    <%
    Response.Write(Request.QueryString["test"]); // Атака через параметр URL
    %>
```

Конфигурационный файл _Web __.__ config_ для сервера _server __.__ com_ может выглядеть так:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="windows-1251"** />
        </system.web>
    </configuration>
```xml

_Примечание: Механизм защиты чувствительных данных запроса ( __Validation__ Request__) и атрибут_ _Web__-страницы validateRequest доступен, только для ASP.Net версии 1.1 и выше, или для Mono (сведений о поддерживающих версиях не имеется) [6]._

1. Обход механизма кодирования чувствительных символов HTML в их безопасные эквиваленты.

_Замечание: Эта атака не применима для_ _ASP __.__ Net_ _из реализации_ _Mono__._

HttpServerUtility.HtmlEncode пропускает Unicode символы из диапазона U+ff00-U+ff60.

Функция перевода чувствительных символов HTML в их безопасные эквиваленты, не защищает от, приведённых в примерах выше, атак. Обработка HttpServerUtility.HtmlEncode производиться до перевода строки в национальную кодировку, поэтому можно воспользоваться широкими символами ASCII для внедрения вредоносного кода на Web-страницу.

Пример:

    http://server.com/attack3.aspx?test=%uff1cscript%uff1ealert(&#39;vulnerability&#39;)%uff1c/script%uff1e

На уязвимой web-странице _&#39; __attack3.aspx__&#39;_ производится:

1. вывод на страницу параметра _&#39; __test__&#39;_, полученного из HTTP запроса_,_
2. вывод на страницу некоторой строки с внедрёнными символами Unicode.

Страница может выглядить следующим образом:
```csharp
    <!-- Web-страница attack3.aspx -->
    <% @Page Language="cs" %>
    <%
    Response.Write(Server.HtmlEncode(Request.QueryString["test"])); // 1) Атака через параметр URL

    string code = Server.HtmlEncode("\xff1cscript\xff1ealert(&#39;vulnerability&#39;)\xff1c/script\xff1e"); 2) Атака через внедрение Unicode символов

    Response.Write(code);
    %>
```

Конфигурационный файл _Web.config_для сервера_server.com_:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="windows-1251"** />
        </system.web>
    </configuration>
```

Все три атаки имеют общие корни. Если, каким-либо образом, в строку будут внедрены Unicode символы из диапазона U+ff00-U+ff60, то они будут пропущены в обход механизмов обнаружения и фильтрации чувствительных данных, и, в частности, методы преобразования специальных символов HTML в их безопасные эквиваленты, свободно пропустят широкие ASCII символы, благодаря тому, что они применяются до осуществления перевода строк в национальную кодовую страницу.

### Методы защиты

Вариантов защиты от возможных атак может быть предложено несколько:

1. Не использовать национальные кодировки при выводе на ASP.Net страницы, для этого следует указать в конфигурационном файле Web-приложения, чтобы для вывода использовался Unicode:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="utf-8"** />
        </system.web>
    </configuration>
```

1. В случае необходимости использования национальных кодировок, проверять данные поступающие от недоверенного источника (пользователь, приложения, компоненты и др.) на присутствие символов из диапазона широких символов ASCII (U+ff00-U+ff60) и в случае обнаружения, фильтровать их.

### Дополнительная информация

О проблеме было сообщено в MicrosoftSecurityResponseCenter (2 августа 2004 года) и получен ответ о том, что описание уязвимости помещено в case 5438. Немного позднее был получен следующий ответ:

"_We have decided that a KB article and update to tools and/or best practice guidelines should be done for this, and will be as time permits. We are not tracking this case as a security bulletin"._

На текущий момент (09 февраля 2005) проблема не была разрешена и уязвимость до сих пор присутствует.

### Литература

1. CERT® Advisory CA-2000-02 Malicious HTML Tags Embedded in Client Web Requests, [http://www.cert.org/advisories/CA-2000-02.html](http://www.cert.org/advisories/CA-2000-02.html)
2. Unicode Home Page, [http://unicode.org/](http://unicode.org/)
3. Unicode.org, Halfwidth and Fullwidth Forms, [http://www.unicode.org/charts/PDF/UFF00.pdf](http://www.unicode.org/charts/PDF/UFF00.pdf).
4. Mono Project, [http://mono-project.com/](http://mono-project.com/)
5. CGISecurity.com, "The Cross Site Scripting FAQ.", Май 2002, http://www.cgisecurity.com/articles/xss-faq.shtml
6. .Net Framework SDK, @Page directive, ValidateRequest attribute, [http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconPage.asp](http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconPage.asp)