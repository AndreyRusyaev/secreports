<!-- Файл attack3.aspx -->
<% @Page Language="cs" %>
<%
Response.Write(Server.HtmlEncode(Request.QueryString["test"])); // 1) Атака через GET параметр URL
string code = Server.HtmlEncode("\xff1cscript\xff1ealert('vulnerability')\xff1c/script\xff1e"); // 2) Атака через внедрение Unicode символов
Response.Write(code);
%>
