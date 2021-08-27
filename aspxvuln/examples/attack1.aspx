<!-- Web-страница attack1.aspx -->
<% @Page Language="cs" %>
<%
Response.Write(Request.QueryString["test"]); // Атака через параметр URL
%>
