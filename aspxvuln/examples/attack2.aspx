<!-- Web-страница attack2.aspx -->
<% @Page Language="cs" validateRequest="true" %>
<%
Response.Write(Request.QueryString["test"]); // Атака через параметр URL
%>
