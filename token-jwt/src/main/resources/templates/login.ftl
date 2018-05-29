<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Bootstrap Admin</title>
    <meta content="IE=edge,chrome=1" http-equiv="X-UA-Compatible">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="stylesheet" type="text/css" href="lib/bootstrap/css/bootstrap.css">
    <link rel="stylesheet" href="lib/font-awesome/css/font-awesome.css">
    <script src="lib/jquery-1.11.1.min.js" type="text/javascript"></script>
    <link rel="stylesheet" type="text/css" href="stylesheets/theme.css">
    <link rel="stylesheet" type="text/css" href="stylesheets/premium.css">
	<link rel="stylesheet" type="text/css" href="lib/css/login.css">
</head>
<body class=" theme-blue">
	<!-- Le HTML5 shim, for IE6-8 support of HTML5 elements -->
	<!--[if lt IE 9]>
	  <script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>
	<![endif]-->

  <!--[if lt IE 7 ]> <body class="ie ie6"> <![endif]-->
  <!--[if IE 7 ]> <body class="ie ie7 "> <![endif]-->
  <!--[if IE 8 ]> <body class="ie ie8 "> <![endif]-->
  <!--[if IE 9 ]> <body class="ie ie9 "> <![endif]-->
  <!--[if (gt IE 9)|!(IE)]><!--> 
   
  <!--<![endif]-->

<div class="navbar navbar-default" role="navigation">
    <div class="navbar-header">
      <span class="navbar-brand">欢迎使用XXX系统</span>
     </div>
</div>

<div class="dialog">
    <div class="panel panel-default">
        <p class="panel-heading no-collapse">快速登录XXX系统</p>
        <div class="panel-body">
            <form method="post" action="/login.do">
                <div class="form-group item">
                    <label class="input-tips">用户名:</label>
                    <div class="inputOuter">
                    	<input type="text" name="loginId" class="form-control span12">
                    </div>
                </div>
                <div class="form-group item">
                	<label class="input-tips">密<span class="space"></span>码：</label>
                	<div class="inputOuter">
                    	<input type="password" name="password" class="form-control span12">
                    </div>
                </div>        
                <#if error??>
            		<div class="f_checktip f_wrong">${error}</div>
   				</#if>   				
                <input type="submit" class="btn btn-primary pull-right" value="登录"/>
                
                <!--<label class="remember-me"><input type="checkbox"> 记住我</label>-->
                <div class="clearfix"></div>
            </form>
        </div>
    </div>
</div>
<script src="lib/bootstrap/js/bootstrap.js"></script>
</body>
</html>
