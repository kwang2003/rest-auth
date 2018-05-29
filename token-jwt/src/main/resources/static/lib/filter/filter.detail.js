//查询
var search = function(){
	$("#filterDetailForm").attr("action","/filter_detail_list.html");
	$("#filterDetailForm").submit();
}

//导出
var exportFun = function(){
	$("#filterDetailForm").attr("action","/exportInfo.json");
	$("#filterDetailForm").submit();
}