$(function(){
	
	//获取滤芯列表页面的查询条件
	var q_Condition = $("#hiddenCondition").val();	
	if(q_Condition != null && q_Condition != ""){
		$(".form-control").val(q_Condition);
	}
});

//查询
var search = function(){
	$("#filterManageForm").attr("action","/filter_list.html");
	$("#filterManageForm").attr("method","POST");
	$(".form-control").attr("name","name");
	$("#filterManageForm").submit();	
}

//编辑
var edit = function(id){
	$("#filterManageForm").attr("action","/edit_filter.html");
	$("#filterManageForm").attr("method","POST");
	$(".form-control").val(id);
	$(".form-control").attr("name","id");
	$("#filterManageForm").submit();	
}

//添加、编辑保存
var save = function(){
	//获取填写项目
	var filterName = $("#filterName").val();
	var shortName = $("#shortName").val();
	var description = $("#description").val();
	var lifetime = $("#lifetime").val();
	var propertyCode = $("#propertyCode").val();
	
	if(filterName == null || filterName == ""){
		$("#filterName").focus();
		$("#filterNameTip").attr("style","display:block");
		return false;
	}
	
	if(shortName == null || shortName == ""){
		$("#shortName").focus();
		$("#shortNameTip").attr("style","display:block");
		return false;
	}
	
	if(propertyCode == null || propertyCode == ""){
		$("#propertyCode").focus();
		$("#propertyCodeTip").attr("style","display:block");
		return false;
	}
	
	if(description == null || description == ""){
		$("#description").focus();
		$("#descriptionTip").attr("style","display:block");
		return false;
	}
	
	if(lifetime == null || lifetime == ""){
		$("#lifetime").focus();
		$("#lifetimeTip").attr("style","display:block");
		return false;
	}else{
		if(isNaN(lifetime)){
			$("#lifetime").focus();
			$("#lifetimeTip2").attr("style","display:block");
			return false;
		}
	}
	
	//提交
	$("#edit_filterInfoForm").attr("action","/save_filter.json");
	$("#edit_filterInfoForm").attr("method","post");
	$("#edit_filterInfoForm").ajaxSubmit(function(result){
		if(result.result == 1){
			alert("编辑成功");
			window.location.href="/filter_list.html";
		}else{
			alert("编辑失败，请检查输入项是否正确！");
		}
	});
}


//删除---弹窗
var deleteDialogFun = function(id){
	$("#hiddenId").val(id);
	$("#myModal").modal();
}

//删除
var deleteFun = function(){
	$.ajax({
		url:"/delete_filter.json",
		type:"post",
		data:{
			id:$("#hiddenId").val()
		},
		success:function(result){
			var jsonResult = JSON.parse(result);
			if(jsonResult.result == 1){
				alert("删除成功");
				search();
			}else{
				alert("删除失败");
			}
		}
	});
}

//点击分页查询
var searchByCurrentPage = function(page){
	$("#page").val(page);
	search();
}
	