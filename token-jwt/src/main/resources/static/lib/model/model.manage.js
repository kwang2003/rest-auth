
//添加、编辑保存
var add = function(){
	//获取填写项目
	var modelName = $("#modelName").val();
	var modelId = $("#modelId").val();
	var typeId = $("#typeId").val();
	if(modelName == null || modelName == ""){
		$("#modelName").focus();
		$("#modelNameTip").attr("style","display:block");
		return false;
	}
	
	if(modelId == null || modelId == ""){
		$("#modelId").focus();
		$("#modelIdTip").attr("style","display:block");
		return false;
	}
	
	if(typeId == null || typeId == ""){
		$("#typeId").focus();
		$("#typeIdTip").attr("style","display:block");
		return false;
	}
	for(var i = 1;i <=3;i++){
		var filterId = $("#filter"+i).val();
		if(filterId == null || filterId == ''){
			$("#filterId"+i).focus();
			$("#modelId"+i+"Tip").attr("style","display:block");
			return false;
		}
	}
	
	//提交
	$("#addModelForm").attr("action","/add_model.json");
	$("#addModelForm").attr("method","post");
	$("#addModelForm").ajaxSubmit(function(result){
		if(result.success){
			alert("编辑成功");
			window.location.href="/model_list.html";
		}else{
			alert("添加失败："+result.error);
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
		url:"/delete_model.json",
		type:"post",
		data:{
			id:$("#hiddenId").val()
		},
		success:function(result){
			if(result.success){
				alert("删除成功");
				search();
			}else{
				alert("删除失败:"+result.error);
			}
		}
	});
}

//点击分页查询
var searchByCurrentPage = function(page){
	$("#page").val(page);
	search();
}
	