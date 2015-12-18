$(document).ready(function () {
	$('#edit').click(function(){
		var pathname=window.location.pathname;
		if(pathname.substr(0,7)=="/_edit/"){
			window.location.href=pathname;
		}
		else{
			window.location.href="/_edit"+pathname;
		}
	});
});