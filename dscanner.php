<?php
/**
 * DScanner - A PHP Local File Scanner
 *
 * @package  DScanner
 * @version  0.0.01
 * @author   Deloz <deloz@deloz.net>
 * @link     http://deloz.net/
 */

/*
|----------------------------------------------------------------
| 使用说明
|----------------------------------------------------------------
|
| 提醒: 编辑时请使用UTF-8编码
|
*/

// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// 配置开始++++++++++++++++++++++++++++++++++++++++++++++++++++++
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-


/*
|----------------------------------------------------------------
| 需要扫描的路径:scan_path
|----------------------------------------------------------------
|
| 请使用有效的路径,如:F:\www\tool\ ,  或者 /home/www
| 如果无效,默认值是dscanner.php当前所在的目录.
| 注意: 优先使用HTML界面提交的路径.
|
*/

$scan_path = 'F:\www\tool';

/*
|----------------------------------------------------------------
| 是否DEBUG:debug
|----------------------------------------------------------------
|
| true 或者 false
|
*/

$debug = true;

/*
|----------------------------------------------------------------
| 登录用户名:
|----------------------------------------------------------------
|
*/

$user = 'admin';

/*
|----------------------------------------------------------------
| 登录密码:
|----------------------------------------------------------------
|
*/

$password = 'admin';

/*
|----------------------------------------------------------------
| 扫描深度:max_depth
|----------------------------------------------------------------
|
| 最大的扫描深度,数字,如 3层  ,   -1代表任意深度 ,  默认3层
| 层数越大,扫描越慢..
|
*/

$max_depth = 3;

/*
|----------------------------------------------------------------
| 日志存储路径:log_path
|----------------------------------------------------------------
|
| 默认为当前目录下的logs目录
|
*/

$log_path = '';

/*
|----------------------------------------------------------------
| 特征表:features函数
|----------------------------------------------------------------
|
| 有空再慢慢加上吧...
|
*/
function features() {
  return array(
    'php' => array(
      'cha88.cn大马'=>'cha88.cn',
      '51shell大马'=>'51shell',
      'ts7shell'=>'ts7',
      'shell_exec'=>'->shell_exec(',
      'phpspy特征1'=>'phpspy',
      'phpspy特征2'=>'admin = array()',
      'phpspy特征3'=>'//angel',
      '大马特征1'=>'passthru(',
      '大马特征2'=>'Scanners',
      '大马特征3'=>'cmd.php',
      '大马特征4'=>'str_rot13',
      '大马特征5'=>'webshell',
      '大马特征6'=>'大马',
      '大马特征7'=>'小马',
      '大马特征8'=>'tools88.com',
      'php加密1'=>'eval(gzinflate(',
      'php加密2'=>'eval(base64_decode(',
      'php加密3'=>'eval(gzuncompress(',
      '国外shell-1'=>'H4NN1B4L',
      '国外shell-2'=>'c99shell',
      '国外shell-1'=>'N3tshexit',
      'PHPJackal-1'=>'PHPJackal',
      'PHPJackal-2'=>'Web shell',
      'phpinfo'=>'phpinfo();',
      '批量替换'=>'替换内容',
      'php特征admin'=>'admin[',
      '威盾加密'=>')));return;?',
      'base64加密'=>'base64_decode',
      '打包马1'=>'打包下载',
      '打包马2'=>'选择要压缩的文件或目录',
     '打包马3'=>'打包程序扩展名',
     '打包马4'=>'faisunZIP',
      '一句话特征1'=>'eval($_',
      '一句话特征2'=>'eval ($_',
      '一句话特征3'=>'/e",$_POST[',
      '一句话特征3'=>'@preg_replace("/[email]/e',
      '一句话特征x'=>'<?php $_POST[',
      '一句话特征4'=>'@preg_replace("/',
      '一句话特征5'=>'"a"."s"."s"."e"."r."t";',
      '一句话特征6'=>'ts7($_POST[',
      '一句话特征7'=>'axsxxsxexrxxt',
      '一句话特征8'=>'preg_replace("//',
      '一句话特征9'=>'"ass"."ert"',
      '一句话特征10'=>'include("$file")',
      '一句话特征11'=>'preg_replace',
      '一句话特征12'=>'$_POST["',
      '一句话特征13'=>'$_GET[)',
      '一句话特征14'=>'assert',
      '一句话特征15'=>'require_once(',
      '一句话特征16'=>'system',
      '一句话特征17'=>'fputs',
      '一句话特征18'=>'file_put_contents',
      '一句话特征19'=>'str_replace(',
      '一句话特征20'=>'$_POST[]()',
      '一句话特征21'=>'error_reporting',
      '一句话特征22'=>'@preg_replace("//e"',
      '一句话特征23'=>'chr(',
      '一句话特征24'=>' str_replace',
      '一句话特征25'=>').@$_($_GET[',
      '一句话特征26'=>'passthru',
      '一句话特征27'=>'shell_exec',
      '一句话特征28'=>'popen',
      '一句话特征29'=>'touch',
      '一句话特征30'=>'proc_open',
      '一句话特征31'=>'escapeshellarg',
      '一句话特征32'=>'curl_exec',
      '一句话特征33'=>'1833596',
      '一句话特征34'=>'if (!defined("',
      '一句话特征35'=>'if($_GET[{',
      '一句话特征36'=>'"Access");',
      '一句话特征37'=>'],$_FILES[',
      '一句话特征38'=>'<script language="php',
      '一句话特征39'=>'],$_POST[',
      '一句话特征40'=>'@eval_r($_POST[',
      '一句话特征41'=>'($_POST[chr(',
      '一句话特征42'=>'@include($_POST[',
      '一句话特征43'=>'true);global',
      '一句话特征44'=>'file_get_contents(',
      '一句话特征45'=>']($_POST[',
      '一句话特征46'=>').@$_($_POST[',
      '一句话特征47'=>'0155',
      '一句话特征48'=>'chmod(',
      '一句话特征49'=>']($_REQUEST[',
      '一句话特征49'=>'php://input',
        'php小马1'=>'copy($_FILES',
      'php小马2'=>'copy ($_FILES',
      'php小马3'=>'$fp = @fopen($_POST',
      'php小马4'=>'保存成功',
      'php小马5'=>'fputs(fopen',
      'UDF提权1'=>'returns string soname',
      'UDF提权2'=>'c:\\windows\\system32',
      'UDF提权3'=>'C:\\Winnt\\udf.dll',
      'mix提权1'=>'mixdll',
      '包含后门'=>'require_once(dirname(__FILE__)',
      'php上传后门特征3'=>'move_uploaded_file ($_FILES',
    ),

  'asx' => array(
    'asp小马特征2'=>'输入马的内容',
    'asp小马特征3'=>'fso.createtextfile(path,true)',
    'asp一句话特征4'=>'<%execute(request',
    'asp一句话特征5'=>'<%eval request',
    'asp一句话特征6'=>'execute session(',
    'asp数据库后门特征7'=>'--Created!',
    'asp大马特征8'=>'WScript.Shell',
    'asp大小马特征9'=>'<%@ LANGUAGE = VBScript.Encode %>',
    'aspx大马特征10'=>'www.rootkit.net.cn',
    'aspx大马特征11'=>'Process.GetProcesses',
    'aspx大马特征12'=>'lake2',
    ),
  );
}

// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
// 配置结束++++++++++++++++++++++++++++++++++++++++++++++++++++++
// *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
/*
                                                  .~))>>
                                                 .~)>>
                                               .~))))>>>
                                             .~))>>             ___
                                           .~))>>)))>>      .-~))>>
                                         .~)))))>>       .-~))>>)>
                                       .~)))>>))))>>  .-~)>>)>
                   )                 .~))>>))))>>  .-~)))))>>)>
                ( )@@*)             //)>))))))  .-~))))>>)>
              ).@(@@               //))>>))) .-~))>>)))))>>)>
            (( @.@).              //))))) .-~)>>)))))>>)>
          ))  )@@*.@@ )          //)>))) //))))))>>))))>>)>
       ((  ((@@@.@@             |/))))) //)))))>>)))>>)>
      )) @@*. )@@ )   (\_(\-\b  |))>)) //)))>>)))))))>>)>
    (( @@@(.@(@ .    _/`-`  ~|b |>))) //)>>)))))))>>)>
     )* @@@ )@*     (@)  (@) /\b|))) //))))))>>))))>>
   (( @. )@( @ .   _/  /    /  \b)) //))>>)))))>>>_._
    )@@ (@@*)@@.  (6///6)- / ^  \b)//))))))>>)))>>   ~~-.
 ( @jgs@@. @@@.*@_ VvvvvV//  ^  \b/)>>))))>>      _.     `bb
  ((@@ @@@*.(@@ . - | o |' \ (  ^   \b)))>>        .'       b`,
   ((@@).*@@ )@ )   \^^^/  ((   ^  ~)_        \  /           b `,
     (@@. (@@ ).     `-'   (((   ^    `\ \ \ \ \|             b  `.
       (*.@*              / ((((        \| | |  \       .       b `.
                         / / (((((  \    \ /  _.-~\     Y,      b  ;
                        / / / (((((( \    \.-~   _.`" _.-~`,    b  ;
                       /   /   `(((((()    )    (((((~      `,  b  ;
                     _/  _/      `"""/   /'                  ; b   ;
                 _.-~_.-~           /  /'                _.'~bb _.'
               ((((~~              / /'              _.'~bb.--~
                                  ((((          __.-~bb.-~
                                              .'  b .~~
                                              :bb ,' 
                                              ~~~~
*/

$encoding = 'UTF-8';

define('DSCANNER_START', microtime(true));
define('ENCODING', $encoding);
define('USER', $user);
define('PASSWORD', $password);
define('MB_STRING', (int) function_exists('mb_get_info'));
!defined(__DIR__) and define('__DIR__', dirname(__FILE__));
!defined('DS') and define('DS', DIRECTORY_SEPARATOR);
header('Content-type:text/html; charset='.ENCODING);

session_start();

$scan_path = Request::get('sp') ? Request::get('sp') : (empty($scan_path) ? __DIR__ : $scan_path;

/********************************HTML START*******************/
$request_do = Request::get('do');
if ($request_do === 'logout') {
  Auth::logout();
  header('Location: dscanner.php');
  exit;
}
if (!Auth::check()) {
  if ($request_do !== 'login') {
    header('Location: dscanner.php?do=login');
    exit;
  } else {
  $request_name = Request::get('name');
  $request_password = Request::get('password');

  if ($request_do === 'login' && $request_name && $request_password) {
    if (Auth::login($request_name, $request_password)) {
      header('Location: dscanner.php');
      exit;
    } else {
      echo '<p style="color:#f50;">user or password wrong.</p>';
    }
  }
?>
  <form method="POST" action="dscanner.php?do=login">
    <p>user:<input type="text" name="name" value=""></p>
    <p>password: <input type="password" name="password" value=""></p>
    <p><input type="submit" value="login"></p>
  </form>
<?php
  exit;
  }
}
if (Request::cli()) {
  echo "\n++++++++++++++++++++WELCOME TO USE DSCANNER++++++++++++++++++++\n",
       "\n                   USEAGE:      writing....                    \n",
       "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
        ;
} elseif ($request_do === 'scan' || !$request_do) {
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>DScanner - 扫描</title></head><body>
<?php $type = Request::get('st'); ?>
<div class="actall" style="height:100px;"><form method="POST" name="tform" id="tform" action="?do=scan">

  <p>【<?php echo $_SERVER['REMOTE_ADDR'];?>】【<?php echo PHP_OS,': ',  $_SERVER["SERVER_SOFTWARE"]; ?>】&nbsp;&nbsp;&nbsp;<a href="?do=logout">退出登录</a></p>
<p>路径 <input type="text" name="sp" id="sp" value="<?php echo $scan_path; ?>" style="width:300px;"></p>
<p>扫描选项
<select name="st">
<option value="php" <?php echo showSelected('php', $type); ?>>php</option>
<option value="asx" <?php echo showSelected('asx', $type); ?>>asp+aspx</option>
<option value="txt" <?php echo showSelected('txt', $type); ?>>txt</option>
<option value="jpg" <?php echo showSelected('jpg', $type); ?>>jpg</option>
<option value="gif_bmp" <?php echo showSelected('gif_bmp', $type); ?>>gif_bmp</option>
</select>
<input type="submit" value="开始扫描" style="width:180px;"></p>
</form></div>
</body>
</html>
<?php
} 
/********************************HTML END*******************/
$is_exists_log_path =  File::exists($log_path);
if (!$is_exists_log_path || empty($log_path)) {
  $log_path = __DIR__.DS.'logs';
  if (!$is_exists_log_path && false === File::mkdir($log_path, 0777)) {
    die('无法创建日志目录: '.$log_path);
  }
}
define('LOG_STORAGE', clearSlash($log_path));

if ( ! isset($GLOBALS['dscanner']['scan_options'])) {
  $GLOBALS['dscanner']['scan_options'] = array(
    'path' => $scan_path,
    'debug' => $debug,
    'max_depth' => $max_depth,
  );
}      
Request::run();

class Scanner {
  protected static $files = array();
  protected $options = array();
  protected $path = null;
  protected $debug = false;
  protected $max_depth = 3;
  protected $file_type = null;
  protected $file_ext = null;

  public function __construct(array $options) {
    $this->options = $options;
    isset($options['debug']) and $this->debug = $options['debug'];
    isset($options['max_depth']) and $this->max_depth = $options['max_depth'];
    isset($options['file_type']) and $this->file_type = $options['file_type'];    
  }

  protected function setDebug()
  {
    if ($this->debug) {
      error_reporting(E_ALL);
    } else {
      error_reporting(0);
    }
  }

  public function run()
  {
    $this->setDebug();
    $this->setFileExt();
    $this->load();    
  }

  protected function setFileExt()
  {
    if (!$this->file_type) {
      $this->showError('请先选择文件类型');
    }
  
    $file_exts = array(
      'php' => array(
        'php',
        'inc',
        'phtml',
       ),
      'asx' => array(
        'asp',
        'asa',
        'cer',
        'aspx',
        'ascx',
       ),
      'jpg' => array(
        'jpg',
        'jpeg',
       ),
      'gif_bmp' => array(
        'bmp',
        'gif',
        'png',
       ),
      'txt' => array(
        'txt',
       ),
    );

    if (isset($file_exts[$this->file_type])) {
      $this->file_ext = $file_exts[$this->file_type];
    } else {
      $this->showError('不支持文件类型: '.$this->file_type);
    }
  }

  protected function load()
  {
    
    if (isset($this->options['path'])) {
      if (!is_string($this->options['path'])) {
        $this->showError('路径只能是字符串: '.$this->options['path'], 2);
      }
      if (!file_exists($this->options['path'])) {
        $this->showError('路径不存在: '.$this->options['path'], 1);
      }
      $this->path = clearSlash($this->options['path']).DS;      
      $this->scan();
    } else {
      $this->path = __DIR__.DS;
      $this->showError('路径没有配置: 程序自动设置为 '.$this->path, 0);
    }
  }

  protected function showResult()
  {
    print_r(self::$files);
  }

  protected function scan()
  {    
    $file_spl_objects = new RecursiveIteratorIterator(
        new RecursiveDirectoryiterator($this->path),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    $file_spl_objects->setMaxDepth($this->max_depth);

    try {      
      foreach ($file_spl_objects as $full_filename => $file_spl_object) {
        if (endsWith($full_filename, '.') || endsWith($full_filename, '..')) {
          continue;
        }
        set_time_limit(0);
        if ($file_spl_object->isFile()){
          //echo $full_filename. ' '. $file_spl_object->getPathname(). "\n\n";
          $file_name = $file_spl_object->getFilename();
          $the_file = $file_spl_object->getPath().DS.$file_name;
          if (in_array(File::extension($the_file), $this->file_ext)) {
            $this->hasVirus($the_file);
          }          
          //$file_name = $this->convert2utf8($fileinfo->getFilename());
          //self::$files[] = $fileinfo->getPath().DS.$file_name;
        } elseif ($file_spl_object->isDir()) {

        }
        flush();
        ob_flush();
      }
    } catch (Exception $ex) {
      $this->showError($ex->getMessage());
    }
  }

  protected function hasVirus($full_filename)
  {
    if (!File::exists($full_filename)) {
      $this->showError('文件不存在: '.$full_filename);
    }
    $features = features();
    $feature_type = '';
    switch ($this->file_type) {
      case 'txt':
      case 'gif_bmp':
      case 'jpg':
      case 'php':
        $feature_type = 'php';
        break;
      case 'asx':
        $feature_type = 'asx';
        break;
      default:
        $this->showError('暂未支持此类型: '.$this->file_type);
        break;
    }
    if (isset($features[$feature_type])
        && !empty($features[$feature_type])
        && is_array($features[$feature_type])) {
      $file_content = File::get($full_filename);
      foreach ($features[$feature_type] as $key => $value) {

        if (strContains($file_content, $value)) {
          if (Request::cli()) {
            echo "{$full_filename}    -   {{$key}}\n";
          } else {
            $params = http_build_query(array(
              'file' => base64_encode($full_filename),
              'virus' => base64_encode($key),
              'why' => base64_encode($value),
             ));
            $file_size = getFileSize(File::size($full_filename));
            $modified_time = date('Y-m-d H:i:s', File::modified($full_filename));
            echo '<p style="border-bottom:1px solid #ccc;background:#eee;padding:5px;margin-bottom:10px;"><a href="?do=edit&'.$params.'" target="_blank" style="text-decoration:none;">编辑&lt;&lt;</a>&nbsp;&nbsp;&nbsp;&nbsp;修改时间:'.$modified_time.'&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'.convert2utf8($full_filename).'&nbsp;&nbsp;&nbsp;&nbsp;【'.$key.'】【'.entities($value).'】&nbsp;&nbsp;&nbsp;&nbsp;文件大小:'.$file_size.'<br /></p>';
          }
          Log::file($full_filename, $key);
        }
      }
    }
  }

  protected function createThread()
  {
    if (-1 === ($child_pid = pcntl_fork())) {
      $this->showError('创建子进程失败了');
    }


  }

  protected function showError($msg, $code = 0)
  {
    if ($this->debug) {
      echo '<pre>';
      var_dump($msg);
      echo '</pre>';      
    } else {
      print_r($msg);
    }
    if ($code !== 0){
      die;
    }
  }
}

class Request {
  public static function cli()
  {
    return defined('STDIN') || (PHP_SAPI != "cgi-fcgi" && substr(PHP_SAPI, 0, 3) == 'cgi' && getenv('TERM'));
  }  
  public static function get($key, $default = null)
  {
    return isset($_GET[$key]) ? $_GET[$key] : (isset($_POST[$key]) ? $_POST[$key] : $default);
  }

  public static function run()
  {
    $do = self::get('do');
    if ($do === 'scan' && ($file_type = self::get('st'))) {
      $sanner = new Scanner($GLOBALS['dscanner']['scan_options'] + array('file_type' => $file_type));
      $sanner->run();
      //$sanner->showResult();      
    } elseif ($do === 'edit' && ($file = self::get('file'))) {
      $features = array(
        'virus' => self::get('virus'),
        'why' => self::get('why'),
      );
      $edit = new Edit($file, $features);
      $edit->run($do);
    } elseif ($do === 'save' && ($file = self::get('file'))) {
      $options = array(
        'original_encoding' => self::get('original_encoding'),
        'code' => self::get('code'),
        'virus' => self::get('virus'),
        'why' => self::get('why'),        
       );
      $edit = new Edit($file, $options);
      $edit->run($do);
    }
  }
}

class Auth {
  public static function login($user, $password)
  {
    if ($user === USER && $password === PASSWORD) {
      $_SESSION['logined'] = true;
      return true;
    } else {
      $_SESSION['logined'] = false;
      return false;
    }
  }

  public static function check()
  {
    return isset($_SESSION['logined']) && $_SESSION['logined'];
  }

  public static function logout()
  {
    session_destroy();
  }
}

class Edit {
  protected $file = null;
  protected $features = array(
    'virus' => null,
    'why' => null,
  );
  protected $original_encoding = ENCODING;
  protected $code = null;

  public function __construct($file, array $options = array())
  {
    isset($options['virus']) and $this->features['virus'] = base64_decode($options['virus']);
    isset($options['why']) and $this->features['why'] = base64_decode($options['why']);

    isset($options['original_encoding']) and $this->original_encoding = base64_decode($options['original_encoding']);
    isset($options['code']) and $this->code = $options['code'];

    if (!($this->file = base64_decode($file))) {
      $this->showError('请先选择文件: ');
    }
    if (!File::exists($this->file)) {
      $this->showError('文件不存在: '.$this->file);
    }
  }

  protected function save()
  {
    $save_success = false;
    if (!empty($this->code)) {
      $save_success = File::put($this->file, utf82original($this->code, $this->original_encoding));
    }

    if ($save_success) {
      $params = http_build_query(array(
        'file' => base64_encode($this->file),
        'virus' => base64_encode($this->features['virus']),
        'why' => base64_encode($this->features['why']),
        'do' => 'edit',
        'file' => base64_encode($this->file),
       ));      
      echo '<p>保存成功! <a href="?'.$params.'">再改一次?</a></p>';
    } else {
      $dir = dirname($this->file);
      echo '<p style="color:#f50;">保存失败! <a href="?'.$params.'">再试一次?</a></p>',
            '<p><h1>权限检测</h1></p>',      
            '目录: ', $dir, ' ', is_readable($dir) ?  '不可读' : '可读', '<br />',
            '文件: ', $this->file, ' ', is_readable($this->file) ? '不可读' : '可读', '<br />',
            '文件: ', $this->file, ' ', is_writable($this->file) ? '不可写' : '可写', '<br />';
    }
  }

  public function run($do_type)
  {
    if (method_exists($this, value($do_type))) {
      $this->$do_type();
    } else {
      $this->showError('class Edit的方法不存在: '.$do_type);
    }
  }

  protected function edit()
  {
    $file_content = File::get($this->file);
    $original_encoding = detectEncoding($file_content);    
?>

<!doctype html>
<html><head><meta charset="utf-8"><title>DScanner - 编辑文件</title><script language="JavaScript"> 
<!--  
function doZoom(size){ 
     document.getElementById('zoom').style.fontSize=size+'px' 
}


var DOM = (document.getElementById) ? 1 : 0; 
var NS4 = (document.layers) ? 1 : 0; 
var IE4 = 0; 
if (document.all) 
{ 
     IE4 = 1; 
     DOM = 0; 
}

var win = window;    
var n    = 0;

function findIt() { 
     if (document.getElementById("searchstr").value != "") 
         findInPage(document.getElementById("searchstr").value); 
}


function findInPage(str) { 
var txt, i, found;

if (str == "") 
     return false;

if (DOM) 
{ 
     win.find(str, false, true); 
     return true; 
}

if (NS4) { 
     if (!win.find(str)) 
         while(win.find(str, false, true)) 
             n++; 
     else 
         n++;

     if (n == 0) 
         alert("未找到指定内容."); 
}

if (IE4) { 
     txt = win.document.body.createTextRange();

     for (i = 0; i <= n && (found = txt.findText(str)) != false; i++) { 
         txt.moveStart("character", 1); 
         txt.moveEnd("textedit"); 
     }

if (found) { 
     txt.moveStart("character", -1); 
     txt.findText(str); 
     txt.select();
     txt.scrollIntoView(); 
     n++; 
} 
else { 
     if (n > 0) { 
         n = 0; 
         findInPage(str); 
     } 
     else 
         alert("未找到指定内容."); 
     } 
}

return false; 
} 
// --> 
</script>
</head><body>
<div class="actall"><form method="POST" name="tform" id="tform" action="?do=save">
<input name="file" type="hidden" value="<?php echo base64_encode($this->file); ?>" />
<input name="why" type="hidden" value="<?php echo base64_encode($this->features['why']); ?>" />
<input name="virus" type="hidden" value="<?php echo base64_encode($this->features['virus']); ?>" />
<input name="original_encoding" type="hidden" value="<?php echo base64_encode($original_encoding); ?>" />
<p style="color:rgb(211, 21, 21);">文件: <?php echo convert2utf8($this->file); ?></p>
<p style="color:rgb(235, 235, 13);font-weight:bold;">原因: <?php echo $this->features['virus']; ?>&nbsp;&nbsp;&nbsp;&nbsp;病毒: <?php echo entities($this->features['why']); ?><input type="text" id="searchstr" name="searchstr" class="textbox" value="<?php echo entities($this->features['why']); ?>" size="10"> 
<input type="button" value="页内查找" onclick="javascript:findIt();" class="sbttn"> </p>
<p style="color:#cdc;">上次修改时间:<?php  echo date('Y-m-d H:i:s', File::modified($this->file)); ?></p>
<p style="color:rgb(11, 196, 26);">原编码: <?php echo $original_encoding; ?></p>
<p><input type="submit" name="save" value="保存" />&nbsp;&nbsp;&nbsp;&nbsp;<a href="javascript:window.close()">取消编辑</a></p>
<p><textarea style="width:100%;" name="code" rows="100"><?php echo entities(convert2utf8($file_content)); ?></textarea></p>
</form></div>
</body>
</html>

<?php
  }

  protected function showError($msg)
  {
    die($msg);
  }
}

class File {
  public static function extension($path)
  {
    return pathinfo($path, PATHINFO_EXTENSION);
  }

  public static function size($path)
  {
    return filesize($path);
  }

  public static function modified($path)
  {
    return filemtime($path);
  }

  public static function type($path)
  {
    return filetype($path);
  }      

  public static function mkdir($path, $chmod = 0777)
  {
    return ( ! is_dir($path)) ? mkdir($path, $chmod, true) : true;
  } 

  public static function latest($directory, $skip_dots = true)
  {
    $latest = null;
    $time = 0;

    $items = new DirectoryIterator($directory);

    foreach ($items as $item) {
      if ($item->isDot() && $skip_dots) {
        continue;
      } 
      if ($item->getMTime() > $time) {
        $latest = $item;
        $time = $item->getMTime();
      }
    }

    return $latest;
  } 

  public static function append($path, $data)
  {
    return file_put_contents($path, $data, LOCK_EX | FILE_APPEND);
  } 

  public static function put($path, $data)
  {
    return file_put_contents($path, $data, LOCK_EX);
  }

  public static function get($path, $default = null)
  {
    return (file_exists($path)) ? file_get_contents($path) : value($default);
  }

  public static function exists($path)
  {
    return file_exists($path);
  }         
}

class Log {
  /**
   * 写一行.
   *
   * <code>
   *    // 写一个目录 "directory" 
   *    Log::write('directory', 'f:\www\log', '大马特征7');
   *    Log::directory('f:\www\log', '大马特征7');
   *  
   *    // 写一个文件 "file"
   *    Log::write('file', 'f:\www\qq.png', '大马特征7');
   *    Log::file('f:\www\qq.png', '大马特征7');
   *
   *         
   *    最终文件显示的格式是:  文件名是当前日期 + .log, 如2013-04-27.log
   *    2013-04-27 01:01:01 2013-04-27 01:01:01 FILE F:\www\www\qqq.png 大马特征7
   *    2013-04-27 10:10:10 2013-04-27 10:10:10 DIRECTORY F:\www\ddd\directory php特征admin
   * </code>
   *
   */

  public static function write($type, $content, $virus)
  {
    File::append(LOG_STORAGE.DS.date('Y-m-d').'.log', self::format($type, $content, $virus));
  }

  protected static function format($type, $content, $virus)
  {
    $str = convert2utf8($content);
    return date('Y-m-d H:i:s').' '.date('Y-m-d H:i:s', File::modified($content)).' '.upper($type)." {$str} {$virus}".PHP_EOL;
  }

  public static function directory($content, $virus)
  {
    self::write('directory', $content, $virus);
  }

  public static function file($content, $virus)
  {
    self::write('file', $content, $virus);
  }
}

function getFileSize($size) {
  $units = array('Bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB');
  return @round($size / pow(1024, ($i = floor(log($size, 1024)))), 2).' '.$units[$i];
}
function detectEncoding($str) {
    return mb_detect_encoding($str, array('UTF-8', 'CP936', 'BIG-5'));
}

function convert2utf8($str) {
    if ('UTF-8' !== ($original_encoding = detectEncoding($str))) {
      return mb_convert_encoding($str, 'UTF-8', $original_encoding);
    }
    return $str;
}

function entities($value) {
  return htmlentities($value, ENT_QUOTES, ENCODING, false);
}

function decode($value) {
  return html_entity_decode($value, ENT_QUOTES, ENCODING);
}

function utf82original($str, $original_encoding) {
    return mb_convert_encoding($str, $original_encoding, 'UTF-8');
}

function clearSlash($str) {
  return rtrim(rtrim($str, '/'), "\\");
}

function upper($value) {
  return (MB_STRING) ? mb_strtoupper($value, ENCODING) : strtoupper($value);
}

function endsWith($haystack, $needle) {
  return $needle == substr($haystack, strlen($haystack) - strlen($needle));
}

function startWith($haystack, $needle) {
  return strpos($haystack, $needle) === 0;
}

function value($value) {
  return (is_callable($value) and ! is_string($value)) ? call_user_func($value) : $value;
}

function showSelected($need, $do_type) {
  return $do_type === $need ? ' selected = selected ' : '';
}

function strContains($haystack, $needle) {
  foreach ((array) $needle as $n) {
    if (strpos($haystack, $n) !== false) return true;
  }

  return false;
}

echo "\nrunning time: ", number_format((microtime(true) - DSCANNER_START), 2), 's';