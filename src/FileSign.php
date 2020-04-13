<?php
namespace ibnux;

use \Firebase\JWT\JWT;
use \Exception;

/**
 * Digital Signature file using JSON Web Token implementation
 *
 * PHP version 5
 *
 * @author   Ibnu Maksum <me@ibnux.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/ibnux/filesign
 */

class FileSign {
    private $file = null;
    private $name = null, $email = null, $company = null, $note = null;
    private $country = null, $state = null, $city = null;

    /**
     * choose which file to sign, full path or relative
     * @param string $file path to file or null
     */
    function __construct($file=null) {
        $this->file = $file;
    }

    /**
     * Set location info
     * @param string $country full country name
     * @param string $state full state name
     * @param string $city full city name
     */
    function setLocation($country, $state, $city){
        $this->country = $country;
        $this->state = $state;
        $this->city = $city;
    }

    /**
     * Set location info
     * @param string $name full name who sign file
     * @param string $email Company or personal email mandatory
     * @param string $company full company name
     */
    function setUserInfo($name, $email, $company){
        $this->name = $name;
        $this->email = $email;
        $this->company = $company;
    }

    /**
     * Set note
     * @param note note about signing
     */
    function setNote($note){
        $this->note = $note;
    }

    /**
     * Add digital Signature to file
     * it will create new file beside real file
     * @param string/array $privateKey String|array if using password, use array [key,password]
     * @param string $publicKey Optional String it will be added to payload if exists
     * @return array ['status'=>'success','data'=>''] or ['status'=>'failed','message'=>'invalid key or anything']
     */
    function sign($privateKey, $publicKey=null){
        if(!file_exists($this->file)){
            return array('status'=>'failed','message'=>'File not found');
        }
        if(!empty($this->email)){
            return array('status'=>'failed','message'=>'Email mandatory');
        }
        $payload = array();

        // add if exists
        if(!empty($this->name)) $payload['name'] = $this->name;
        if(!empty($this->email)) $payload['email'] = $this->email;
        if(!empty($this->company)) $payload['company'] = $this->company;
        if(!empty($this->country)) $payload['country'] = $this->country;
        if(!empty($this->state)) $payload['state'] = $this->state;
        if(!empty($this->city)) $payload['city'] = $this->city;
        if(!empty($this->note)) $payload['note'] = $this->note;

        $payload['file'] = basename($this->file);
        $payload['content_type'] = mime_content_type($this->file);
        $payload['size'] = filesize($this->file);
        $payload['sha256'] = hash_file("sha256",$this->file);
        $payload['sha1'] = sha1_file($this->file);
        $payload['md5'] = md5_file($this->file);

        $payload['iat'] = time();
        //Add publicKey if exists
        if($publicKey!=null){
            $payload['key'] = $publicKey;
            $payload['key_sha1'] = sha1($publicKey);
        }
        $signs = array();
        if(file_exists($this->file.'.jwt.sign')){
            $sigs = explode("\n",str_replace("\r",'',file_get_contents($this->file.'.jwt.sign')));
            foreach($sigs as $sig){
                //if same as this email, it will not be added to array
                if(strpos($sig,$this->email)===false && !empty(trim($sig))){
                    $signs[] = $sig;
                }
            }
        }

        try{
            $jwt = JWT::encode($payload, $privateKey , 'RS256');
            $signs[] = $this->email." ".$jwt;
            file_put_contents($this->file.'.jwt.sign',implode("\n",$signs));
            return array('status'=>'success','data'=>$jwt);
        }catch(Exception $e){
            return array('status'=>'failed','message'=>$e->getMessage());
        }
    }

    /**
     * Verify digital signature file
     * @param string $filePath real file path if different folder or different filename
     * @param array $publicKeys array by email ['me@ibnux.net'=>'adasdasdsd'] Public Key to verify, optional if key exists in payload
     * @param string $fileSign path to digital signature if has different name or string sign
     * @return array ['status'=>'success','data'=>''] or ['status'=>'failed','message'=>'invalid key or anything']
     */
    function verify($filePath, $publicKeys = array(), $fileSign = null){
        $payload = "";
        if($fileSign!=null){
            if(file_exists($fileSign))
                $payload = file_get_contents($fileSign);
            else{
                // if not file then it is a payload
                $payload = $fileSign;
            }
        }else{
            $payload = file_get_contents($filePath.'.jwt.sign');
        }

        if($publicKeys==null)
            $publicKeys = array();

        $result = array();
        $signs = explode("\n",str_replace("\r",'',$payload));
        foreach($signs as $temp){
            //sign array 0 is email 1 is jwt
            $sign = explode(" ",$temp);
            //if it email then process
            if (filter_var($sign[0], FILTER_VALIDATE_EMAIL)) {
                //get public key from payload if publicKeys not provided
                if(isset($publicKeys[$sign[0]])){
                    $tmp = explode(".",$sign[1]);
                    $data = json_decode(base64_decode($tmp[1]),true);
                    $publicKey = $data['key'];
                }else{
                    $publicKey = $publicKeys[$sign[0]];
                }
                try{
                    $res = (array) JWT::decode($sign[1], $publicKey, array('RS256'));
                    foreach($res as $k => $v){
                        $result[$sign[0]][$k] = $v;
                    }
                    $path = ($filePath!=null && file_exists($filePath))? $filePath : $res['file'];
                    if(!file_exists($path)){
                        $result[$sign[0]]['verified'] = false;
                        $result[$sign[0]]['error'] = 'File not found';
                    }else{
                        $result[$sign[0]]['sha256_verified'] = ($res['sha256']==hash_file("sha256",$path));
                        $result[$sign[0]]['sha1_verified'] = ($res['sha1']==sha1_file($path));
                        $result[$sign[0]]['md5_verified'] = ($res['md5']==md5_file($path));
                        if($result[$sign[0]]['sha256_verified'] && $result[$sign[0]]['sha1_verified'] && 
                            $result[$sign[0]]['md5_verified']){
                            $result[$sign[0]]['verified'] = true;
                        }else{
                            $result[$sign[0]]['verified'] = false;
                        }
                    }
                }catch(Exception $e){
                    $result[$sign[0]]['verified'] = false;
                    $result[$sign[0]]['error'] = 'File not found';
                }
            }
        }
        return $result;
    }

    /**
     * Verify digital signature file
     * @param string $filePath real file path if different folder or different filename
     * @param string $publicKeys array by email ['me@ibnux.net'=>'adasdasdsd'] Public Key to verify, optional if key exists in payload
     * @param string $fileSign path to digital signature if has different name
     * @return boolean true/false
     */
    function isVerified($filePath, $publicKeys = array(), $fileSign = null){
        $result = $this->verify($filePath, $publicKeys, $fileSign);

        if(count($result)==0){
            return false;
        }

        foreach($result as $sign)
            if(!$sign['verified'])
                return false;

        return true;
    }
}