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
        $payload['contentType'] = mime_content_type($this->file);
        $payload['size'] = filesize($this->file);
        $payload['sha256'] = hash_file("sha256",$this->file);
        $payload['sha1'] = sha1_file($this->file);
        $payload['md5'] = md5_file($this->file);
        $payload['crc32'] = hash_file("crc32",$this->file);

        $payload['iat'] = time();
        //Add publicKey if exists
        if($publicKey!=null)
            $payload['key'] = $publicKey;

        $signs = array();
        if(file_exists($this->file.'.jwt.sign')){
            $sigs = explode("\n",str_replace("\r",'',file_get_contents($this->file.'.jwt.sign')));
            foreach($sigs as $sig){
                //if same as this email, it will not be added to array
                if(strpos($sig,$this->email)===false){
                    $signs[] = $sig;
                }
            }
        }

        $jwt = JWT::encode($payload, $privateKey , 'RS256');
        $signs[] = $this->email." ".$jwt;
        file_put_contents($this->file.'.jwt.sign',implode("\n",$signs));
        return array('status'=>'success','data'=>$jwt);
    }

    /**
     * Verify digital signature file
     * @param string $payload JWT payload
     * @param string $publicKey Public Key to verify, optional if key exists in payload
     * @param string $filePath real file pat if different folder or different filename
     * @return array ['status'=>'success','data'=>''] or ['status'=>'failed','message'=>'invalid key or anything']
     */
    function verify($payload, $publicKey = null, $filePath = null){
        try{
            //get public key from payload if publicKey not provided
            if($publicKey==null){
                $temp = explode(".",$payload);
                $data = json_decode(base64_decode($temp[1]),true);
                $publicKey = $data['key'];
            }
            $res = (array) JWT::decode($payload, $publicKey, array('RS256'));
            $path = ($filePath!=null && file_exists($filePath))? $filePath : $res['file'];
            if(!file_exists($path)){
                return array('status'=>'failed','message'=>'File not found');
            }
            if(
                $res['sha256']==hash_file("sha256",$path) &&
                $res['sha1']==sha1_file($path) &&
                $res['md5']==md5_file($path) &&
                $res['crc32']==hash_file("crc32",$path)
            ){
                return array('status'=>'success','verified'=>true,'data'=>$res);
            }else{
                return array('status'=>'success','verified'=>false,'data'=>$res);
            }
        }catch(Exception $e){
            return array('status'=>'failed','message'=>$e->getMessage());
        }
    }

    /**
     * Verify digital signature file
     * @param string $payload JWT payload
     * @param string $publicKey Public Key to verify, optional if key exists in payload
     * @param string $filePath real file path if different folder or different filename
     * @return boolean true/false
     */
    function isVerified($payload, $publicKey = null, $filePath = null){
        try{
            //get public key from payload if publicKey not provided
            if($publicKey==null){
                $temp = explode(".",$payload);
                $data = json_decode(base64_decode($temp[1]),true);
                $publicKey = $data['key'];
            }
            $res = (array) JWT::decode($payload, $publicKey, array('RS256'));
            $path = ($filePath!=null && file_exists($filePath))? $filePath : $res['file'];
            if(!file_exists($path)){
                return false;
            }
            if(
                $res['sha256']==hash_file("sha256",$path) &&
                $res['sha1']==sha1_file($path) &&
                $res['md5']==md5_file($path) &&
                $res['crc32']==hash_file("crc32",$path)
            ){
                return true;
            }else{
                return false;
            }
        }catch(Exception $e){
            return false;
        }
    }
}