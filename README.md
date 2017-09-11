# vulsList
 使用這支程式抓取 [NSFOCUS](http://www.nsfocus.net/index.php?act=sec_bug) , [HKCERT](https://www.hkcert.org/security-bulletin?p_p_id=3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet&_3tech_list_security_bulletin_full_WAR_3tech_list_security_bulletin_fullportlet_cur=) , [exploit-db](https://www.exploit-db.com/) 的漏洞揭露資訊。
## 使用準備
  1. 將 settings-sample.py 改為 settings.py
  1. 填入 settings.py 相關內容並儲存
## 使用方式
  * 執行 ``` python ./this.py ``` 即可抓取 ``` settings.py ``` 中 ``` date_range_start ``` 的相對日期檔案
  * 或是 ``` python ./this.py something.xlsx ``` 則會讀取指定檔案
