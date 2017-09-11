#python 2
#setting it and save as setting.py in the seme dir of crawler.py
class settings:
    sTime = 0 #每爬一個站 delay 多久
    path = '.' #預設資料夾(relative patht supported)
    date_range_start = 2 #起算日期(從今日算起幾天前)
    date_range_end = 1 #結算日期(從今日算起幾天前)
    http_try_limit = 3 #每個頁面最多試幾次
    
    # vvvvvvvvvv mail config vvvvvvvvvv
    send_from = "foo@bar.bizz" 
    send_to = "foo@bar.bizz" 
    subject = "vlusList" 
    text = '''
        crawling time :{crawl_time}
        range : {begin} ~ {end}
        FYI
        
        who cares about your vulnerability
    '''
    server = "mx.bar.bizz"
    port = 465
    username = "foo@bar.bizz"
    password = 'Passw0rd'
    # ^^^^^^^^^^ mail config ^^^^^^^^^^