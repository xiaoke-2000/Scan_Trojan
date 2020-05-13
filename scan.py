# python根据pid寻找端口
import psutil
import win32api
import win32con
import datetime
import time
import os
import wmi
import platform

pids=[] #常见PID
flag=0#不存在异常
#################端口扫描################
def netpidport(pid: int):
    """根据pid寻找该进程对应的端口"""
    alist = []
    # 获取当前的网络连接信息
    net_con = psutil.net_connections()
    for con_info in net_con:
        if con_info.pid == pid:
            alist.append({pid:con_info.laddr.port})
    return alist


def netportpid(port: int):
    """根据端口寻找该进程对应的pid"""
    adict = {}
    # 获取当前的网络连接信息
    net_con = psutil.net_connections()
    for con_info in net_con:
        if con_info.laddr.port == port:
            adict[port] = con_info.pid
    return adict
def dealwrong(p):
    #判断异常端
    for i in range(len(pids)):
        if p == pids[i]:
            return True
    return False
            

def scanport(count):
    dicts = {'port':'','pid':''}
    for i in range(0,8000):#查询开放端口号的范围
        dicts=netportpid(i)
        if dicts:
            p = psutil.Process(dicts[i])#获取进程名
            print('端口号:{:5s}   PID:{:5s}   进程名:{}'.format(str(i),str(dicts[i]),p.name()))
            if count == 0:
                pids.append(dicts[i])
            else:
                if not dealwrong(dicts[i]):#存在异常进程
                    flag=1
                    print("存在异常!!!\n 异常pid:{} 进程名:{}".format(dicts[i],p.name()))
                
def scan():
    for i in range(2):#扫描次数
        print('-------第{}次扫描---------'.format(i+1))
        nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')#现在的时间
        print(nowTime)
        scanport(i)
        print('\n')

#################启动文件夹扫描################
        
#本主机启动文件夹为:
#C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
#开启文件扫描
def get_file(fpath, level=0, mfile_list=None):
    if mfile_list == None:
        mfile_list = []
##列出指定根目录下的所有文件和文件夹
    parent = os.listdir(fpath)
    for child in parent:
        child_path = os.path.join(fpath, child)
        if os.path.isdir(child_path):
            for i in range(level):
                print("----", end = "")
            print(child)               
            get_file(child_path, level+1)
        else:  
            for i in range(level):
                print("----", end = "")
            mfile_list.append(child)
            print(child)
    return mfile_list
#记录扫描文件日志
def savelist(lists,time):
    f = open('Startuplist.txt', 'a')
    f.write(str(lists)+'\n'+time+'\n')
    f.close()
    
#分析启动文件夹
def deallist(starlist,nowlist):
    startset = set(starlist) # 将列表转换成集合
    endset = set(nowlist)
    sets=startset ^ endset  #判断新出现的可疑文件
    if sets: #输出异常开机启动文件
        flag=1
        print("异常文件：{}".format(sets))
    else:
        print("<------无异常------>")
    
def scanlist():
    path = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
    startlist=get_file(path)
    if os.path.isdir(path):
        for i in range(10): #设置扫描次数 也可以无限循环扫描
            nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')#现在的时间
            print(nowTime)
            nowlist=get_file(path)
            savelist(nowlist,nowTime)#保存至日志文件
            deallist(startlist,nowlist)#保存至日志文件
            time.sleep(1)  #每1秒扫描一次
    else:
        print("路径有误!")
        
        
#################注册表扫描################
    
def scanRegistry():   
    # 打开项
    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software',0, win32con.KEY_ALL_ACCESS)
    print(key)
    chuan="新项 #"
    lenchuan=len(chuan)
    # RegQueryInfoKey函数查询项的基本信息
    print(win32api.RegQueryInfoKey(key))   # 返回项的子项数目、项值数目，以及最后一次修改时间
    keysb1=(win32api.RegQueryInfoKey(key))[0] 
    #result = False
    nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')#现在的时间
    print(nowTime)
    print ("注册表中共有",keysb1,"个子项")
    #print(win32api.RegEnumKey(key,0))
    for i in range(keysb1,0,-1):
    	#若不进行try操作，如果test不存在的话会有异常
    	try:
    		if win32api.RegEnumKey(key,i-1) != '123465':
    			print("第",i,"个子项，名称：",win32api.RegEnumKey(key,i-1),end="")
    			if (win32api.RegEnumKey(key,i-1)[0:lenchuan]) == chuan:
    				print ("此项为异常子项!!",end="")
    				#win32api.RegDeleteKey(key,win32api.RegEnumKey(key,i-1))  #可以选择删除异常项
    			print ()
    			pass
    		else:
    			#result = True
    			break
    	except:
    		pass 
    keysb1=(win32api.RegQueryInfoKey(key))[0] 

#################服务列表扫描################
def sys_version():
    c = wmi.WMI ()
    #获取操作系统版本
    for sys in c.Win32_OperatingSystem():
        print("Version:%s" % sys.Caption,"Vernum:%s" % sys.BuildNumber)
        print(sys.OSArchitecture)#系统是32位还是64位的
        print(sys.NumberOfProcesses) #当前系统运行的进程总数

def network():
    print(platform.platform())
    c = wmi.WMI ()
    #获取MAC和IP地址
    '''for interface in c.Win32_NetworkAdapterConfiguration (IPEnabled=1):
        print("MAC: {}".format(interface.MACAddress))
    for ip_address in interface.IPAddress:
        print("ip_add: {}".format(ip_address))
    #获取自启动程序的位置
    for s in c.Win32_StartupCommand ():
        print("[%s] %s <%s>" % (s.Location, s.Caption, s.Command))
    #获取当前运行的进程
    for process in c.Win32_Process ():
        print(process.ProcessId, process.Name)'''
    #获取当前遍历服务
    count=0
    for service in c.Win32_Service ():
        count=count+1
        print("服务ID:{:6}   服务名:{}" .format(service.ProcessId, service.Name))
    print("-----------服务总数为:{}-------------".format(count))
    

#菜单函数
def menu():
    print("----欢迎使用木马扫描v1.0----\n")
    print("0.全局扫描\n")
    print("1.扫描检测启动文件夹\n")
    print("2.扫描检测注册表信息\n")
    print("3.扫描检测服务列表\n")
    print("4.扫描检测端口开放情况\n")
    print("5.退出系统\n")
    choose=int(input("请输入您的选择："))
    return choose

if __name__ == '__main__':
    while True:
        flag=0
        choose=menu()
        if choose == 1:
            scanlist()
        elif choose == 2:
            scanRegistry()
        elif choose == 3:
            network()
        elif choose == 4:
            scan()
        elif choose == 0:
            print("--------开始全局扫描-------\n")
            scanlist()
            scanRegistry()
            network()
            scan()
        elif choose == 5:
            print("----感谢使用木马扫描v1.0----\n")
            exit(0)
        else:
            print("输入有误 请重新输入")
        if flag==1:
            print("---此次扫描发生异常---")
        else:
            print("---此次扫描无异常---")
            
    