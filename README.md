# 防木马软件

------
**木马**(Trojan)，也称木马病毒，是指通过特定的程序木马程序来控制另一台计算机。木马程序是目前比较流行的病毒文件，与一般的病毒不同，它不会自我繁殖，也并不刻意地去感染其他文件，它通过将自身伪装吸引用户下载执行，向施种木马者提供打开被种主机的门户，使施种者可以任意毁坏、窃取被种者的文件，甚至远程操控被种主机。木马病毒的产生**严重危害**着现代网络的安全运行。

特洛伊木马程序是**不能自动操作**的， 一个特洛伊木马程序是包含或者安装一个存心不良的程序的， 它可能看起来是有用或者有趣的计划（或者至少无害）对一不怀疑的用户来说，但是实际上有害当它被运行。特洛伊木马不会自动运行，它是**暗含在某些用户感兴趣的文档中**，用户下载时附带的。当用户运行文档程序时，特洛伊木马才会运行，信息或文档才会被破坏和遗失。

通常我们会选择不随便访问**来历不明的网站**以及使用**来历不明的软件**，但很多情况下是难以完全做到的，于是我们需要相关的木马查杀软件，进行木马的扫描以及清理。常见的木马出现的异常表现为

> *  **存在陌生用户**：电脑中木马后，常常会开启一些服务程序，为黑客提供各种数据信息。用户可以启动服务查看器，查看是否存在异常的服务，并及时关闭服务。
> *  **可疑启动项**：在入侵之后黑客一般会添加一个启动项随计算机启动而启动。打开“系统配置”对话框，选择“启动”选项卡，查看是否有可疑的启动项。
> *   **注册表异常**：在查看注册表异常时，用户最好在修改前对注册表进行备份。运行Regedit命令，打开“注册表编辑器”窗口，查看相应的键和值是否出现异常。
> *  **进程异常**：在windows任务管理器中出现一些异常现象，发现一些可疑的进程，我们应该及时将其结束。
> * ...

在本次实验基于相关的异常情况，进行编程从而达到木马的扫描，具体实验内容如下。
### **一、实验要求**
>  **编写防木马软件**，要求能够扫描课程中提到启动位置（启动文件夹，注册表，服务列表），其次，扫描系统开放的端口（要呈现出打开端口的进程id，进程名），能够对比每次扫描的结果，找出异常进程，基于上述关键点，查找是否有木马或类木马软件。
### **二、实验准备**
本次实验采用**python**编程，由于需要用到相关系统的调用，于是引用了一些库如下：
> *  **psutil**： 是一个跨平台库[(http://pythonhosted.org/psutil/)](http://pythonhosted.org/psutil/)能够轻松实现获取系统运行的进程和系统利用率（包括CPU、内存、磁盘、网络等）信息。它主要用来做系统监控，性能分析，进程管理。
> *  **Pywin32**：该库为python提供Windows API的扩展，提供了Windows常量、接口、线程以及COM机制等。
> *  **wmi**：WMI 模块可用于获取 Windows 内部信息，在使用Python获取Windows系统上的相关的信息可以使用WMI接口来获取。
> *  **os**： Python os模块包含普遍的操作系统功能。如果你希望你的程序能够与平台无关的话，这个模块是尤为重要的。
> *  **platform**： 该模块用来访问平台相关属性。例如一些常见属性和方法如：平台架构、网络名称（主机名）、系统版本和系统名称等。
### **三、实验代码**
1.启动文件夹扫描函数

```python
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
```
2.注册表扫描函数
```python
#################注册表扫描################
    
def scanRegistry():   
    # 打开项
    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,'Software',0, win32con.KEY_ALL_ACCESS)
    print(key)
    chuan="新项 #"
    lenchuan=len(chuan)
    # RegQueryInfoKey函数查询项的基本信息
    print(win32api.RegQueryInfoKey(key))   
    # 返回项的子项数目、项值数目，以及最后一次修改时间
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
```

3.服务列表扫描函数

```python
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
```

 4.端口进程扫描函数
 
```python
#################端口扫描################
pids=[] #常见PID
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
```
5.相关主函数
```python
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
```
### **四、运行结果**
#### 1.扫描启动文件夹
![image](https://github.com/xiaoke-2000/img/blob/master/1589356499811.png)

**当在尝试运行过程中，直接将qq链接文件拉入，则会开始如下图所示出现异常**：
![image](https://github.com/xiaoke-2000/img/blob/master/1589356608850.png)

------
#### 2.扫描注册表
![image](https://github.com/xiaoke-2000/img/blob/master/1589356699235.png)

**当出现为未经允许新的注册子项，将会报异常信息**。

------
#### 3.扫描服务列表
![image](https://github.com/xiaoke-2000/img/blob/master/1589356846275.png)

------
#### 4.扫描开放端口占用进程
![image](https://github.com/xiaoke-2000/img/blob/master/1589356925064.png)

**当出现为不常见的进程号占用端口，将会提醒异常信息**。

### **五、实验反思**
 本次实验基于**python**编写了基础的防木马程序，能够扫描课程中提到**启动位置**（启动文件夹，注册表，服务列表）。一般正常安装的程序，比如杀毒，MSN，防火墙等，都会建立自己的系统服务，不在系统目录下，如果有第三方服务指向的路径是在系统目录下，那么他就是“**木马**”。同时也能够扫描系统**开放的端口**，要呈现出了打开端口的进程id，进程名。将每次扫描的结果**保存至日志文件**，从而能够对比每次扫描的结果，找出异常进程。通过这样可以简单的查找系统中是否有木马或类木马软件。所以能仿佛基本的木马，但是现在的软件都**不是万能**的，需要学点专业知识同时尽量**小心谨慎**的浏览下载相关程序软件。
