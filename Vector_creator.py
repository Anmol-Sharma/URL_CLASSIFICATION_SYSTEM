"""
This Module is the actual Code to extract Relevant Information from a URL on features like length,domain tokens,path tokens etc.
It receives a URL and them Processing is done on it.
"""
import re
import requests
import http.client
import urllib
import whois
import datetime

#### List of Suspicious Words Present in URL
Suspicious_Words=['secure','account','update','banking','login','click','confirm','password','verify','signin','ebayisapi','lucky','bonus']

### List of Suspicious Top Level Domains in URLs
Suspicious_TLD=['zip','cricket','link','work','party','gq','kim','country','science','tk']

def Total_Dots(link):
	"""
	Function to calculate the Total Number of Dots in a URL
	"""
	dot='.'
	count=0
	for i in link:
		if i==dot:
			count+=1
	return count

def Total_Delims(str):
	"""
	Function to calculate the Total Number of Delimeters in a URL
	"""
	delim=['-','_','?','=','&']
	count=0
	for i in str:
		for j in delim:
			if i==j:
				count+=1
	return count
	

def no_of_hyphens_in_domain(link):
	"""
	Function to calculate the Total Number of Hyphens in a Domain
	"""
	hyph='-'
	count=0
	for i in link:
		if i==hyph:
			count+=1
	return count

def ip_presence(lis): # Function to Check for Presence of Ip in Domain
	for i in lis:
		if i.isdigit()==False:
			return 0
	else:
		return 1

def Construct_Vector(mystr):
	"""
	Actual Execution function which to do Processing on URLs
	"""
	### Defined Vector which will contain the Values for Different Parameters associated with a URL
	vec=[]	

	removed_protocol=re.sub(r'^http(s*)://','',mystr)		###Removed Protocol in a given URL using Python Regex

	vec.append(len(removed_protocol))	 					#append length of URL to the Vector
	vec.append(Total_Dots(removed_protocol)) 	  			#append Number of Dots in URL to the Vector

	### Checking for Presence of Suspicious Words in URL
	for i in Suspicious_Words:
		if re.search(i,removed_protocol,re.IGNORECASE):
			vec.append(1)								#security sensitive word present so append 1
			break
	else:
		vec.append(0)									#security sensitive word not present so append 0


	patt=r'^[^/]*'										#pattern to extract domain from the URL
	patt_path=r'/[^/]*'									#pattern to extract path of URL
	dom=re.match(patt,removed_protocol).group(0)
	info=re.findall(patt_path,removed_protocol)
	###print('Domain Name: ',dom)
	doma_hyph_count=no_of_hyphens_in_domain(dom)
	vec.append(int(doma_hyph_count))					#Appending Number of hyphens in Domain of URL to the Vector
	domain_Tokens=(dom).split('.')
	domain_Tokens=[x for x in domain_Tokens if x!='']	##Removing Null Values (if Any)
	##print('Domain Length: ',len(dom))
	path_tokens=[re.sub('/','',x) for x in info]
	if path_tokens!=[]:
		file_n_args=path_tokens[-1]
	else:
		file_n_args=''
	path_tokens=path_tokens[:-1]
	info=[x for x in info if x!='']
	slashes=len(info)
	#print('Slashes:',slashes)
	dir_len=0
	for i in (path_tokens):
		dir_len+=len(i)
	dir_len+=slashes
	vec.append(int(dir_len))								#Appeding Directory length to the URL to the Vector
	#print('Directory Length: ',dir_len)
	num_subdir=len(path_tokens)
	#print('Number of Subdirectories :',num_subdir)
	vec.append(num_subdir)									#Appending Number of Subdirectories	Present in the URL to the Vector
	#print('Path Tokens : ',path_tokens)
	TLD=domain_Tokens[-1]	
	#print('Top Level Domain :',TLD)
	vec.append(len(dom)) 									#Domain Length
	vec.append(len(domain_Tokens))					#Domain Token Count
	vec.append(len(path_tokens)) 					#Path Token Count
	#asn_num=msh.check(dom)
	is_ip=ip_presence(domain_Tokens)
	vec.append(is_ip) 								#Presence of ip address Yes:1, No:0
	##print('ASN number :',asn_num)
	domain_tok_lengts=[]
	for i in domain_Tokens:
		domain_tok_lengts.append(len(i))
	largest_dom_token_len=max(domain_tok_lengts)
	vec.append(largest_dom_token_len)  				#Largest Domain Token Length

	avg_dom_Tok_len=float(sum(domain_tok_lengts))/len(domain_tok_lengts)

	vec.append(avg_dom_Tok_len)     				#Average Domain Token Length

	path_tok_lengts=[]
	path_tok_dots=0
	path_tok_delims=0
	avg_path_Tok_len=0
	largest_path_token_len=0
	if len(path_tokens):
		for i in path_tokens:
			path_tok_lengts.append(len(i))
			path_tok_dots=Total_Dots(i)
			path_tok_delims=Total_Delims(i)
		avg_path_Tok_len=float(sum(path_tok_lengts))/len(path_tok_lengts)
		largest_path_token_len=max(path_tok_lengts)
		vec.append(largest_path_token_len) 				#Largest Path Token Length
		vec.append(avg_path_Tok_len)					#Average Path Token Length
	else:
		vec.append(largest_path_token_len)				#Largest Path Token Length :0 (No, Path Tokens)
		vec.append(avg_path_Tok_len)					#Average Path Token Length :0 (No, Path Tokens)	
	#print('Largest Path Token Length:',largest_path_token_len)
	#print('Path Token Total Dots:',path_tok_dots)
	#print('Path Token Delims:',path_tok_delims)
	if is_ip:
		vec.append(0)									#Ip address present so no suspicious TLD
	else:
		for i in Suspicious_TLD:
			if re.search(i,TLD,re.IGNORECASE):
				vec.append(1)							#Suspicious TLD
				break
		else:
			vec.append(0)								#Non Suspicious TLD
	if file_n_args!='':		

		### Define Condition whether file and arguments present in the URL
		tmp=file_n_args.split('?')
		file=tmp[0]
		if len(tmp)>1:
			args=tmp[1]
		else:
			args=''
		#print('File:',file)
		#print('Arguments:',args)
		vec.append(len(file))							#Length of file
		vec.append(Total_Dots(file))					#Total_Dots in file name
		vec.append(Total_Delims(file))					#Total_Delims in file name
		#print('Total dots in file: ',Total_Dots(file))
		#print('Total Delims in file: ',Total_Delims(file))

		if args=='':
			### Checking if any POST arguments present in the URL or not
			vec.append(0)									#Length of Argument Appended to the Vector
			vec.append(0)									#Number of Variables Appended to the Vector
			vec.append(0)									#Length of larges variable value Appended to the Vector
			vec.append(0)									#Maximum number of Delims Appended to the Vector
			#print('argument length:',0)
			#print('number of arguments:',0)
			#print('length of Largest variable value:',0)
			#print('Maximun no of delims:',0)

		else:
			## indicated Presence of POST arguments in the URL

			vec.append(len(args)+1)							#Length of Argument Appended to the Vector
			#print('argument length:',len(args)+1)
			arb=args.split('&')
			vec.append(len(arb))							#Number of Arguments Appended to the Vector
			#print('Number of arguments',len(arb))
			len_var=[]
			max_delim=[]
			for i in arb:
				### Spliting POST Arguments around '=' sign
				tmp=i.split('=')
				if len(tmp)>1:
					len_var.append(len(tmp[1]))
					max_delim.append(Total_Delims(tmp[0]))
					max_delim.append(Total_Delims(tmp[1]))
				else:
					len_var.append(0)
					max_delim.append(0)
			vec.append(max(len_var))						#Length of Largest variable value
			#print('length of Largest variable value:',max(len_var))
			max_delim=max(max_delim)
			vec.append(max_delim)							#Maximum number of Delimeters	
			#print('Maximum no of delims:',max_delim)


	else:

		### Defines condition to the corresponding if that File and Arguments are not Present in the URL so Just Append 0 to the
		### corresponding Parameter in the Vector

		vec.append(0)									#Length of file Appended to the Vector
		vec.append(0)									#Total_Dots in file name Appended to the Vector
		vec.append(0)									#Total_Delims in file name Appended to the Vector
		vec.append(0)									#Length of Argument Appended to the Vector
		vec.append(0)									#Number of Variables Appended to the Vector
		vec.append(0)									#Length of larges variable value Appended to the Vector
		vec.append(0)									#Maximum number of Delims Appended to the Vector
		#print('argument length:',0)
		#print('number of arguments:',0)
	
	###########Extracting Host Based Features Now

	### Defined Avg Month of the Year
	avg_month_time=365.2425/12.0

	###Loop to remove extra delimeter and Dots in the URL to query WHOIS server
	while(True):
		if(not dom[-1].isalnum()):
			dom=dom[:-1]
		else:
			break

	### Sending Request to WHOIS Server
	try:
		who_info=whois.whois(dom)
	except Exception:
		vec.append(-1)									### created age in months
		vec.append(-1)									### expiry age in months
		vec.append(-1)									### updated age in days
		vec.append(-1)									### zip code
		return vec

	### Define case where there may be an exception/error in query or maybe record not present in the WHOIS database
	if(who_info.creation_date == None and who_info.expiration_date == None and who_info.updated_date == None and who_info.zipcode == None):
		vec.append(-1)									### created age in months Appended to the Vector
		vec.append(-1)									### expiry age in months Appended to the Vector
		vec.append(-1)									### updated age in days Appended to the Vector
		vec.append(-1)									### zip code Appended to the Vector
		return vec

	### Further Processing to Creation Date, Updation Date, Expiry Date etc of a URL
	### Processing involves checking whether the datetime object returned is a list or string and then extract information from it
	if(who_info.creation_date==None or type(who_info.creation_date) is str):
		vec.append(-1)
	else:
		if(type(who_info.creation_date) is list): 
			create_date=who_info.creation_date[-1]
		else:
			create_date=who_info.creation_date
		if(type(create_date) is datetime.datetime):
			today_date=datetime.datetime.now()
			create_age_in_mon=((today_date - create_date).days)/avg_month_time
			create_age_in_mon=round(create_age_in_mon)
			vec.append(create_age_in_mon)					#### appending created age in months Appended to the Vector
		else:
			vec.append(-1)									#### created age error so append -1

	if(who_info.expiration_date==None or type(who_info.expiration_date) is str):
		vec.append(-1)
	else:
		if(type(who_info.expiration_date) is list):
			expiry_date=who_info.expiration_date[-1]
		else:
			expiry_date=who_info.expiration_date
		if(type(expiry_date) is datetime.datetime):
			today_date=datetime.datetime.now()
			expiry_age_in_mon=((expiry_date - today_date).days)/avg_month_time
			expiry_age_in_mon=round(expiry_age_in_mon)
			vec.append(expiry_age_in_mon)					#### appending expiry age in months Appended to the Vector
		else:
			vec.append(-1)									#### expiry date error so append -1

	if(who_info.updated_date==None or type(who_info.updated_date) is str):
		vec.append(-1)		
	else:
		if(type(who_info.updated_date) is list):
			update_date=who_info.updated_date[-1]
		else:
			update_date=who_info.updated_date
		if(type(update_date) is datetime.datetime):
			today_date=datetime.datetime.now()
			update_age_in_days=((today_date - update_date).days)
			vec.append(update_age_in_days)					#### appending updated age in days Appended to the Vector
		else:
			vec.append(-1)


	zipcode=who_info.zipcode
	if(zipcode == None or (type(zipcode) is not str)):
		zipcode=-1
	else:
		if '-' in zipcode:
			zipcode=re.sub('-*','',zipcode)
		zipcode=re.sub(r'[A-Za-z\s]*','',zipcode)

	if(type(zipcode) is str and zipcode.isdigit()):
		vec.append(int(zipcode))							####appending zipcode of the Given URL to the Vector
	else:
		zipcode=-1
		vec.append(zipcode)
	return vec