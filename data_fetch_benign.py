"""
This Module is for obtaining Beningn URLs from Dmoz Open Repository
"""
import re 
import csv
import time
import urllib.request as req
import urllib.parse as prs

def extrac_relevant_info(dat,my_file):
	"""
	Function to extract the relevant Link from a given Page of DMOZ open repository and write it to a file
	"""
	#patt=r'<a href=(\S*)\sclass="listinglink">'
	patt=r'<a target="_blank" href="[^"]+'		###Regular Expression for matching and searching Relevant Link on the Page
	links=re.findall(patt,dat) #Parsing Data Using Regex
	print('The total of %i links are as follows : '%len(links))
	for i in links:
		i=i.replace(r'<a target="_blank" href="','')
		print('Writing link :',i)
		my_file.writerow([i,0])					### Writing the Link to Dataset File
	print('\n')

#### Actual Code where execution Begins
try:
	headers={}
	headers['user-agent']="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"
	savefile=open('benign_url.csv','a')
	savefile_obj=csv.writer(savefile)
	#savefile_obj.writerow(['URL','Lable'])
	for i in range(30):
		url=input('Enter Url: ')
		myreq=req.Request(url,headers=headers)	
		resp=req.urlopen(myreq)
		respData=str(resp.read())
		extrac_relevant_info(dat=respData,my_file=savefile_obj)
	savefile.close()

except Exception as e:
	print(str(e))