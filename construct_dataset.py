"""
Python Module to randomly shuffle the two files of Malicious URLs and Beningn URLs and create a dataset of them
"""
import random
##File to which we will write the new dataset
train=open('train_dataset.csv','w')

##File from which Maclicious URLs are Read
malicious=open('malicious_url.csv','r')

###File from which Benign URLs are Read
benign=open('benign_url.csv','r')

#Reading Malicious URLs
file_1=malicious.readlines()
#Reading Benign URLs
file_2=benign.readlines()

print(file_1[0],len(file_1),file_2[0],len(file_2),sep='\n')

####appending all read URLs in a single Python list
data=[]
for i in range(1,3701):
	data.append(file_1[i])
for i in range(1,3301):
	data.append(file_2[i])
print(len(data))

#### Now shuffling and Writing Data to File
temp=[]
train.write('URL,Lable\n')
count=0
while True:
	if count==7000:
		break;
	ran=random.randrange(0,7000)#Randomizing The Dataset
	if ran not in temp:
		temp.append(ran)
		train.write(data[ran])
		count+=1

train.close()
malicious.close()
benign.close()
### Files closed
print('Total Items writen are : %d'%(count))