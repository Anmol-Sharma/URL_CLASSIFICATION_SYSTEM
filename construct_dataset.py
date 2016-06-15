import random
train=open('train_dataset.csv','w')
malicious=open('malicious_url.csv','r')
benign=open('benign_url.csv','r')
#Reading Malicious URLs
file_1=malicious.readlines()
#Reading Benign URLs
file_2=benign.readlines()
print(file_1[0],len(file_1),file_2[0],len(file_2),sep='\n')
data=[]
for i in range(1,3701):
	data.append(file_1[i])
for i in range(1,3301):
	data.append(file_2[i])
print(len(data))
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
print('Total Items writen are : %d'%count)