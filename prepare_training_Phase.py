"""
This Module is for extracting Relevant information on Training Dataset of URLs and Storing the information in a Binary(Pickle) File
"""
import numpy as np
import pandas as pd
import Vector_creator as Vc
import pickle
import time

###Reading the training Dataset file
df_object=pd.read_csv('train_dataset.csv',header=0)
#print(df_object.info())
#print("\nHeader:\n",df_object.head(5))


### Specifying the Data Frame Columns
training_df=pd.DataFrame(columns=('len of url','no of dots','security sensitive words','no of hyphens in dom',\
'dir_len','no of subdir','domain len','domain token count','path token count','ip present','largest domain_tok_len',\
'avg_dom_token_len','largest path token length','avg path token length','suspicious tld','len_of_file','total dots in file',\
'total delims in file','len_of_argument','no_of_variables','len_of_largest_variable_val',\
'max_no_of_argum_delims','create_age(months)','expiry_age(months)','update_age(days)','zipcode'))


print('\n\n===========================================================')
print('Starting to Extract Training Data from URLs')
print('===========================================================\n\n')
print('And we go.....3,2,1')
time.sleep(3)

###Starting To Store information on Each URL
for i in range(len(df_object['URL'])):
	vec=Vc.Construct_Vector(df_object.URL[i])
	training_df.loc[i]=vec
	print('Training example :',i,"done")
#training_df['URL']=df_object['URL']
training_df['Lable']=df_object.Lable
training_df['URL']=df_object.URL
del(df_object)
	
print('all done feature values for training set obtained')
#print(training_df.info())
#print('\n\n\n',training_df.head(2))
#print(len_URL)	


print('\n\n==========================================================')
print('\nStarting to dump Training Data')
print('==========================================================\n\n')
pickle.dump(training_df,open('Training_Data.pkl','wb'))				###Writing the Information on a Binary File
print('All Done')
