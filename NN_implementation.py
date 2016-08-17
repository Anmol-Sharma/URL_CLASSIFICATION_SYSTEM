"""
This Module is the Neural Network Implementation of the Classfier using Tensorflow Learning API
"""
import numpy as np
## Importing TensorFlow API
import tensorflow as tf
import pickle as pkl
import Vector_creator as Vc
import pandas as pd

train_data=pkl.load(open('Training_Data.pkl','rb'))
print('\n\n===========================================================')
print('\nReading of Training Phase Done\n')
print('===========================================================\n\n')

y_train=train_data['Lable'].values						#### Stroring Training Lables 
x_data=train_data.drop(['URL','Lable'],axis=1).values	#### Droping Unecessary Columns from the Data Fram

classifier=tf.contrib.learn.DNNClassifier(hidden_units=[10],n_classes=2)

print('\n\n===========================================================')
print('\nStarting to Train the Classifier\n')
print('===========================================================\n\n')
classifier.fit(x=x_data,y=y_train,steps=200)

print('\n\n===========================================================')
print('\nDone Training the Classifier\n')
print('===========================================================\n\n')

print('\n\n===========================================================')
print('\nEnter URLs to Test the Classifier\n')
print('===========================================================\n\n')
while True:
	url=input('\nEnter URL:\n')
	if url=='':
		break
	vec=Vc.Construct_Vector(url)
	vec=np.array(vec)
	vec=vec.reshape(1,-1)
	predicted=classifier.predict(vec)
	if predicted:
		### if True
		print('\n\aLooks like a Malicious Link Ahead')
	else:
		print('\nLooks like a Safe Link')