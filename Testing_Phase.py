import numpy as np
import pandas as pd
import Vector_creator as Vc
import pickle as pkl
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

train_data=pkl.load(open('Training_Data.pkl','rb'))
print('\n\n===========================================================')
print('\nReading of Training Phase Done\n')
print('===========================================================\n\n')

model=LogisticRegression()
Target_labels=train_data['Lable'].values
train_data=train_data.drop(['URL','Lable'],axis=1)
print(train_data.info())
predictor=train_data.values
model.fit(predictor,Target_labels)
model.score(predictor,Target_labels)
while True:
	url=input('\nEnter URL:\n')
	if url=='':
		break
	vec=Vc.Construct_Vector(url)
	vec=np.array(vec)
	vec=vec.reshape(1,-1)
	predicted=model.predict(vec)
	if predicted:
		print('\n\aMalicious Link Ahead')
	else:
		print('\nSafe Link')

