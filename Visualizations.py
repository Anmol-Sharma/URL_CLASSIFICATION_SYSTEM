"""
This Module Generates Visualization on the information on the Training Dataset.
Different Plots are generated below and commented out.
To Generate any plot Just Uncomment the code for the Given Plot
"""

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import pickle as pkl

###Opening Training Training Dataset file to read values
train_data=pkl.load(open('Training_Data.pkl','rb'))
#### Printing the information of the Dataframe
print(train_data.info())

"""sns.set(style="darkgrid")
sns.distplot(train_data[train_data['Lable']==0]['len of url'],color='green',label='Benign URLs')
sns.distplot(train_data[train_data['Lable']==1]['len of url'],color='red',label='Malicious URLs')
sns.plt.title('Url Length Distribution')
plt.legend(loc='upper right')
plt.xlabel('Length of URL')
sns.plt.show()"""


"""x=train_data[train_data['Lable']==0]['no of dots']
y=train_data[train_data['Lable']==1]['no of dots']
plt.hist(x,bins=8, alpha=0.9, label='Benign URLs',color='blue')
#sns.distplot(x,bins=8,color='blue',label='Benign URLs')
plt.hist(y,bins=10, alpha=0.6, label='Malicious URLs',color='red')
#sns.distplot(y,bins=8,color='red',label='Malicious URLs')
plt.legend(loc='upper right')
plt.xlabel('Number of Dots')
plt.title('Distribution of Number of Dots in URL')
plt.show()"""


"""graph=sns.jointplot(x='total dots in file',y='total delims in file',color='y',data=train_data[train_data['Lable']==1 ],marker='o',label='Malicious URLs')
graph.x=train_data[train_data['Lable']==0 ]['total dots in file']
graph.y=train_data[train_data['Lable']==0 ]['total delims in file']
graph.plot_joint(plt.scatter,marker='x',c='b',s=50,label='Benign URLs')
plt.xlabel('Total Dots in File Name')
plt.ylabel('Total Delimeters in File Name')
plt.legend()
sns.plt.show()"""


"""graph=sns.jointplot(x='len of url',y='domain len',color='r',data=train_data[train_data['Lable']==1 ],marker='v',label='Malicious URLs',xlim=(0,130))
graph.x=train_data[train_data['Lable']==0 ]['len of url']
graph.y=train_data[train_data['Lable']==0 ]['domain len']
graph.plot_joint(plt.scatter,marker='x',c='b',s=50,label='Benign URLs')
plt.xlabel('Length of URL')
plt.ylabel('Domain Length')
plt.legend()
sns.plt.show()"""

"""sns.set(style="darkgrid")
sns.distplot(train_data[train_data['Lable']==0]['domain len'],color='blue',label='Benign URLs')
sns.distplot(train_data[train_data['Lable']==1]['domain len'],color='red',label='Malicious URLs')
sns.plt.title('Domain Length Distribution')
plt.legend(loc='upper right')
plt.xlabel('Length of Domain/Host')
sns.plt.show()"""

"""sns.set(style="whitegrid")
sns.distplot(train_data[train_data['Lable']==0]['create_age(months)'],color='green',label='Benign URLs')
sns.distplot(train_data[train_data['Lable']==1]['create_age(months)'],color='red',label='Malicious URLs')
sns.plt.title('Creation Age Distribution')
plt.legend(loc='upper right')
plt.xlabel('Age of Domain (Months)')
sns.plt.show()"""