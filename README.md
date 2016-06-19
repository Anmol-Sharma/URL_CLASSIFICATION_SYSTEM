# URL CLASSIFICATION SYSTEM

Malicious Web sites are a cornerstone of Internet criminal activities.
These Web sites contain various unwanted content such as spam-advertised products, phishing sites, dangerous "drive-by"
harness that infect a visitor's system with malware. The most influential approaches to the malicious
URL problem are manually constructed lists in which all malicious web page`s URLs are listed, as
well as users systems that analyze the content or behavior of a Web site as it is visited.

To overcome the disadvantage of _Blacklisting_ approach in which we have to do the tedious task of searching the list for
presence of the entry. Also the list cannot be kept upto date because of the evergrowing growth of web link each and every hour.

In the given System we are using **Machine-Learning** techniques to classify a URL as either safe or unsafe in Real Time without even the need to download the webpage.

The two main Algorithms we are using in this system are :

*	[Random Forest] ()
*	[Logistic Regression] ()

The system is presently working only on **Lexical** features(Simple text features of a URL) which includes:

*	Length of URL
*	Domain Length
*	Presence of Ip Address in Host Name
*	Presence of Security Sensitive Words in URL

and many more(around 22 total). The Host Based Features like country code in which site is hosted, creation date, updation date etc. are still yet to be added to the system and increase accuracy of the classifier but increase the _Latency time_ in classifying the URL as we have to query **WHOIS** servers in order to come up with the Host Based Features.
For this query purpose the PyWhois module has been used.

## Files and Information Related to them

### Data Extraction/Data Munging Files

####	data_fetch_benign.py
This python script will extract the list of URLs from a given page of DMOZ Open Directory relating to a given category. Enter the URL of DMOZ's web page and it will extract the enlisted links and write them to respective csv file.

####	data_fetch_malicious.py
This python script iteratively extracts the list of phishing urls from Phistank.com iteratively and write those links to the respective csv file.

####	contruct_dataset.py
This file reads a certain amount of data from malicious dataset file and certain from benign dataset file and uses random shuffling to create training dataset file.

### Data Set Files

####	bening_url.csv

This file contains the list of Benign( i.e. Non-Malicious URLs) in a comma separated file along with Label 0 specifying them as Non-Spam. This data is collected from DMOZ open Directory.

####	malicious_url.csv

This file contains the list of Malicious URLs in a comma separated file along with Label 1 specifying them as Spam.
This data is collected from Phishtank.com .

####	train_dataset.csv

File constructed after random shuffling of URLs from both Malicious and Benign URLs.

####	Training_Data.pkl

Binary File containing the feature values computed on training dataset URLs

###	Visualizations

####	Visualizations.py
Python script to generate the following figure/plots of the training dataset to gain insight of type of features we can exploit to get better results from our algorithm

####	Fig-1.png
The image shows the URL length Distributions of both Malicious as well as Benign URLs.
![URL Length Distribution](https://github.com/Anmol-Sharma/URL_CLASSIFICATION_SYSTEM/blob/master/Fig-1.png)


####	Fig-2.png
The image shows the Number of Dots Distributions of both Malicious as well as Benign URLs.

![No of Dots Distribution](https://github.com/Anmol-Sharma/URL_CLASSIFICATION_SYSTEM/blob/master/Fig-2.png)


####	Fig-3.png
The image shows the scatter plot of Total Dots vs Total Delimeters in File name in a given URL.

![Scatter Plot]	(https://github.com/Anmol-Sharma/URL_CLASSIFICATION_SYSTEM/blob/master/Fig-3.png)


####	Fig-4.png
The image show the Domain length Distributions of both Malicious as well as Benign URLs.

![Domain Length Distribution](https://github.com/Anmol-Sharma/URL_CLASSIFICATION_SYSTEM/blob/master/Fig-4.png)

###	Machine Learning/Data Processing Scripts

####	Vector_Creator.py
Python script to extract features values from a given URL and return it as a list.

####	training_Phase.py
Python script to produce training dataset after doing feature extraction and storing it in a binary file named Training_Data.pkl as defined above.

####	Testing_Phase.py
Python script which take as input a url and then classify it where Safe or Unsafe after training the algorith on the training dataset values.
