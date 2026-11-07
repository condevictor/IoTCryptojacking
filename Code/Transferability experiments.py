#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import tsfresh
import os
import json
import scapy
import numpy as np
import warnings
from timeit import default_timer as timer

from scapy.all import *

warnings.filterwarnings("ignore") #ignore warnings caused by 


#################################################################
#                                                               #
#               malicious csv files import                      #
#                                                               #
#################################################################

df1 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/WebOS_binary.csv') #
df2 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Server_Binary.csv') #
df3 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Raspberry_Webmine_Robust.csv')
df4 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Raspberry_Binary.csv') #
df5 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Raspberry_Webmine_Aggressive.csv')
df6 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Raspberry_WebminePool_Aggressive.csv')
df7 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Server_WebminePool_Aggressive.csv') #

df32 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Server_WebminePool_Robust.csv') #
df33 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Raspberry_WebminePool_Stealthy.csv') #
df34 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Raspberry_WebminePool_Robust.csv') #
df35 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/malicious/Desktop_WebminePool_Aggressive.csv') #


#################################################################
#                                                               #
#               benign csv files import                         #
#                                                               #
#################################################################

############### LAPTOP #############

df8 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Laptop/Laptop_download_benign.csv')
df9 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Laptop/Laptop_idle_benign.csv')
df10 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Laptop/Laptop_interactive_benign.csv')
df11 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Laptop/Laptop_video_benign.csv')
df12 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Laptop/Laptop_webbrowsing_benign.csv')

############### Raspberry ##########

df13 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Raspberry/Raspberry_download_benign.csv')
df14 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Raspberry/Raspberry_idle_benign.csv')
df15 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Raspberry/Raspberry_interactive_benign.csv')
df16 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Raspberry/Raspberry_video_benign.csv')
df17 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Raspberry/Raspberry_webbrowsing_benign.csv')

############### Server ############


df18 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Server/Server_download_benign.csv')
df19 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Server/Server_idle_benign.csv')
df20 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Server/Server_interactive_benign.csv')
df21 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Server/Server_video_benign.csv')
df22 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/Server/Server_webbrowsing_benign.csv')

############### WebOS ############

df23 = pd.read_csv('/home/CIN/vddc/cryptojacking/data/benign-2/WebOS/Webos_video(live&normal)_benign.csv')




df_results = pd.DataFrame()

# In[2]:


print("df1 -->> {}".format(len(df1)))
print("df2 -->> {}".format(len(df2)))
print("df3 -->> {}".format(len(df3)))
print("df4 -->> {}".format(len(df4)))
print("df5 -->> {}".format(len(df5)))
print("df6 -->> {}".format(len(df6)))
print("df7 -->> {}".format(len(df7)))
print("df32 -->> {}".format(len(df32)))
print("df33 -->> {}".format(len(df33)))
print("df34 -->> {}".format(len(df34)))
print("df35 -->> {}".format(len(df35)))
print("/////////////////////////////////////////////////")

print(" LAPTOP ")


print("df8 -->> {}".format(len(df8)))
print("df9 -->> {}".format(len(df9)))
print("df10 -->> {}".format(len(df10)))
print("df11 -->> {}".format(len(df11)))
print("df12 -->> {}".format(len(df12)))

print(" Raspberry ")


print("df13 -->> {}".format(len(df13)))
print("df14 -->> {}".format(len(df14)))
print("df15 -->> {}".format(len(df15)))
print("df16 -->> {}".format(len(df16)))
print("df17 -->> {}".format(len(df17)))

print(" Server ")

print("df18 -->> {}".format(len(df18)))
print("df19 -->> {}".format(len(df19)))
print("df20 -->> {}".format(len(df20)))
print("df21 -->> {}".format(len(df21)))
print("df22 -->> {}".format(len(df22)))

print(" WebOS ")

print("df23 -->> {}".format(len(df23)))


# In[3]:


# Prune the datasets for labeling process for malicious data


# For WebOS = 18:56:80:17:d0:ef
index_names = df1[((df1['HW_dst'] != '18:56:80:17:d0:ef') & (df1['Hw_src'] != '18:56:80:17:d0:ef'))].index
df1.drop(index_names, inplace = True)

# Big_Server_Monero_mining_data = a4:bb:6d:ac:e1:fd

index_names = df2[((df2['HW_dst'] != 'a4:bb:6d:ac:e1:fd') & (df2['Hw_src'] != 'a4:bb:6d:ac:e1:fd'))].index
df2.drop(index_names, inplace = True)

# ege_data_rasberry = dc:a6:32:67:66:4b	

index_names = df3[((df3['HW_dst'] != 'dc:a6:32:67:66:4b') & (df3['Hw_src'] != 'dc:a6:32:67:66:4b'))].index
df3.drop(index_names, inplace = True)

# Rasberry_binary_monero_mining = dc:a6:32:68:35:8a

index_names = df4[((df4['HW_dst'] != 'dc:a6:32:68:35:8a') & (df4['Hw_src'] != 'dc:a6:32:68:35:8a'))].index
df4.drop(index_names, inplace = True)

# Rasberry_network_data_2 = dc:a6:32:67:66:4b

index_names = df5[((df5['HW_dst'] != 'dc:a6:32:67:66:4b') & (df5['Hw_src'] != 'dc:a6:32:67:66:4b'))].index
df5.drop(index_names, inplace = True)

# Rasberry-Webmine = dc:a6:32:67:66:4b
index_names = df6[((df6['HW_dst'] != 'dc:a6:32:67:66:4b') & (df6['Hw_src'] != 'dc:a6:32:67:66:4b'))].index
df6.drop(index_names, inplace = True)

# Server_Webmine_Network_data = a4:bb:6d:ac:e1:fd

index_names = df7[((df7['HW_dst'] != 'a4:bb:6d:ac:e1:fd') & (df7['Hw_src'] != 'a4:bb:6d:ac:e1:fd'))].index
df7.drop(index_names, inplace = True)

# Server_%50_Mining = a4:bb:6d:ac:e1:fd

index_names = df32[((df32['HW_dst'] != 'a4:bb:6d:ac:e1:fd') & (df32['Hw_src'] != 'a4:bb:6d:ac:e1:fd'))].index
df32.drop(index_names, inplace = True)

# Rasberry_webmine_%10 = dc:a6:32:67:66:4b

index_names = df33[((df33['HW_dst'] != 'dc:a6:32:67:66:4b') & (df33['Hw_src'] != 'dc:a6:32:67:66:4b'))].index
df33.drop(index_names, inplace = True)

# Rasberry_webmine_%50 = dc:a6:32:68:35:8a

index_names = df34[((df34['HW_dst'] != 'dc:a6:32:68:35:8a') & (df34['Hw_src'] != 'dc:a6:32:68:35:8a'))].index
df34.drop(index_names, inplace = True)

# Desktop_Webmine_%100 = dc:a6:32:68:35:8a

index_names = df35[((df35['HW_dst'] != 'd8:3b:bf:8f:ba:ba') & (df35['Hw_src'] != 'd8:3b:bf:8f:ba:ba'))].index
df35.drop(index_names, inplace = True)

# In[4]:


#################################################################
#                                                               #
#      Labeling Features for further calculations               #
#                                                               #
#################################################################

df1.insert(7, "Is_malicious", 1)
df2.insert(7, "Is_malicious", 1)
df3.insert(7, "Is_malicious", 1)
df4.insert(7, "Is_malicious", 1)
df5.insert(7, "Is_malicious", 1)
df6.insert(7, "Is_malicious", 1)
df7.insert(7, "Is_malicious", 1)

# ========================================================

df8.insert(7, "Is_malicious", 0)
df9.insert(7, "Is_malicious", 0)
df10.insert(7, "Is_malicious", 0)
df11.insert(7, "Is_malicious", 0)
df12.insert(7, "Is_malicious", 0)
df13.insert(7, "Is_malicious", 0)
df14.insert(7, "Is_malicious", 0)
df15.insert(7, "Is_malicious", 0)
df16.insert(7, "Is_malicious", 0)
df17.insert(7, "Is_malicious", 0)
df18.insert(7, "Is_malicious", 0)
df19.insert(7, "Is_malicious", 0)
df20.insert(7, "Is_malicious", 0)
df21.insert(7, "Is_malicious", 0)
df22.insert(7, "Is_malicious", 0)
df23.insert(7, "Is_malicious", 0)

# ========================================================


df32.insert(7, "Is_malicious", 1)
df33.insert(7, "Is_malicious", 1)
df34.insert(7, "Is_malicious", 1)
df35.insert(7, "Is_malicious", 1)

# In[5]:


def run_process(a,b,c,d,x):
    #run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)
 
  
    df_malicious_Train = a.copy()
    df_benign_Train    = b.copy()
    
    df_malicious_Test = c.copy()
    df_benign_Test    = d.copy()
    
    
    
    from tsfresh import extract_features, select_features
    from tsfresh.utilities.dataframe_functions import impute
    from tsfresh import extract_features
    from tsfresh.feature_selection.relevance import calculate_relevance_table


    df_malicious_Train.reset_index(drop=True, inplace=True) #reset index
    df_malicious_Train['id']= np.floor(df_malicious_Train.index.array/10)
    
    df_malicious_Test.reset_index(drop=True, inplace=True) #reset index
    df_malicious_Test['id']= np.floor(df_malicious_Test.index.array/10)
    
    
    df_benign_Train.reset_index(drop=True, inplace=True) #reset index
    df_benign_Train['id']= np.floor(df_benign_Train.index.array/10)
    
    df_benign_Test.reset_index(drop=True, inplace=True) #reset index
    df_benign_Test['id']= np.floor(df_benign_Test.index.array/10)
    


    tf1=tsfresh.extract_features(df_malicious_Train,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf1['class']= 1
    
    tf1_1=tsfresh.extract_features(df_malicious_Test,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf1_1['class']= 1

      
    tf2=tsfresh.extract_features(df_benign_Train,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf2['class']= 0
    
    tf2_1=tsfresh.extract_features(df_benign_Test,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf2_1['class']= 0
    

    tf2.columns = tf1.columns
    tf2_1.columns = tf1_1.columns
    

    features_train=pd.concat([tf1,tf2])
    features_test=pd.concat([tf1_1,tf2_1])
    
    
    features2_train = features_train.copy()
    features2_train.reset_index(drop=True, inplace=True)
    

    
    y_train = pd.Series(data = features2_train['class'], index=features2_train.index)
    
    relevance_table_train = calculate_relevance_table(features2_train, y_train)
    

    relevance_table_train = relevance_table_train[relevance_table_train.relevant]
    relevance_table_train.sort_values("p_value", inplace=True)
    best_features_train = relevance_table_train[relevance_table_train['p_value'] <= 0.05] 
    
    
    df_ML_train = pd.DataFrame()
    df_ML_test  = pd.DataFrame()
    

    df_ML_train[best_features_train.feature] = features_train[best_features_train.feature]

    df_ML_test[best_features_train.feature] = features_test[best_features_train.feature]


    final = ML_Process(df_ML_train,df_ML_test,x)
    
    return final

# In[6]:


def ML_Process(df_ML_train,df_ML_test,x):
    df_results = x.copy() 
    print('let the ml starts')
  
    from sklearn import neighbors, metrics
    from sklearn.preprocessing import LabelEncoder
    

    X_train = df_ML_train.drop('class',axis=1).to_numpy()
    y_train = df_ML_train['class'].to_numpy()

    X_test = df_ML_test.drop('class',axis=1).to_numpy()
    y_test = df_ML_test['class'].to_numpy()

    
    from sklearn.model_selection import train_test_split
    Le = LabelEncoder()
    for i in range(len(X_train[0])):
        X_train[:, i] = Le.fit_transform(X_train[:, i])
    for i in range(len(X_train[0])):
        X_test[:, i] = Le.fit_transform(X_test[:, i])


    #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=8675309)

    
    from sklearn.linear_model import LogisticRegression
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.svm import SVC
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.naive_bayes import GaussianNB
    #from xgboost import XGBClassifier
    from sklearn import model_selection
    from sklearn.utils import class_weight
    from sklearn.metrics import classification_report
    from sklearn.metrics import confusion_matrix
    import numpy as np
    import pandas as pd
    y_train = y_train.ravel()
    dfs = []
    models = [
          ('LogReg', LogisticRegression()), 
          #('RF', RandomForestClassifier()),
          ('KNN', KNeighborsClassifier()),
          ('SVM', SVC()), 
          ('GNB', GaussianNB())
          #('XGB', XGBClassifier())
            ]
    results = []
    names = []
    scoring = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted', 'roc_auc']
    target_names = ['malignant', 'benign']
    for name, model in models:
        kfold = model_selection.KFold(n_splits=5, shuffle=True, random_state=90210)
        cv_results = model_selection.cross_validate(model, X_train, y_train, cv=kfold, 
                                                    scoring=scoring)

        clf = model.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        print(name)
        print(classification_report(y_test, y_pred, target_names=target_names))
        results.append(cv_results)
        names.append(name)
        this_df = pd.DataFrame(cv_results)
        this_df['model'] = name
        dfs.append(this_df)
        final = pd.concat(dfs, ignore_index=True)
        print(final)


    return(final)


# In[110]:


## Train: Webmine, Test: WebminePool
 
df_malicious_Train = pd.concat([df5])
df_malicious_Test = pd.concat([df6])


df_benign_Train = pd.concat([df13,df14,df15,df16,df17])[:450000]
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])[450000:]

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")


print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)
 
end = timer()
print(end - start)


# In[112]:


## Train: WebminePool, Test: Webmine
 
df_malicious_Train = pd.concat([df6])
df_malicious_Test = pd.concat([df5])


df_benign_Train = pd.concat([df13,df14,df15,df16,df17])[:450000]
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])[450000:]

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")


print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)
 
end = timer()
print(end - start)


# In[11]:


## Train: Raspberry (server), Test: binary (WebOS)
 
df_malicious_Train = pd.concat([df4])
df_malicious_Test = pd.concat([df1])


df_benign_Train = pd.concat([df14,df15,df16,df17])
df_benign_Test = pd.concat([df14,df15,df16,df17])

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)
 
end = timer()
print(end - start)


# In[115]:


## Train: Binary (raspberry), Test: in-browser (aggressive) (raspberry)
 
df_malicious_Train = pd.concat([df4])
df_malicious_Test = pd.concat([df6])

df_benign_Train = pd.concat([df13,df14,df15,df16,df17])[:450000]
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])[450000:]

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)
 
end = timer()
print(end - start)


# In[116]:


## Train: Binary  (raspberry), Test: in-browser (robust)  (raspberry)
  
df_malicious_Train = pd.concat([df4])
df_malicious_Test = pd.concat([df3])

df_benign_Train = pd.concat([df13,df14,df15,df16,df17])
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)


end = timer()
print(end - start)


# In[117]:


## Train: Binary, Test: in-browser (stealthy)
 
df_malicious_Train = pd.concat([df4])
df_malicious_Test = pd.concat([df33])


df_benign_Train = pd.concat([df13,df14,df15,df16,df17])
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)

end = timer()
print(end - start)


# In[118]:


## Train: in-browser (aggressive), Test: in-browser (stealthy)
 
df_malicious_Train = pd.concat([df5])
df_malicious_Test = pd.concat([df33])


df_benign_Train = pd.concat([df13,df14,df15,df16,df17])
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)

end = timer()
print(end - start)


# In[119]:


## Train: in-browser (aggressive), Test: in-browser (robust)
 
df_malicious_Train = pd.concat([df4])
df_malicious_Test = pd.concat([df32])


df_benign_Train = pd.concat([df13,df14,df15,df16,df17])
df_benign_Test = pd.concat([df13,df14,df15,df16,df17])

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

#print("{} NAN in malicious!".format(len(df_malicious[df_malicious.isna().any(axis=1)])))
#print("{} NAN in benign!".format(len(df_benign[df_benign.isna().any(axis=1)])))

df_malicious_Test = df_malicious_Test.dropna()
df_malicious_Train = df_malicious_Train.dropna()

df_benign_Test = df_benign_Test.dropna()
df_benign_Train = df_benign_Train.dropna()

print("After droppping NAN rows: ")

print("malicious_train: {}".format(len(df_malicious_Train)))
print("malicious_test: {}".format(len(df_malicious_Test)))

print("benign_train: {}".format(len(df_benign_Train)))
print("benign_test: {}".format(len(df_benign_Test)))

start = timer()

results_all_combined_s0 = run_process(df_malicious_Train,df_benign_Train,df_malicious_Test,df_benign_Test,df_results)

end = timer()
print(end - start)

