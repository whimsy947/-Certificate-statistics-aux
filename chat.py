import pandas as pd
import ast
new_head = ['as', 'org', 'country']
new_columns=pd.DataFrame({
    'as':[],
    'org':[],
    'country':[]
})

data = pd.read_csv('new.csv')


data['error_data'].fillna('<NA>', inplace=True)


filtered_data = data[data['error_data'].str.contains('invalid certificate chain')]

mergedata=pd.concat([filtered_data,new_columns],axis=1)
modified_data = pd.DataFrame(columns=mergedata.columns)
file = open('ipas.txt', 'r')
line=file.readline()
ipastotal={}
while line:
    ipas = ast.literal_eval(line)
    if ipas['status']=='success':
        ip = ipas['query']
        ipastotal[ip] = ['', '', '']
        ipastotal[ip][0]=ipas['as']
        ipastotal[ip][1]=ipas['org']
        ipastotal[ip][2]=ipas['country']
    line = file.readline()

ipastotal =pd.DataFrame(ipastotal)
for index, row in mergedata.iterrows():
    if row['ip'] in ipastotal:
        mergedata.loc[index, 'as'] = ipastotal[row['ip']][0]
        mergedata.loc[index, 'org'] = ipastotal[row['ip']][1]
        mergedata.loc[index, 'country'] = ipastotal[row['ip']][2]
        new=mergedata.loc[[index]]
        modified_data=pd.concat([modified_data,new],ignore_index=True)
      
    else:
        mergedata.drop(index, inplace=True)
mergedata.to_csv('1.csv')
file.close()
            
