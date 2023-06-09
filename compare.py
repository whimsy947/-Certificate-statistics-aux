import pandas as pd

top100={}

outputfile=open("outputfile",'w+',newline='')
with open ("ocsp100winput.txt","r") as output:
    line = output.readline()
    while line :
        sigline=line.split(',')
        top100[sigline[1]]=True
with open ("top100w.csv","r") as input:
    input100w=pd.read_csv(input)
    for index,row in input100w.iterrows():
        domain=str(row).split(',')
        if domain[1] in top100:
            outputfile.write(domain[1])

outputfile.close()