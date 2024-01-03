#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[17]:


from lxml import etree
import xml.etree.ElementTree as ET
import nltk
from nltk.corpus import stopwords
from gensim.utils import simple_preprocess
from nltk.tokenize import word_tokenize
import gensim
import gensim.similarities 
from gensim.models.word2vec import Word2Vec
import numpy as np
import pandas as pd
import csv


# # Pre-Processing

# In[18]:


# reads in the CVE data set and returns vulnerability information  

def read_file(file):
    all_entries = {0: {'CVE': "", 'Date': "",'Description': [], 'Description-Tokenized' : [],
                   'Month-String':"",'Month-Int': 0,"Year":"","Year-Int":0, "Time Start": 0, "Time End": 0}}
    
    untokenized_text = list()
    start_index = 0
    year_num = 1
    
    vulns = parse_data(file)
    for text in vulns[1]:
        untokenized_text.append(text)
    all_entries = store_entries(vulns,start_index,year_num,len(file))
        
    return [all_entries,untokenized_text]        

# helper method used to identify "REJECT" entries 

def is_member(target, possible):
    for item in possible:
        if target is item or target == item:
              return True
    return False

# parse CVE dataset in a hierarchical format

def parse_data(file):
    tree = ET.parse(file)
    root = tree.getroot()
    notes = list()
    cve = list()
    pub = list()
    for i in range(5,len(root)):
        try:
            token = word_tokenize(root[i][1][0].text)
            if is_member("REJECT",token) == False:  
                pub.append(root[i][1][1].text)
                cve.append(root[i][2].text)
                notes.append(root[i][1][0].text)
        except:
            continue
    
    vulns_info = [cve,notes,pub]
    return vulns_info
      
# methods for tokenizing     
    
def tokenize(text):
    tokenized = list()
    for i in range(0, len(text)):
        filtered = remove_stopwords(word_tokenize(text[i]))
        tokenized.append(filtered)
                         
    return tokenized

def tokenize_single(sentence):
    filtered = remove_stopwords(word_tokenize(sentence))
    tokenized = [word.lower() for word in filtered] 
    return tokenized

# remove stopwords and punctuation

def remove_stopwords(text):
    # NLTK stopwords
    stop_words = stopwords.words('english')
    stop_words.append(')')
    stop_words.append('(')
    stop_words.append('.')
    stop_words.append('')
    filtered_sentence = [w for w in text if not w.lower() in stop_words]
    filtered_sentence = []
 
    for w in text:
        if w not in stop_words:
            filtered_sentence.append(w)
    return filtered_sentence

# read vulnerability text for doc2vec model training 

def read_corpus(text, tokens_only=False):
    count=0
    for doc in text:
        count+=1
        tokens = gensim.utils.simple_preprocess(doc)
        if tokens_only:
            yield tokens
        else:
            yield gensim.models.doc2vec.TaggedDocument(tokens, [count])

# build and train a doc2vec model on all vulnerability text          
            
def build_doc2vec(untokenized_text):
    train_corpus = list(read_corpus(untokenized_text))
    test_corpus = list(read_corpus(untokenized_text, tokens_only=True))
    model = gensim.models.doc2vec.Doc2Vec(vector_size=100, min_count=2, epochs=20)
    model.build_vocab(train_corpus)
    model.train(train_corpus, total_examples=model.corpus_count, epochs=model.epochs)
    return model

# converts the vulnerability text to vectors. text is a list of tokenized sentences for the entire data set
# model is a doc2vec model 
 
def compute_vectors(text,model):
    vectors = list()
    for sentence in text:
        vectors.append(model.infer_vector(sentence))
    return vectors
        
    
# store information of each vulnerability entry in a dictionary. Includes CVE ID, Publication date, vulnerability
# description, tokenized description, month as a string, month as an int (1-12), and start and end times
    
def store_entries(vulns,start_index,year_num,total_years):
    entries = {start_index: {'CVE': "", 'Date': "",'Description': [], 'Description-Tokenized' : [],
                   'Month-String':"",'Month-Int': 0,"Year":"","Year-Int":0,"Time Start": 0, "Time End": 0}}
    j=0

    for i in range(start_index,start_index+len(vulns[0])):
        entries[i] = {}
        entries[i]['CVE'] = vulns[0][j]
        entries[i]['Date'] = vulns[2][j]
        entries[i]['Description'] = vulns[1][j]
        tokenized = tokenize_single(vulns[1][j])
        desc_tokenized = remove_stopwords(tokenized)
        entries[i]['Description-Tokenized'] = desc_tokenized
        entries[i]['Month-String'] = "n/a"
        entries[i]['Month-Int'] = 0
        entries[i]["Year"] = entries[i]['Date'][0:4]
        entries[i]["Year-Int"] = year_num
        j = j + 1

    for i in range(start_index,start_index+len(vulns[0])):
        if str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '1':
            entries[i]["Month-String"] = "January"
            entries[i]["Month-Int"] = 1
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '2':
            entries[i]["Month-String"] = "February"
            entries[i]["Month-Int"] = 2
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '3':
            entries[i]["Month-String"] = "March"
            entries[i]["Month-Int"] = 3
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '4':
            entries[i]["Month-String"] = "April"
            entries[i]["Month-Int"] = 4
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '5':
            entries[i]["Month-String"] = "May"
            entries[i]["Month-Int"] = 5
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '6':
            entries[i]["Month-String"] = "June"
            entries[i]["Month-Int"] = 6
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '7':
            entries[i]["Month-String"] = "July"
            entries[i]["Month-Int"] = 7
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '8':
            entries[i]["Month-String"] = "August"
            entries[i]["Month-Int"] = 8
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '9':
            entries[i]["Month-String"] = "September"
            entries[i]["Month-Int"] = 9
        elif str(entries[i]['Date'])[5] == '1' and entries[i]['Date'][6] == '0':
            entries[i]["Month-String"] = "October"
            entries[i]["Month-Int"] = 10
        elif str(entries[i]['Date'])[5] == '1' and entries[i]['Date'][6] == '1':
            entries[i]["Month-String"] = "November"
            entries[i]["Month-Int"] = 11
        else:
            entries[i]["Month-String"] = "December"
            entries[i]["Month-Int"] = 12
        
        # get time interval 
        entries[i]["Time Start"] = (year_num * 12) - entries[i]["Month-Int"]
        entries[i]["Time End"] = total_years * 12
        
    return entries


# # Main Method

# In[9]:


# Ask user for filename of data set and the edge attributes to be analyzed 
dataset_filename = str(input("Enter the name of the dataset file you are analyzing: "))
nodes_filename = str(input("Enter the name of the graph file you would like to analyze: "))


# In[31]:


# return the descriptions of the vulnerabilities in the top 5 largest communities 

def main(dataset_file,nodes_file):
    node_data = pd.read_csv(nodes_file)
    class_sorted = node_data.sort_values('Community')
    top_communities = class_sorted['Community'].value_counts()[:5].index.tolist()
    file_info = read_file(dataset_file)
    entries = file_info[0]
    text = file_info[1]
    classes = class_sorted.Community.unique()
    
    for value in top_communities:
        print("_____________________________________________________________________________________________________")
        cur_class = classes[value]
        print('Community Number: ',cur_class)
        cur_nodes = class_sorted.loc[class_sorted['Community'] == cur_class]
    
        for i in range(0,len(cur_nodes)):
            id = cur_nodes.iloc[i]['Id']
            print(entries[id]['Description'])
        print("_____________________________________________________________________________________________________")


# In[32]:


main(dataset_filename,nodes_filename)


# In[ ]:




