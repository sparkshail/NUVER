# NUVER
A network-based vulnerability visualizer! The paper, "NUVER: Network Based Vulnerability Visualizer," is published in the 2023 IEEE 30th Annual Software Technology Conference (STC) proceedings. Found here: https://ieeexplore.ieee.org/document/10336275

### Dependencies
* Please utilize the following commands for dependency installations:
  * pip install lxml
  * pip install nltk
  * pip install gensim 
  * pip install scipy
  * pip install networkx
  * pip install igraph 
  * pip install numpy
  * pip install pandas 
  
* You will also need to download the following applications:
  * Anaconda
  * Gephi 0.10.1
    * Be sure the version (64-bit versus 32-bit) matches your Python installation
  
### Directions
1. Place the dataset would like to analyze in the NUVER folder. 
  * All CVE datasets can be found at https://www.cve.org/Downloads.
2. Run "python networkCreation.py" from the NUVER folder. Then input the name of the dataset you would like to analyze when prompted.  
3. Open Gephi and create a new project. The user can select any name for the project. Select "Import spreadsheet...". First, import the file titled "node_list.csv" followed by "edge_list.csv". Select "append to existing workspace" when prompted, and confirm that the network is undirected. 
4. Open the Data Laboratory. For both the node and edge tables, merge the start_time and end_time columns by selecting "Create time interval" for the merge strategy. Confirm the start and end time columns are correct. 
5. The user can perform any community detection algorithm of their choice, and select any layout of their choice. In the graph overview, under node appearance, select partition and choose the appropriate community attribute. 
  * Depending on the number of communities, not all nodes will be automatically assigned a color. The user can manually color the other communities if they choose. 
  * Click enable timeline to view an animation the network. 
  * Before exporting the graph file, rename whichever column holds community\cluster labels to "Community".
  * Save the spreadsheet files in the NUVER folder. 
6. Run "python gephiResultAnalysis.py" from the NUVER folder. Then input the name of the dataset and Gephi network data you would like to analyze the community detection results for when prompted.  

