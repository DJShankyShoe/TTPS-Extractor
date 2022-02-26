# TTP-Extractor
A tool that automates the process of extracting TTPs from Threat Intel Reports released by different vendors. These extracted TTPs will be useful for threat hunting, implementing automated blocks at SIEM and many more. Automating the process of extracting TTPs achieves vertical extraction scalability of TTPs and its implementations.


## Uses
```
usage: TTPs_Extractor.py [-h] [-md file.docx] [-mt file.txt]

Options:
-h, --help                                                  Help Commands
-md, --MicrosoftDefender  [file1.docx file2.docx ...]       Microsoft Defender Threat Intel Docx Files
-mt, --MicrosoftDefender  [file1.txt file2.txt .....]       Microsoft Defender Threat Intel Txt Files


Filename Syntax: "<Intel ID>+<Actor Grp (if any)>".docx/txt
Example Syntax : "Cobalt Kitty+APT32.docx", sysrv.txt, etc

Example Commands:
./TTPs_Extractor.py -md *.docx -mt *.txt
./TTPs_Extractor.py -md Qakbot.docx
./TTPs_Extractor.py -md "Cobalt Kitty+APT32.docx" Qakbot.docx -mt sysrv.txt
```


## Setup Procedure

To execute the script, you will need to install all python dependencies with the following command
```
pip3 install -r requirements.txt
```

Give it executable permissions and run it
```
chmod +x TTPs_Extractor.py
./TTPs_Extractor.py
```


## First-Time Execution

Users executing the script for the first time will lack the files `mitre.json` & `wordlist.json`. Thus, the script will automatically download these files if not present. This process takes around 1 min however, if takes longer, attempt to disconnect from VPN and try again. 

![f14b6400-9715-11ec-93fc-e09942401e87](https://user-images.githubusercontent.com/62169971/155850262-a365893c-9dd6-45fe-a33a-d273166e37aa.png)


## Maintenance

When the Mitre Framework is updated, to update the local Mitre Framework File, you will have to delete it, so that the script can redownload a newer local copy of Mitre Framework. The local Mitre Framework copy file is needed for extracting mitre att&ck from Intel Reports.


## Important Note

- When attempting to copy-paste data Microsoft Threat Intel Report to docx/txt files, **never attempt** to change the format of the intel report. Doing so might result
in improper extraction of TTPs
- To reduce errors in extraction, it is recommended to copy-paste report into `DOCX` rather than `TXT`.
