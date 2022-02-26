#!/usr/bin/env python3

import docx2txt
import json
from pyattck import Attck
import os.path
import re
import requests
import hashlib
import pandas as pd
import argparse
import validators
import datetime
from sys import exit


# Handling Defender Reports - Files
class MicrosoftDefender:

    def __init__(self, text, name, result, type):
        self.text = text
        self.name = name
        self.result = result
        self.type = type

    # Extract Mitre Framework
    class Mitre:
        def __init__(self, text, name, result):
            self.mitre_filename = "mitre.json"
            self.name = name
            self.mitre_dict = {}
            self.text = text
            self.result = result
            self.pos = 1

        # Perform Multiple API calls to retrieve Mitre Attack Framework Copy and store it locally for future execution
        # This process might take 1-2 minutes however only executed if the user executed this tool for the 1st time
        def import_mitre(self):
            attack = Attck()
            mitre_dict = {}

            for tactic in attack.enterprise.tactics:
                technique_dict = {}

                for technique in tactic.techniques:
                    technique_dict[technique.id.lower()] = technique.name.lower()
                mitre_dict[tactic.name.lower()] = technique_dict

            with open(self.mitre_filename, 'w') as outfile:
                json.dump(mitre_dict, outfile, indent=4)

        # Imports the local copy of Mitre Framework into python
        def call_mitre(self):
            with open(self.mitre_filename) as json_file:
                self.mitre_dict = json.load(json_file)

        # Attempts to trim down the extracted txt from the file to the area that is only need for
        def simplify_text(self, lower):
            current = "^MITRE ATT&CK technique(s\\b|\\b)( observed\\b|\\b)$"
            headers = ["^References(s\\b|\\b)$", "^MITRE ATT&CK technique(s\\b|\\b)( observed\\b|\\b)$",
                       "^Indicator(s\\b|\\b)( of compromise\\b|\\b)$", "^Advanced hunting$",
                       "^Detection detail(s\\b|\\b)$"]

            reg_result_1 = re.search(current, self.text, flags=re.IGNORECASE | re.MULTILINE)
            if reg_result_1:
                current_str = reg_result_1.group(0)
                self.text = self.text[self.text.find(f'\n{current_str}\n'):]

                for header in headers:
                    reg_result_2 = re.search(header, self.text, flags=re.IGNORECASE | re.MULTILINE)
                    if reg_result_2 and header != current:
                        header_str = reg_result_2.group(0)
                        self.text = self.text[:self.text.find(f"\n{header_str}\n")]

                # ------------------------------- removes "•       " from the text ---------------------------------#
                temp_list = self.text.split("\n")
                new_text = ""
                for sentence in temp_list:
                    if sentence.encode("utf-8").startswith(b"\xe2\x80\xa2\t"):
                        new_text += sentence.encode("utf-8").replace(b"\xe2\x80\xa2\t", b"").decode("utf-8")
                    else:
                        new_text += sentence
                    new_text += "\n"

                self.text = new_text
                ######################################################################################################

                if lower:
                    self.text = self.text.lower()

            else:
                self.text = ""

        # The Mitre Framework Tactics will be rearranged in the right order. <Dropped because redundant>
        def format_mitre(self):
            temp_pos = []
            temp_dict = {}
            new_dict = {}

            for tactic in self.mitre_dict:
                value = self.text.find("\n" + tactic + "\n")

                if value != -1:
                    temp_pos.append(value)
                    temp_dict[value] = tactic

            temp_pos.sort()
            for pos in temp_pos:
                new_dict[temp_dict[pos]] = self.mitre_dict[temp_dict[pos]]

            self.mitre_dict = new_dict

        # The extracted Mitre Framework from intel report will be parsed into a python dictionary with the right format
        def regrp_result(self, messy_result):
            temp_id = {}
            final_dict = {}
            temp_pos = []

            for id in messy_result:
                pos = self.text.find(id)
                temp_id[pos] = id
                temp_pos.append(pos)

            temp_pos.sort()

            for pos in temp_pos:
                final_dict[temp_id[pos]] = {"mitreTactic": messy_result[temp_id[pos]][0], "mitreID": messy_result[temp_id[pos]][1], "Process": messy_result[temp_id[pos]][2]}

            if self.result == {}:
                self.result[self.name] = {"Mitre Framework": final_dict}
            else:
                self.result[self.name]["Mitre Framework"] = final_dict

        # Looping through every single Tactics & Techniques in the local cope of MItre Framework
        # Objective is to find a match in the intel report and get extracted
        def check_mitre(self):
            messy_result = {}
            for tactic in self.mitre_dict:
                for technique in self.mitre_dict[tactic]:
                    if "." in technique:
                        mitre_string = f"{technique} {self.mitre_dict[tactic][technique[:len(technique) - 4]]}: {self.mitre_dict[tactic][technique]}"
                    else:
                        mitre_string = f"{technique} {self.mitre_dict[tactic][technique]}"

                    if mitre_string in self.text:
                        process = re.findall(f"{mitre_string}.* \| (.*?)\n", self.text)[0]

                        # messy_result[technique] = [tactic, mitre_string, process]
                        messy_result[technique] = [tactic.title(), technique.upper(), process.capitalize()]

            self.regrp_result(messy_result)

        def main(self):
            if not os.path.isfile("mitre.json"):
                print("[+] Importing Mitre Framework.. (Average duration: 1 min)")
                self.import_mitre()
                print("[+] Completed imports")

            self.call_mitre()
            # self.format_mitre()
            self.simplify_text(True)
            self.check_mitre()

            print("[+] Completed Mitre Extraction")
            return self.result

    # Extract Indicators
    class Indicators:
        def __init__(self, text, name, result):
            self.wordlists_filename = "wordlist.json"
            self.wordlists_dict = {}
            self.text = text
            self.name = name
            self.result = result
            self.temp_result_dict = {}

        # The extracted Indicators from intel report will be parsed into a python dictionary with the right format
        def format_result(self, key, value, indicator_type, hashType, final):
            if final:

                # removing empty string from dict lists if any
                for type in self.temp_result_dict:
                    self.temp_result_dict[type] = list(filter(None, self.temp_result_dict[type]))

                if self.result == {}:
                    self.result[self.name] = {"Indicators": self.temp_result_dict}
                else:
                    self.result[self.name]["Indicators"] = self.temp_result_dict
                return

            if key[-1] == ":":
                key = key[:-1]
            if key in self.temp_result_dict:
                self.temp_result_dict[key].append({"IOC": value, "indicator_type": indicator_type, "hashType": hashType})
            else:
                self.temp_result_dict[key] = [{"IOC": value, "indicator_type": indicator_type, "hashType": hashType}]

        # Attempts to trim down the extracted txt from the file to the area that is only need for
        def simplify_text(self, lower):
            current = "^Indicator(s\\b|\\b)( of compromise\\b|\\b)$"
            headers = ["^References(s\\b|\\b)$", "^MITRE ATT&CK technique(s\\b|\\b)( observed\\b|\\b)$",
                       "^Indicator(s\\b|\\b)( of compromise\\b|\\b)$", "^Advanced hunting$",
                       "^Detection detail(s\\b|\\b)$"]

            reg_result_1 = re.search(current, self.text, flags=re.IGNORECASE | re.MULTILINE)
            if reg_result_1:
                current_str = reg_result_1.group(0)
                self.text = self.text[self.text.find(f'\n{current_str}\n'):]

                for header in headers:
                    reg_result_2 = re.search(header, self.text, flags=re.IGNORECASE | re.MULTILINE)
                    if reg_result_2 and header != current:
                        header_str = reg_result_2.group(0)
                        self.text = self.text[:self.text.find(f"\n{header_str}\n")]

                # ------------------------------- removes "•       " from the text ---------------------------------#
                temp_list = self.text.split("\n")
                new_text = ""
                for sentence in temp_list:
                    if sentence.encode("utf-8").startswith(b"\xe2\x80\xa2\t"):
                        new_text += sentence.encode("utf-8").replace(b"\xe2\x80\xa2\t", b"").decode("utf-8")
                    else:
                        new_text += sentence
                    new_text += "\n"

                self.text = new_text
                ######################################################################################################

                if lower:
                    self.text = self.text.lower()

            else:
                self.text = ""

        # Determine the IOC type for classification and tagging
        def indicator_type_verify(self, value):
            HASH_TYPE_REGEX = {
                re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE): ["MD5", "MD4", "MD2", "Double MD5",
                                                                     "LM", "RIPEMD-128", "Haval-128",
                                                                     "Tiger-128", "Skein-256(128)", "Skein-512(128",
                                                                     "Lotus Notes/Domino 5", "Skype", "ZipMonster",
                                                                     "PrestaShop"],
                re.compile(r"^[a-f0-9]{64}(:.+)?$", re.IGNORECASE): ["SHA-256", "RIPEMD-256", "SHA3-256", "Haval-256",
                                                                     "GOST R 34.11-94", "GOST CryptoPro S-Box",
                                                                     "Skein-256", "Skein-512(256)", "Ventrilo"],
                re.compile(r"^[a-f0-9]{128}(:.+)?$", re.IGNORECASE): ["SHA-512", "Whirlpool", "Salsa10",
                                                                      "Salsa20", "SHA3-512", "Skein-512",
                                                                      "Skein-1024(512)"],
                re.compile(r"^[a-f0-9]{56}$", re.IGNORECASE): ["SHA-224", "Haval-224", "SHA3-224",
                                                               "Skein-256(224)", "Skein-512(224)"],
                re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE): ["SHA-1", "Double SHA-1", "RIPEMD-160",
                                                                     "Haval-160", "Tiger-160", "HAS-160",
                                                                     "LinkedIn", "Skein-256(160)", "Skein-512(160)",
                                                                     "MangoWeb Enhanced CMS"],
                re.compile(r"^[a-f0-9]{96}$", re.IGNORECASE): ["SHA-384", "SHA3-384", "Skein-512(384)",
                                                               "Skein-1024(384)"],
                re.compile(r"^[a-f0-9]{16}$", re.IGNORECASE): ["MySQL323", "DES(Oracle)", "Half MD5",
                                                               "Oracle 7-10g", "FNV-164", "CRC-64"],
                re.compile(r"^\*[a-f0-9]{40}$", re.IGNORECASE): ["MySQL5.x", "MySQL4.1"],
                re.compile(r"^[a-f0-9]{48}$", re.IGNORECASE): ["Haval-192", "Tiger-192", "SHA-1(Oracle)",
                                                               "XSHA (v10.4 - v10.6)"]
            }

            regex_ip = re.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            regex_domain = re.compile("^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")
            regex_url = re.compile("([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])")

            def hash_check(value):
                for algorithm, items in HASH_TYPE_REGEX.items():
                    if algorithm.match(value):
                        return "file", items[0]

            if regex_ip.match(value):
                return "IP", "<none>"

            elif hash_check(value):
                return hash_check(value)

            elif regex_domain.match(value):
                return "Domain", "<none>"

            elif regex_url.match(value):
                return "URL", "<none>"
            else:
                return False

        # The logic of extracting indicators is done by checking if that word exists in English dictionary
        # Other few logics are also used to reduce false positives - relying on the Microsoft Defender Format
        def check_indicators(self):

            data = self.text.split("\n\n")
            if len(data) == 1:
                data = self.text.split("\n")

            for word_count in data:
                data_value = word_count.replace("\n", "")

                if not self.indicator_type_verify(data_value.replace("[.]", ".").replace(" ", "")):
                    key = data_value
                else:
                    data_value = data_value.replace("[.]", ".").replace(" ", "")
                    indicator_type, hashType = self.indicator_type_verify(data_value)
                    self.format_result(key, data_value, indicator_type, hashType, False)

            self.format_result(None, None, None, None, True)

        def main(self):
            self.simplify_text(False)
            self.check_indicators()

            print("[+] Completed Indicators Extraction")
            return self.result

    # Extract Queries
    class HuntsDetections:
        def __init__(self, text, name, result, type):
            self.text = text[text.find('\nAdvanced hunting\n'):]
            self.wordlists_filename = "wordlist.json"
            self.name = name
            self.result = result
            self.temp_result_dict = {}
            self.type = type
            self.wordlists_dict = {}

        # Attempts to trim down the extracted txt from the file to the area that is only need for
        def simplify_text(self, lower):
            current = "^Advanced hunting$"
            headers = ["^References(s\\b|\\b)$", "^MITRE ATT&CK technique(s\\b|\\b)( observed\\b|\\b)$", "^Indicator(s\\b|\\b)( of compromise\\b|\\b)$", "^Advanced hunting$",
                       "^Detection detail(s\\b|\\b)$"]

            reg_result_1 = re.search(current, self.text, flags=re.IGNORECASE | re.MULTILINE)
            if reg_result_1:
                current_str = reg_result_1.group(0)
                self.text = self.text[self.text.find(f'\n{current_str}\n'):]

                for header in headers:
                    reg_result_2 = re.search(header, self.text, flags=re.IGNORECASE | re.MULTILINE)
                    if reg_result_2 and header != current:
                        header_str = reg_result_2.group(0)
                        self.text = self.text[:self.text.find(f"\n{header_str}\n")]

                # ------------------------------- removes "•       " from the text ---------------------------------#
                temp_list = self.text.split("\n")
                new_text = ""
                for sentence in temp_list:
                    if sentence.encode("utf-8").startswith(b"\xe2\x80\xa2\t"):
                        new_text += sentence.encode("utf-8").replace(b"\xe2\x80\xa2\t", b"").decode("utf-8")
                    else:
                        new_text += sentence
                    new_text += "\n"

                self.text = new_text
                ######################################################################################################

                if lower:
                    self.text = self.text.lower()

            else:
                self.text = ""

        # Additional english dictionary - add IT words to reduce false positives (** Avoid duplicates from https://raw.githubusercontent.com/dwyl/english-words/master/words_dictionary.json **)
        def addtionaContent(self):
            extra_package = {"malware": 1,
                             "url": 1,
                             "ip": 1,
                             "sql": 1,
                             "botnet": 1,
                             "ransomware": 1,
                             "linux": 1}
            return extra_package

        # The extracted Queries from intel report will be parsed into a python dictionary with the right format
        def format_result(self, detail, query, query_cat, query_info, final):
            if final:
                if self.result == {}:
                    self.result[self.name] = {"Hunt Queries": self.temp_result_dict}
                else:
                    self.result[self.name]["Queries"] = self.temp_result_dict
                return

            hash = hashlib.sha1(query.encode("UTF-8")).hexdigest()[:10]
            self.temp_result_dict[hash] = {"Detail": detail, "Query": query, "Category": query_cat, "Info": query_info}

        # Downloads a copy of English Dictionary - presents all possible English Words
        # This process is only executed if the user executed this tool for the 1st time
        def import_wordlists(self):
            r = requests.get("https://raw.githubusercontent.com/dwyl/english-words/master/words_dictionary.json")
            open('wordlist.json', 'wb').write(r.content)

        # Imports the local copy of English Dictionary into python dictionary
        def call_wordlists(self):
            with open(self.wordlists_filename) as json_file:
                try:
                    self.wordlists_dict = json.load(json_file)
                except:
                    print("Corrupted wordlist.json - delete the file")

            extra_pack = self.addtionaContent()
            self.wordlists_dict = {**self.wordlists_dict, **extra_pack}

        # Check if the parsed word exists in the english dictionary
        def word_check(self, words):
            split_words = words.split(" ")

            total = len(split_words)
            pos_words = 0

            for word in split_words:
                if word.lower() in self.wordlists_dict:
                    pos_words += 1

            percentage = pos_words/total * 100
            return percentage

        # A logic that is used to determine if a following sentence is a query or not
        # This logic is used if the Defender Intel Report is in txt instead of DOCX
        # This increases false positives thus it is recommended to used DOCX
        def query_line_txt_verify(self, line):
            first_check = False
            sec_check = False

            if line.endswith("and") or line.endswith("or"):
                sec_check = True

            if line[:2] == "//":
                first_check = True

            elif line.startswith("    "):
                first_check = True

            elif line.startswith("|"):
                first_check = True

            elif line.startswith("and") or line.startswith("or"):
                first_check = True

            elif "regex" not in line and " – " in line:
                pass

            else:
                percentage = self.word_check(line)
                if percentage < 55:
                    first_check = True

            return first_check, sec_check

        # determine query type (Splunk/MSD) & (Summarize/Reduce)
        def query_type_check(self, query):
            if "index" in query.lower() or "sourcetype" in query.lower():
                query_cat = "splunk"
                query_info = "<none>"
            else:
                query_cat = "msd"
                if "summarize" in query.lower() or "reduce" in query.lower():
                    query_info = "aggregation"
                else:
                    query_info = "event"

            return query_cat, query_info

        # Uses some logic and syntax recognition to extract queries out
        def check_query(self):
            if self.type == "docx":
                data = self.text.split("\n\n")
                query_bool = False
                query = ""

                for text_pos in range(len(data)):

                    if text_pos + 1 == len(data):
                        if query_bool and query != "":
                            query_cat, query_info = self.query_type_check(query)
                            self.format_result(detail, query, query_cat, query_info, False)

                        self.format_result(None, None, None, None, True)
                        break

                    if not query_bool and "\t\t\t\t\t\t" in data[text_pos + 1]:
                        query_bool = True
                        detail = data[text_pos]

                    if query_bool:
                        if "\t\t\t\t\t\t" in data[text_pos + 1]:
                            query += data[text_pos + 1].replace("\t", "").replace("\n", "") + "\n"
                        else:
                            query_bool = False

                            query_cat, query_info = self.query_type_check(query)
                            self.format_result(detail, query, query_cat, query_info, False)
                            query = ""

            elif self.type == "txt":
                data = self.text.split("\n")
                data = list(filter(None, data))

                query_bool = False
                query = ""

                text_no = 0
                while text_no < len(data):
                    if re.search("^.*run (this \\b|\\b)query$", data[text_no], flags=re.IGNORECASE):

                        if query != "":
                            query_cat, query_info = self.query_type_check(query)
                            self.format_result(detail, query, query_cat, query_info, False)
                            query = ""

                        query_bool = True
                        detail = data[text_no]
                        text_no += 1
                        query += data[text_no]

                    elif query_bool:
                        current, future = self.query_line_txt_verify(data[text_no])

                        if not current:
                            query_bool = False
                            query_cat, query_info = self.query_type_check(query)
                            self.format_result(detail, query, query_cat, query_info, False)
                            query = ""

                        else:
                            query += data[text_no]

                            if future:
                                text_no += 1
                                query += data[text_no]

                    text_no += 1

                query_cat, query_info = self.query_type_check(query)
                try:
                    self.format_result(detail, query, query_cat, query_info, False)
                    self.format_result(None, None, None, None, True)
                except UnboundLocalError:
                    pass

        def main(self):
            if not os.path.isfile(self.wordlists_filename):
                print("[+] Importing Wordlists..")
                self.import_wordlists()
                print("[+] Completed imports")
            self.call_wordlists()

            self.simplify_text(False)
            self.check_query()
            print("[+] Completed Splunk Hunts & Detection Extraction")
            return self.result

    # Dumps json type syntax to excel
    class JsonToExcel:

        def __init__(self, data):
            self.data = data
            self.writer = None

        def mitre(self, doc):
            df1 = pd.DataFrame(self.data[doc]["Mitre Framework"])
            df1.to_excel(self.writer, sheet_name='Mitre Framework')

        def indicator(self, doc):
            large_len = 0

            for key in self.data[doc]["Indicators"]:
                if len(self.data[doc]["Indicators"][key]) > large_len:
                    large_len = len(self.data[doc]["Indicators"][key])

            for key in self.data[doc]["Indicators"]:
                diff = large_len - len(self.data[doc]["Indicators"][key])
                for _ in range(diff):
                    self.data[doc]["Indicators"][key].append("")

            df2 = pd.DataFrame(self.data[doc]["Indicators"])
            df2.to_excel(self.writer, sheet_name='Indicators')

        def query(self, doc):
            df1 = pd.DataFrame(self.data[doc]["Queries"])
            df1.to_excel(self.writer, sheet_name='Queries')

        def main(self):
            option = {'strings_to_formulas': False, 'strings_to_urls': False}

            for doc in self.data:
                self.writer = pd.ExcelWriter(f"{doc}.xlsx", engine='xlsxwriter', engine_kwargs={'options': option})

                for tatic in self.data[doc]:
                    if tatic == "Mitre Framework":
                        self.mitre(doc)

                    elif tatic == "Indicators":
                        self.indicator(doc)

                    elif tatic == "Queries":
                        self.query(doc)

                self.writer.save()
                print("[+] Exported TTPs to Excel")
                # self.writer.close()

    def main(self):
        print("\nFILE: " + self.name)
        print("-----------------------------------------------------------")
        self.result = self.Mitre(self.text, self.name, self.result).main()
        self.result = self.Indicators(self.text, self.name, self.result).main()
        self.result = self.HuntsDetections(self.text, self.name, self.result, self.type).main()

        #self.JsonToExcel(self.result).main()
        return self.result

# Handling Palo alto Reports - URLS (Still being developed)
class Paloalto:
    def __init__(self, text, name, result):
        self.text = text
        self.name = name
        self.result = result

    class Mitre:
        def __init__(self, text, name, result):
            self.mitre_filename = "mitre.json"
            self.name = name
            self.mitre_dict = {}
            self.text = text
            self.result = result
            self.pos = 1

        def import_mitre(self):
            attack = Attck()
            mitre_dict = {}

            for tactic in attack.enterprise.tactics:
                technique_dict = {}

                for technique in tactic.techniques:
                    technique_dict[technique.id.lower()] = technique.name.lower()
                mitre_dict[tactic.name.lower()] = technique_dict

            with open(self.mitre_filename, 'w') as outfile:
                json.dump(mitre_dict, outfile, indent=4)

        def call_mitre(self):
            with open(self.mitre_filename) as json_file:
                self.mitre_dict = json.load(json_file)

        def simplify_text(self, lower):
            current = "MITRE ATT&CK techniques observed"
            headers = ["References", "MITRE ATT&CK techniques observed", "Indicators", "Advanced hunting",
                       "Detection details"]

            if self.text.find(f'\n{current}\n') != -1:
                self.text = self.text[self.text.find(f'\n{current}\n'):]

                for header in headers:
                    if self.text.find(f"\n{header}\n") != -1 and header != current:
                        self.text = self.text[:self.text.find(f"\n{header}\n")]

                if lower:
                    self.text = self.text.lower()

            else:
                self.text = ""

        def regrp_result(self, messy_result):
            temp_id = {}
            final_dict = {}
            temp_pos = []

            for id in messy_result:
                pos = self.text.find(id)
                temp_id[pos] = id
                temp_pos.append(pos)

            temp_pos.sort()

            for pos in temp_pos:
                final_dict[temp_id[pos]] = {"Info": messy_result[temp_id[pos]][0], "Process": messy_result[temp_id[pos]][1]}

            if self.result == {}:
                self.result[self.name] = {"Mitre Framework": final_dict}
            else:
                self.result[self.name]["Mitre Framework"] = final_dict

        def check_mitre(self):
            messy_result = {}
            for tactic in self.mitre_dict:
                for technique in self.mitre_dict[tactic]:
                    if "." in technique:
                        mitre_string = f"{technique} {self.mitre_dict[tactic][technique[:len(technique) - 4]]}: {self.mitre_dict[tactic][technique]}"
                    else:
                        mitre_string = f"{technique} {self.mitre_dict[tactic][technique]}"

                    if mitre_string in self.text:
                        process = re.findall(f"{mitre_string}.* \| (.*?)\n", self.text)[0]
                        messy_result[technique] = [mitre_string, process]

            self.regrp_result(messy_result)

        def main(self):
            if not os.path.isfile("mitre.json"):
                print("[+] Importing Mitre Framework.. (Average duration: 1 min)")
                self.import_mitre()
                print("[+] Completed imports")

            self.call_mitre()
            self.simplify_text(True)
            self.check_mitre()

            print("[+] Completed Mitre Extraction")
            return self.result

    def main(self):
        print("Paloalto extraction still being developed")

# The final process where the extracted TTPs are sent to this class for CSV Dumping
class Initiator:
    def __init__(self, data_files):
        self.data_files = data_files
        self.merged_dict = {}
        self.excel_dict = {"reportID": [], "indicator_type": [], "value": [], "sourceBrands": [], "fileHashType": [], "mitreTactic": [], "mitreID": [], "Tags": [], "Description": [], "splunkQuery": [], "mdeQuery": []}
        self.docID = None
        self.docActor = "<none>"
        self.sourceBrands = "<none>"

    # Dumping the processed python dictionary result to CSV
    def generalDictToCSV(self):
        # option = {'strings_to_formulas': False, 'strings_to_urls': False}

        now = datetime.datetime.now()
        # timestamp = str(now.replace(microsecond=0)).replace(" ", "-")

        if len(self.merged_dict) > 1:
            file_type = "multiple files"
        else:
            file_type = self.docID

        # writer = pd.ExcelWriter(f"{timestamp} - {file_type}.xlsx", engine='xlsxwriter', engine_kwargs={'options': option})
        # df1 = pd.DataFrame(self.excel_dict)
        # df1.to_excel(writer)
        #
        # writer.save()

        df = pd.DataFrame.from_dict(self.excel_dict)
        # df.to_csv(f"{timestamp} - {file_type}.csv")
        df.to_csv(f"{file_type}.csv")

    # formats the values into a dictionary format that will be used in Excel/CSV
    def append_csv_dict(self, indicatorType, value, fileHashType, mitreTactic, mitreID, Description, splunkQuery, mdeQuery, set_tag=None):
        self.excel_dict["reportID"].append(self.docID)
        self.excel_dict["indicator_type"].append(indicatorType)
        self.excel_dict["value"].append(value)
        self.excel_dict["sourceBrands"].append(self.sourceBrands)
        self.excel_dict["fileHashType"].append(fileHashType)
        self.excel_dict["mitreTactic"].append(mitreTactic)
        self.excel_dict["mitreID"].append(mitreID)
        self.excel_dict["Description"].append(Description)
        self.excel_dict["splunkQuery"].append(splunkQuery)
        self.excel_dict["mdeQuery"].append(mdeQuery)

        if set_tag:
            if self.docActor == "<none>":
                self.excel_dict["Tags"].append(set_tag)
            else:
                self.excel_dict["Tags"].append(self.docActor + ", " + set_tag)
        else:
            self.excel_dict["Tags"].append(self.docActor)

    # Extracting the File ID and the Actor Groups
    def extractID(self, filename):
        stripped_path = filename.split("/")[-1]

        if "+" in stripped_path:
            content = stripped_path.split("+")
            self.docActor = content[-1]
            self.docID = stripped_path.replace("+" + self.docActor, "").title().replace(" ", "")
        else:
            self.docID = stripped_path.title().replace(" ", "")
            self.docActor = "<none>"

    # Attempts to process and modify the parsed result to a format wanted by a team
    def final_format(self):
        for report_id in self.merged_dict:
            self.extractID(report_id)
            for type in self.merged_dict[report_id]:

                if type == "Mitre Framework":
                    for technique in self.merged_dict[report_id][type]:
                        tactic = self.merged_dict[report_id][type][technique]["mitreTactic"]
                        technique_des = self.merged_dict[report_id][type][technique]["mitreID"]
                        description = self.merged_dict[report_id][type][technique]["Process"].replace("\n", "")

                        self.append_csv_dict("Attack-Pattern", self.docActor, "<none>", tactic, technique_des, description, "<none>", "<none>")

                elif type == "Indicators":
                    for indicator_cat in self.merged_dict[report_id][type]:
                        for value_ioc in self.merged_dict[report_id][type][indicator_cat]:
                            ioc = value_ioc["IOC"]
                            indicator_type = value_ioc["indicator_type"]
                            hashType = value_ioc["hashType"]
                            self.append_csv_dict(indicator_type, ioc, hashType, "<none>", "<none>", indicator_cat, "<none>", "<none>")

                elif type == "Queries":
                    for query_hash in self.merged_dict[report_id][type]:
                        description = self.merged_dict[report_id][type][query_hash]["Detail"]
                        query = self.merged_dict[report_id][type][query_hash]["Query"].replace("\n", "")
                        query_cat = self.merged_dict[report_id][type][query_hash]["Category"]
                        query_info = self.merged_dict[report_id][type][query_hash]["Info"]

                        if query_cat == "splunk":
                            self.append_csv_dict("Query", "<none>", "<none>", "<none>", "<none>", description, query, "<none>", set_tag=query_info)
                        elif query_cat == "msd":
                            self.append_csv_dict("Query", "<none>", "<none>", "<none>", "<none>", description, "<none>", query, set_tag=query_info)

    # Extract all the text from DOCX document
    def microsoftDefenderDocx(self, file_list):
        for file in file_list:
            text = docx2txt.process(file).replace(u'\xa0', ' ')
            name = file.replace(".docx", "")

            text = text.encode("utf-8").replace(b"\xe2\x80\x9c", b'"').replace(b"\xe2\x80\x9d", b'"').decode("utf-8")

            created_dict = MicrosoftDefender(text, name, {}, "docx").main()
            self.merged_dict = {**created_dict, **self.merged_dict}

    # Extract all the text from TXT File
    def microsoftDefenderTxt(self, file_list):
        for file in file_list:
            with open(file, "r") as data:
                try:
                    text = data.read()
                except UnicodeDecodeError:
                    print("Invalid File for parameter -mt\n")
                    exit()

                name = file.replace(".txt", "")

                text = text.encode("utf-8").replace(b"\xe2\x80\x9c", b'"').replace(b"\xe2\x80\x9d", b'"').decode("utf-8")

                created_dict = MicrosoftDefender(text, name, {}, "txt").main()
                self.merged_dict = {**created_dict, **self.merged_dict}

    def main(self):
        for type in self.data_files:
            if type == "MicrosoftDefenderDocx":
                self.microsoftDefenderDocx(self.data_files[type])
                self.sourceBrands = "MSD365"

            elif type == "MicrosoftDefenderTxt":
                self.microsoftDefenderTxt(self.data_files[type])
                self.sourceBrands = "MSD365"

        self.final_format()
        self.generalDictToCSV()
        print("\n\n[+] Exported TTPs to Excel")
        print("[+] Completed Extraction\n\n")

# Giving the user the option to use arguments & flags
def arguments():

    # Prints the help command
    def help_command():
        print('''
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

            ''')
        exit()

    # Attempts to verify whether the right file extensions were used
    def verify(type, string):
        if type == "MicrosoftDefenderDocx":
            try:
                docx2txt.process(string)
            except:
                print("Error: -md parameter only accept docx files")
                help_command()

        elif type == "Paloalto":
            if not validators.url(string):
                print("Error: -p parameter only accept valid urls")
                help_command()

    parser = argparse.ArgumentParser(add_help=False)
    result = {}
    temp_check = "0"

    parser._optionals.title = 'Options'
    parser.add_argument('-md', '--MicrosoftDefenderDocx', nargs="+")
    parser.add_argument('-mt', '--MicrosoftDefenderTxt', nargs="+")
    parser.add_argument("-p", '--Paloalto', nargs="+")
    parser.add_argument('-h', action="store_true")

    try:
        args = parser.parse_args()
    except SystemExit:
        help_command()

    if args.h:
        help_command()

    if args.MicrosoftDefenderDocx:
        temp_check = True
        for file in args.MicrosoftDefenderDocx:
            verify("MicrosoftDefenderDocx", file)
            if temp_check:
                result["MicrosoftDefenderDocx"] = [file]
                temp_check = False
            else:
                result["MicrosoftDefenderDocx"].append(file)

    if args.MicrosoftDefenderTxt:
        temp_check = True
        for file in args.MicrosoftDefenderTxt:
            if temp_check:
                result["MicrosoftDefenderTxt"] = [file]
                temp_check = False
            else:
                result["MicrosoftDefenderTxt"].append(file)

    if args.Paloalto:
        Paloalto(None, None, None).main()

    if temp_check == "0":
        help_command()

    return result


if __name__ == "__main__":
    data = arguments()
    Initiator(data).main()
