import re


class Parser:
    def headerParser(input_list):
        outputDictionary = {}
        for item in input_list:
            key_value = re.split(r':\s*', item, 1)
            if len(key_value) == 2:
                key, value = key_value
                outputDictionary[key.strip()] = value.strip()
        return outputDictionary
