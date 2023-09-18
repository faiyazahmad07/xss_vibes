from optparse import OptionParser
import json

class Adder:
    def __init__(self):
        self.dangerous_characters = [  # You can add dangerous characters here
            ">",
            "'",
            '"',
            "<",
            "/",
            ";"
        ]

    def add_payload(self,payload=None,filename=None):
        if filename:
            with open(val.filename, 'r') as payloads:
                payloads = payloads.readlines()
            for payload in payloads:
                new_data = {
                    "Payload": payload,
                    "Attribute": [],
                    "count": 0,
                    "waf": val.waf
                }
                for char in payload:
                    if char in self.dangerous_characters:
                        if char in new_data['Attribute']:
                            pass
                        else:
                            new_data['Attribute'].append(char)
                f = open('payloads.json')
                data = json.load(f)
                data.append(new_data)
                with open('payloads.json', "w") as write_data:
                    json.dump(data, write_data, indent=4)
            print("[+] PAYLOAD HAS BEEN ADDED")

        else:
            new_data = {
                "Payload": val.payload,
                "Attribute": [],
                "count": 0,
                "waf": val.waf
            }
            for char in val.payload:
                if char in self.dangerous_characters:
                    new_data['Attribute'].append(char)

            # print(new_data)

            f = open('payloads.json')
            data = json.load(f)
            data.append(new_data)
            with open('payloads.json', "w") as write_data:
                json.dump(data, write_data, indent=4)
            print("[+] PAYLOAD HAS BEEN ADDED")


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-p", dest="payload", help="enter payload")
    parser.add_option("-f", dest="filename", help="enter filename containing all the payloads")
    parser.add_option("-w", dest="waf", help="enter waf name")
    val, args = parser.parse_args()
    Adder().add_payload(filename=val.filename,payload=val.payload)
