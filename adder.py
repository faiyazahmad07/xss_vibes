import json
payload = input("Enter the payload: ")
attributes = input("Enter the attributes(Separate by spaces): ")

new_data = {"Payload": payload, "Attribute": attributes.split(" "),"count":0}

f = open('payloads.json')
data = json.load(f)
data.append(new_data)
with open('payloads.json',"w") as write_data:
    json.dump(data,write_data)
print("[+] PAYLOAD HAS BEEN ADDED")