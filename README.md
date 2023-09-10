## XSS_VIBES
"Experience the Vibes of Security with xss_vibes"

![alt_text](xss_vibes.png)

### What's New?

- Added threads feature: You can now specify the threads to send multiple request at the same time!(Details given below)
- Improved Payloads: The payloads are now more accurate to the target
- Single URL Scan: Now you can scan single url by using -u flag.

### FEATURES

- Customizable: You can add your custom payload using adder.py
- Dynamic: The tool will prioritize the payloads based on the target's behavior
- Scalable: You can use this tool on bunch of links
- Speed: Send concurrent request to multiple urls

### I N S T A L L A T I O N

```
1. Clone the repository: git clone https://github.com/faiyazahmad07/xss_vibes
2. Install the requirements file: pip3 install -r requirements
3. Run the main.py file
```

### USAGE
```
python3 main.py -f <filename> -o <output>

-f: Filename that contains bunch of links
-o: Output filename in which all the vulnerable endpoints is stored
-t: No of threads[Increase the threads if you want more speed] (Max: 10)
-u: Single URL to scan.
```

### DEMONSTRATION

[Video Link](https://www.youtube.com/watch?v=sAYZu5ItX90)

### CONTRIBUTION

- [FAIYAZ AHMAD](https://www.linkedin.com/in/faiyaz-ahmad-64457520b): DEVELOPER
- [ASIF PATHAN](https://www.linkedin.com/in/asifpathan48/): ADDED PAYLOADS
- [KUNAL DHUMAL](https://www.linkedin.com/in/kunal-dhumal-47356721a/): ADDED PAYLOADS
