from wafw00f.main import WAFW00F

class Waf_Detect:
    def __init__(self,url):
        self.url = url

    def waf_detect(self):
        wafw00f = WAFW00F(self.url)
        result = wafw00f.identwaf()
        if result:
            result = result[0].lower()
        else:
            return None
        #print(result)
        wafs = self.fetch_names('waf_list.txt')
        for waf in wafs:
            if waf in result:
                #print(waf)
                return waf
        return None

    @staticmethod
    def fetch_names(filename):
        with open(filename,'r') as waf_list:
            return waf_list.read().split()

if __name__ == "__main__":
    Waf_Detect('http://testphp.vulnweb.com/listproducts.php?cat=4').waf_detect()
