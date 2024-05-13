import requests

def upload_file(url, filename):
    files = {'file': open(filename, 'rb')}
    response = requests.post(url, files=files)
    # response.raise_for_status()
    print(response.text)

if __name__ == '__main__':
    upload_file('http://192.168.3.140:8080/user1', '/home/yrb/src/linux-2.0.1.tar.gz')
