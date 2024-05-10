import requests

def upload_file(url, filename):
    files = {'file': open(filename, 'rb')}
    response = requests.post(url, files=files)
    print(response.text)

if __name__ == '__main__':
    upload_file('http://127.0.0.1:8080/upload', './wu.txt')
