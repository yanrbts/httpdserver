import requests

def upload_file(url, filename):
    files = {'file': open(filename, 'rb')}
    response = requests.post(url, files=files)
    # response.raise_for_status()
    print(response.text)

if __name__ == '__main__':
    upload_file('http://127.0.0.1:8080/user12', './uploads/ttt.txt')
