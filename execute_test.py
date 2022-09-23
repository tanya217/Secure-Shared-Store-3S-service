import subprocess,os
import time
import json

gtusername = 'gburdell3' # TODO: Place your gtusername here

dict2 = {1: "login", 2: "checkin", 3: "checkout", 4: "grant", 5: "delete", 6: "logout"}

def login(proc, username, user_key):
    proc.stdin.write('{}\n'.format(username).encode('utf-8'))
    proc.stdin.write('{}\n'.format(user_key).encode('utf-8'))

def checkin(proc, document_name, security_flag):
    proc.stdin.write('1\n'.encode('utf-8'))
    proc.stdin.write('{}\n'.format(document_name).encode('utf-8'))
    proc.stdin.write('{}\n'.format(security_flag).encode('utf-8'))

def checkout(proc, document_name):
    proc.stdin.write('2\n'.encode('utf-8'))
    proc.stdin.write('{}\n'.format(document_name).encode('utf-8'))

def grant(proc, document_name, target_user, access_right, time_duration):
    proc.stdin.write('3\n'.encode('utf-8'))
    proc.stdin.write('{}\n'.format(document_name).encode('utf-8'))
    proc.stdin.write('{}\n'.format(target_user).encode('utf-8'))
    proc.stdin.write('{}\n'.format(access_right).encode('utf-8'))
    proc.stdin.write('{}\n'.format(time_duration).encode('utf-8'))

def delete(proc, document_name):
    proc.stdin.write('4\n'.encode('utf-8'))
    proc.stdin.write('{}\n'.format(document_name).encode('utf-8'))

def logout(proc):
    proc.communicate('5\n'.encode('utf-8'))

def initialize_test():
    f = open("/home/cs6238/Desktop/Project4/client1/client.py", "r")
    data_read = f.readlines()
    f.close()
    f = open("/home/cs6238/Desktop/Project4/client1/client_test.py", "w")
    for i in data_read:
        if "with open(gt_username, 'wb') as f" in i:
            b = i.replace("gt_username", "gt_username+action")
            f.write(b)
        else:
            f.write(i)
    f.close()

def check_testresult(test_number):
    try:
        f = open('/home/cs6238/Desktop/Project4/client1/'+gtusername+dict2[test_number],'r')
        output = f.read()
        if output and str(json.loads(output)['status']) == "200":
            print ("Test Case " +  str(test_number) + " - Passed")
        else:
            print ("Test Case " + str(test_number) + " - Failed")
        f.close()
    except Exception as e:
        print (str(e))
        print ("Testing aborted due to failure!")
        exit(1)

def main():
    FNULL = open(os.devnull, 'w')
    try:
        p = subprocess.Popen(
            ['./start_server.sh'],
            cwd ='/home/cs6238/Desktop/Project4/server/application',
            stdout=FNULL,
            stderr=FNULL,
        )
        time.sleep(1)
    except:
        print ("Failed to start the server! Aborting!")
        exit(1)

    try:
        proc = subprocess.Popen(
            ['python3', 'client_test.py'],
            cwd ='/home/cs6238/Desktop/Project4/client1',
            stdin=subprocess.PIPE,
            stdout=FNULL,
        )
    except:
        print ("Failed to invoke the client! Aborting!")
        exit(1)

    # Login
    username = 'user1' # TODO: Place username
    user_key = 'user1.key' # TODO: Place user private key file name present inside userkeys folder
    login(proc, username, user_key)

    # Checkin
    document_name = 'test_document' # TODO: Can be replaced with any document name
    security_flag = '1' # confidentiality
    try:
        with open('/home/cs6238/Desktop/Project4/client1/documents/checkin/'+document_name,'wb') as f:
            f.write('Test input for checkin'.encode('utf-8'))
    except:
        print ("Failed to write checkin file! Exiting")
    checkin(proc, document_name, security_flag)

    # Checkout
    checkout(proc, document_name)

    # Grant
    target_user = 'user2' # TODO: Place the target username
    access_right = '1' # checkin
    time_duration = '10'
    grant(proc, document_name, target_user, access_right, time_duration)

    # Delete
    delete(proc, document_name)

    # Logout
    logout(proc)

def check_results():
    check_testresult(1)
    check_testresult(2)
    check_testresult(3)
    check_testresult(4)
    check_testresult(5)
    check_testresult(6)

def cleanup():
    for i in range(1, 7):
        os.remove('/home/cs6238/Desktop/Project4/client1/'+gtusername+dict2[i])
    os.remove('/home/cs6238/Desktop/Project4/client1/client_test.py')

if __name__ == '__main__':
    initialize_test()
    main()
    check_results()
    cleanup()